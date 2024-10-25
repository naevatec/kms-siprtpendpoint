/*
 * (C) Copyright 2013 Kurento (http://kurento.org/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

 #include <stdio.h>

#include <string.h>
#include <nice/interfaces.h>
#include "kmssiprtpendpoint.h"
#include "kmssiprtpsession.h"
#include "kmssipsrtpsession.h"
#include "kmssiprtpconnection.h"
#include "kmssipsrtpconnection.h"
#include <commons/kmsbasesdpendpoint.h>
#include <commons/constants.h>
#include <gst/sdp/gstsdpmessage.h>
#include <gst/video/video-event.h>

#include "trafficshaper.h"

#define PLUGIN_NAME "siprtpendpoint"

#define DEFAULT_AUDIO_SSRC 0
#define DEFAULT_VIDEO_SSRC 0
#define DEFAULT_QOS_DSCP -1

#define SSRC_SWITCH_SAFE_PERIOD_MS 1000000


#define GST_CAT_DEFAULT kms_sip_rtp_endpoint_debug
GST_DEBUG_CATEGORY (GST_CAT_DEFAULT); 

#define kms_sip_rtp_endpoint_parent_class parent_class

G_DEFINE_TYPE_WITH_CODE (KmsSipRtpEndpoint,
    kms_sip_rtp_endpoint,
    KMS_TYPE_RTP_ENDPOINT,
    GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT,
        PLUGIN_NAME,
        0,
        "GStreamer debug category for the '" PLUGIN_NAME "' element"));


#define KMS_SIP_RTP_ENDPOINT_GET_PRIVATE(obj) (  \
  G_TYPE_INSTANCE_GET_PRIVATE (              \
    (obj),                                   \
    KMS_TYPE_SIP_RTP_ENDPOINT,                   \
    KmsSipRtpEndpointPrivate                    \
  )                                          \
)

#define DEFAULT_MAX_KBPS -1
#define DEFAULT_MAX_BUCKET_SIZE -1
#define DEFAULT_MAX_BUCKET_STORAGE -1

typedef struct _KmsSipRtpEndpointCloneData KmsSipRtpEndpointCloneData;


struct _KmsSipRtpEndpointCloneData
{
	SipFilterSsrcInfo* audio_filter_info;
	SipFilterSsrcInfo* video_filter_info;

	GHashTable *conns;
};

struct _KmsSipRtpEndpointPrivate
{
  gint use_sdes_cache;

  GList *sessionData;

  gint dscp_value;

  GstElement *rtpbin;
  gulong pad_added_signal;

  GstElement *audio_track_selector;
  GstElement *video_track_selector;

  gint64 last_audio_ssrc_switch;
  gint64 last_video_ssrc_switch;

  guint current_ssrc_audio_track;
  guint current_ssrc_video_track;

  GHashTable *pads_to_ssrc;  // Aux table to know the ssrc of a track on its corresponding leg of the pipeline (jitterbuffer element)
  GHashTable *selector_pads;

  gint max_kbps;
  gint max_bucket_size;
  glong max_bucket_storage_size;
};

/* Properties */
enum
{
  PROP_0,
  PROP_AUDIO_SSRC,
  PROP_VIDEO_SSRC,
  PROP_QOS_DSCP,
  PROP_MAX_KBPS,
  PROP_MAX_BUCKET_SIZE,
  PROP_MAX_BUCKET_STORAGE
};


/* Signals and args */
enum
{
  /* signals */
  SIGNAL_CLONE_TO_NEW_EP,

  LAST_SIGNAL
};

static guint obj_signals[LAST_SIGNAL] = { 0 };

static KmsBaseSdpEndpointClass *base_sdp_endpoint_type;


/*----------- Session cloning ---------------*/
static KmsSipRtpEndpointCloneData*
kms_sip_rtp_endpoint_get_clone_data (GList *sessionData)
{
	if (sessionData == NULL)
		return NULL;
	return ((KmsSipRtpEndpointCloneData*)sessionData->data);
}

static void
kms_sip_rtp_endpoint_preserve_rtp_session_data (KmsSipRtpSession *ses,
		GHashTable *conns)
{
	KMS_SIP_RTP_SESSION_CLASS(G_OBJECT_GET_CLASS(ses))->clone_connections (ses,conns);
}

static void
kms_sip_rtp_endpoint_preserve_srtp_session_data (KmsSipSrtpSession *ses,
		GHashTable *conns)
{
	KMS_SIP_SRTP_SESSION_CLASS(G_OBJECT_GET_CLASS(ses))->clone_connections (ses,conns);
}

static void
kms_sip_rtp_endpoint_clone_session (KmsSipRtpEndpoint * self, KmsSdpSession ** sess)
{
	GstElement *rtpbin = self->priv->rtpbin;
	GList *sessionToClone = self->priv->sessionData;

	if (rtpbin != NULL) {
		gboolean is_srtp = FALSE;

		is_srtp = KMS_IS_SIP_SRTP_SESSION (*sess);
		// TODO: Multisession seems not used on RTPEndpoint, anyway we are doing something probably incorrect
		// once multisession is used, that is to assume that creation order of sessions are maintained among all
		// endpoints, and so order can be used to correlate internal rtp sessions.
		GHashTable *conns;

		conns = kms_sip_rtp_endpoint_get_clone_data(sessionToClone)->conns;

		if (is_srtp) {
			kms_sip_rtp_endpoint_preserve_srtp_session_data (KMS_SIP_SRTP_SESSION(*sess), conns);
		} else {
			kms_sip_rtp_endpoint_preserve_rtp_session_data (KMS_SIP_RTP_SESSION(*sess), conns);
		}
	}
}



static gboolean isUseSdes (KmsSipRtpEndpoint * self)
{
	if (self->priv->use_sdes_cache == -1) {
		gboolean useSdes;

		g_object_get (G_OBJECT(self), "use-sdes", &useSdes, NULL);
		self->priv->use_sdes_cache = useSdes;
	}
	return self->priv->use_sdes_cache;
}


static void
kms_sip_rtp_endpoint_set_addr (KmsSipRtpEndpoint * self)
{
  GList *ips, *l;
  gboolean done = FALSE;

  ips = nice_interfaces_get_local_ips (FALSE);
  for (l = ips; l != NULL && !done; l = l->next) {
    GInetAddress *addr;
    gboolean is_ipv6 = FALSE;

    GST_DEBUG_OBJECT (self, "Check local address: %s", (const gchar*)l->data);
    addr = g_inet_address_new_from_string (l->data);

    if (G_IS_INET_ADDRESS (addr)) {
      switch (g_inet_address_get_family (addr)) {
        case G_SOCKET_FAMILY_INVALID:
        case G_SOCKET_FAMILY_UNIX:
          /* Ignore this addresses */
          break;
        case G_SOCKET_FAMILY_IPV6:
          is_ipv6 = TRUE;
        case G_SOCKET_FAMILY_IPV4:
        {
          gchar *addr_str;
          gboolean use_ipv6;

          g_object_get (self, "use-ipv6", &use_ipv6, NULL);
          if (is_ipv6 != use_ipv6) {
            GST_DEBUG_OBJECT (self, "Skip address (wanted IPv6: %d)", use_ipv6);
            break;
          }

          addr_str = g_inet_address_to_string (addr);
          if (addr_str != NULL) {
            g_object_set (self, "addr", addr_str, NULL);
            g_free (addr_str);
            done = TRUE;
          }
          break;
        }
      }
    }

    if (G_IS_OBJECT (addr)) {
      g_object_unref (addr);
    }
  }

  g_list_free_full (ips, g_free);

  if (!done) {
    GST_WARNING_OBJECT (self, "Addr not set");
  }
}

static void
kms_sip_rtp_endpoint_create_session_internal (KmsBaseSdpEndpoint * base_sdp,
    gint id, KmsSdpSession ** sess)
{
  KmsIRtpSessionManager *manager = KMS_I_RTP_SESSION_MANAGER (base_sdp);
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (base_sdp);
  gboolean use_ipv6 = FALSE;
  KmsSipRtpEndpointCloneData *data = NULL;

  /* Get ip address now that session is being created */
  kms_sip_rtp_endpoint_set_addr (self);

  g_object_get (self, "use-ipv6", &use_ipv6, NULL);
  if (isUseSdes(self)) {
	KmsSipSrtpSession *sip_srtp_ses = kms_sip_srtp_session_new (base_sdp, id, manager, use_ipv6, self->priv->dscp_value);
    *sess = KMS_SDP_SESSION (sip_srtp_ses);
	if (self->priv->sessionData != NULL) {
		data = (KmsSipRtpEndpointCloneData*) self->priv->sessionData->data;
		sip_srtp_ses->audio_filter_info = data->audio_filter_info;
		sip_srtp_ses->video_filter_info = data->video_filter_info;
	}
  } else {
	KmsSipRtpSession *sip_rtp_ses = kms_sip_rtp_session_new (base_sdp, id, manager, use_ipv6, self->priv->dscp_value);
    *sess = KMS_SDP_SESSION (sip_rtp_ses);
	if (self->priv->sessionData != NULL) {
		data = (KmsSipRtpEndpointCloneData*) self->priv->sessionData->data;
		sip_rtp_ses->audio_filter_info = data->audio_filter_info;
		sip_rtp_ses->video_filter_info = data->video_filter_info;
	}
  }

  /* Chain up */
  base_sdp_endpoint_type->create_session_internal (base_sdp, id, sess);
//  KMS_BASE_SDP_ENDPOINT_CLASS(
//  (KMS_RTP_ENDPOINT_CLASS
//      (kms_sip_rtp_endpoint_parent_class)->parent_class)->
//	  ->create_session_internal (base_sdp, id, sess);

  if (self->priv->sessionData != NULL) {
	  kms_sip_rtp_endpoint_clone_session (self, sess);
  }

}

/* Internal session management end */


static void
kms_sip_rtp_endpoint_create_media_handler (KmsBaseSdpEndpoint * base_sdp,
    const gchar * media, KmsSdpMediaHandler ** handler)
{
	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->create_media_handler (base_sdp, media, handler);

}




/* Configure media SDP begin */
static gboolean
kms_sip_rtp_endpoint_configure_media (KmsBaseSdpEndpoint * base_sdp_endpoint,
    KmsSdpSession * sess, KmsSdpMediaHandler * handler, GstSDPMedia * media)
{
  gboolean ret = TRUE;

  /* Chain up */
  ret = 	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->
		  	  configure_media (base_sdp_endpoint, sess, handler, media);
  return ret;
}

/* Configure media SDP end */


static guint
ssrc_str_to_uint (const gchar * ssrc_str)
{
  gint64 val;
  guint ssrc = 0;

  val = g_ascii_strtoll (ssrc_str, NULL, 10);
  if (val > G_MAXUINT32) {
    GST_ERROR ("SSRC %" G_GINT64_FORMAT " not valid", val);
  } else {
    ssrc = val;
  }

  return ssrc;
}

static gchar *
sdp_media_get_ssrc_str (const GstSDPMedia * media)
{
  gchar *ssrc = NULL;
  const gchar *val;
  GRegex *regex;
  GMatchInfo *match_info = NULL;

  val = gst_sdp_media_get_attribute_val (media, "ssrc");
  if (val == NULL) {
    return NULL;
  }

  regex = g_regex_new ("^(?<ssrc>[0-9]+)(.*)?$", 0, 0, NULL);
  g_regex_match (regex, val, 0, &match_info);
  g_regex_unref (regex);

  if (g_match_info_matches (match_info)) {
    ssrc = g_match_info_fetch_named (match_info, "ssrc");
  }
  g_match_info_free (match_info);

  return ssrc;
}

static guint32
kms_sip_rtp_endpoint_get_ssrc (const GstSDPMedia* media)
{
	gchar *ssrc_str;
	guint32 ssrc = 0;

	ssrc_str = sdp_media_get_ssrc_str (media);
	if (ssrc_str == NULL) {
	  return 0;
	}

	ssrc = ssrc_str_to_uint (ssrc_str);
	g_free (ssrc_str);

	return ssrc;
}


static gboolean
kms_sip_rtp_endpoint_get_expected_ssrc (const GstSDPMessage *sdp, guint32 *audio_ssrc, guint32 *video_ssrc)
{
	const GstSDPMedia *media;
	guint idx = 0;
	guint num_medias = 0;
	gboolean result = TRUE;

	// We are expecting an SDP answer with just one audio media and just one video media
	// If this was to change, this function would need reconsidering
	num_medias = gst_sdp_message_medias_len  (sdp);
	while (idx < num_medias) {
		const gchar* media_name;

		media = gst_sdp_message_get_media (sdp, idx);
		media_name = gst_sdp_media_get_media (media);
		GST_DEBUG("Found media %s", media_name);

		if (g_strcmp0 (AUDIO_STREAM_NAME, media_name) == 0) {
			*audio_ssrc = kms_sip_rtp_endpoint_get_ssrc (media);
		} else if (g_strcmp0 (VIDEO_STREAM_NAME, media_name) == 0) {
			*video_ssrc = kms_sip_rtp_endpoint_get_ssrc (media);
		} else  {
			result = FALSE;
		}
		idx++;
	}

	return result;
}



static gboolean
kms_sip_rtp_endpoint_process_answer (KmsBaseSdpEndpoint * ep,
    const gchar * sess_id, GstSDPMessage * answer)
{
	return KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->process_answer (ep, sess_id, answer);
}

static KmsRtpBaseConnection *
kms_sip_rtp_endpoint_get_connection (KmsSipRtpEndpoint * self, KmsSdpSession * sess,
    KmsSdpMediaHandler * handler, const GstSDPMedia * media)
{
	return kms_rtp_session_get_connection (KMS_RTP_SESSION (sess), handler);
}


static void
kms_sip_rtp_endpoint_start_transport_send (KmsBaseSdpEndpoint *base_sdp_endpoint,
    KmsSdpSession *sess, gboolean offerer)
{
	guint len;
	KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (base_sdp_endpoint);
  	const GstSDPConnection *msg_conn;

	/* chain up */
	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->start_transport_send (base_sdp_endpoint, sess, offerer);

  	msg_conn = gst_sdp_message_get_connection (sess->remote_sdp);

  	len = gst_sdp_message_medias_len (sess->remote_sdp);
	for (guint i = 0; i < len; i++) {
		const GstSDPMedia *media = gst_sdp_message_get_media (sess->remote_sdp, i);
		const GstSDPConnection *media_con;
   		KmsSdpMediaHandler *handler;
		KmsRtpBaseConnection *conn;

		if (gst_sdp_media_get_port (media) == 0) {
			continue;
		}		

		if (gst_sdp_media_connections_len (media) != 0) {
			media_con = gst_sdp_media_get_connection (media, 0);
		} else {
			media_con = msg_conn;
		}

		if (media_con == NULL || media_con->address == NULL	|| media_con->address[0] == '\0') {
			continue;
		}

		handler = kms_sdp_agent_get_handler_by_index (KMS_SDP_SESSION (sess)->agent, i);
		if (handler == NULL) {
			continue;
		}

		conn = kms_sip_rtp_endpoint_get_connection (self, sess, handler, media);
		g_object_unref (handler);
		if (conn == NULL) {
			continue;
		}

		// Set bitrate restrictions if any
		if (self->priv->max_kbps > 0) {
			g_object_set (G_OBJECT(conn), "max-kbps", self->priv->max_kbps, NULL);
		}
		if (self->priv->max_bucket_size > 0) {
			g_object_set (G_OBJECT(conn), "max-bucket-size", self->priv->max_bucket_size, NULL);
		}
		if (self->priv->max_bucket_storage_size > 0) {
			g_object_set (G_OBJECT(conn), "max-bucket-storage", self->priv->max_bucket_storage_size, NULL);
		}
	}
}

static void
base_conn_set_max_kbps (gpointer key,  gpointer value,  gpointer user_data)
{
	KmsSipRtpEndpoint *endpoint = KMS_SIP_RTP_ENDPOINT(user_data);
	
	if (KMS_IS_SIP_RTP_CONNECTION(value)) {
    	KmsSipRtpConnection *conn = KMS_SIP_RTP_CONNECTION(value);

    	g_object_set (conn, "max-kbps", endpoint->priv->max_kbps, NULL);
	} else if (KMS_IS_SIP_SRTP_CONNECTION(value)) {
    	KmsSipSrtpConnection *conn = KMS_SIP_SRTP_CONNECTION(value);

    	g_object_set (conn, "max-kbps", endpoint->priv->max_kbps, NULL);
  	}
}

static void
base_conn_set_max_bucket_size (gpointer key,  gpointer value,  gpointer user_data)
{
	KmsSipRtpEndpoint *endpoint = KMS_SIP_RTP_ENDPOINT(user_data);

  	if (KMS_IS_SIP_RTP_CONNECTION(value)) {
    	KmsSipRtpConnection *conn = KMS_SIP_RTP_CONNECTION(value);

    	g_object_set (conn, "max-bucket-size", endpoint->priv->max_bucket_size, NULL);
  	} else if (KMS_IS_SIP_SRTP_CONNECTION(value)) {
	    KmsSipSrtpConnection *conn = KMS_SIP_SRTP_CONNECTION(value);

    	g_object_set (conn, "mmax-bucket-size", endpoint->priv->max_bucket_size, NULL);
  	}
}

static void
base_conn_set_max_bucket_storage (gpointer key, gpointer value, gpointer user_data)
{
	KmsSipRtpEndpoint *endpoint = KMS_SIP_RTP_ENDPOINT(user_data);

  	if (KMS_IS_SIP_RTP_CONNECTION(value)) {
    	KmsSipRtpConnection *conn = KMS_SIP_RTP_CONNECTION(value);

    	g_object_set (conn, "max-bucket-storage", endpoint->priv->max_bucket_storage_size, NULL);
  	} else if (KMS_IS_SIP_SRTP_CONNECTION(value)) {
	    KmsSipSrtpConnection *conn = KMS_SIP_SRTP_CONNECTION(value);

    	g_object_set (conn, "mmax-bucket-storage", endpoint->priv->max_bucket_storage_size, NULL);
  	}
}

static void
base_ses_set_max_kbps (gpointer key,  gpointer value,  gpointer user_data)
{
	KmsSipRtpEndpoint *endpoint = KMS_SIP_RTP_ENDPOINT(user_data);
  	KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION(value);

  	if (ses != NULL) {
    	GHashTable *conns = ses->conns;

    	g_hash_table_foreach (conns, base_conn_set_max_kbps, endpoint);
  	}
}

static void
base_ses_set_max_bucket_size (gpointer key,  gpointer value,  gpointer user_data)
{
	KmsSipRtpEndpoint *endpoint = KMS_SIP_RTP_ENDPOINT(user_data);
  	KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION(value);

  	if (ses != NULL) {
    	GHashTable *conns = ses->conns;

    	g_hash_table_foreach (conns, base_conn_set_max_bucket_size, endpoint);
  	}
}

static void
base_ses_set_max_bucket_storage (gpointer key, gpointer value, gpointer user_data)
{
	KmsSipRtpEndpoint *endpoint = KMS_SIP_RTP_ENDPOINT(user_data);
  	KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION(value);

  	if (ses != NULL) {
    	GHashTable *conns = ses->conns;

    	g_hash_table_foreach (conns, base_conn_set_max_bucket_storage, endpoint);
  	}
}

static void
kms_sip_rtp_endpoint_set_max_kbps (KmsSipRtpEndpoint *self)
{
  	// FIXME: Bitrate settings are applied independntly to all connections in the endpoint
  	// They should have a common tocken bucket
  	KmsBaseSdpEndpoint *baseSdpEp = KMS_BASE_SDP_ENDPOINT(self);
  	GHashTable *sess = kms_base_sdp_endpoint_get_sessions (baseSdpEp);

  	g_hash_table_foreach (sess, base_ses_set_max_kbps, self);
}

static void
kms_sip_rtp_endpoint_set_max_bucket_size (KmsSipRtpEndpoint *self)
{
  	// FIXME: Bitrate settings are applied independntly to all connections in the endpoint
  	// They should have a common tocken bucket
  	KmsBaseSdpEndpoint *baseSdpEp = KMS_BASE_SDP_ENDPOINT(self);
  	GHashTable *conns = kms_base_sdp_endpoint_get_sessions (baseSdpEp);

  	g_hash_table_foreach (conns, base_ses_set_max_bucket_size, self);
}

static void 
kms_sip_rtp_endpoint_set_max_bucket_storage (KmsSipRtpEndpoint *self)
{
  	// FIXME: Bitrate settings are applied independntly to all connections in the endpoint
  	// They should have a common tocken bucket
  	KmsBaseSdpEndpoint *baseSdpEp = KMS_BASE_SDP_ENDPOINT(self);
  	GHashTable *conns = kms_base_sdp_endpoint_get_sessions (baseSdpEp);

  	g_hash_table_foreach (conns, base_ses_set_max_bucket_storage, self);
}


static KmsSipRtpEndpointCloneData*
kms_sip_rtp_endpoint_create_clone_data (KmsSipRtpEndpoint *self, KmsBaseRtpSession *ses, guint32 audio_ssrc, guint32 video_ssrc, gboolean continue_audio_stream, gboolean continue_video_stream)
{
	KmsSipRtpEndpointCloneData *data = g_new0(KmsSipRtpEndpointCloneData, 1);
	SipFilterSsrcInfo* audio_filter_info = NULL;
	SipFilterSsrcInfo* video_filter_info = NULL;

	if (KMS_IS_SIP_RTP_SESSION (ses)) {
		KmsSipRtpSession* sip_ses = KMS_SIP_RTP_SESSION (ses);

		GST_DEBUG ("kms_sip_rtp_endpoint_create_clone_data audio filter %p, video filter %p", sip_ses->audio_filter_info, sip_ses->video_filter_info);
		audio_filter_info = kms_sip_rtp_filter_create_filtering_info (sip_ses->audio_filter_info, AUDIO_RTP_SESSION);
		video_filter_info = kms_sip_rtp_filter_create_filtering_info (sip_ses->video_filter_info, VIDEO_RTP_SESSION);
	} else if (KMS_IS_SIP_SRTP_SESSION (ses)) {
		KmsSipSrtpSession* sip_ses = KMS_SIP_SRTP_SESSION (ses);

		GST_DEBUG ("kms_sip_rtp_endpoint_create_clone_data srtp  audio filter %p, video filter %p", sip_ses->audio_filter_info, sip_ses->video_filter_info);
		audio_filter_info = kms_sip_rtp_filter_create_filtering_info (sip_ses->audio_filter_info, AUDIO_RTP_SESSION);
		video_filter_info = kms_sip_rtp_filter_create_filtering_info (sip_ses->video_filter_info, VIDEO_RTP_SESSION);
	}

	data->audio_filter_info = audio_filter_info;
	data->video_filter_info = video_filter_info;
	data->conns = g_hash_table_ref(ses->conns);

	return data;
}

static void
kms_sip_rtp_endpoint_free_clone_data (GList *data)
{
	GList *it = data;

	while (it != NULL) {
		KmsSipRtpEndpointCloneData* data = (KmsSipRtpEndpointCloneData*) it->data;

		if (data->conns != NULL) {
			g_hash_table_unref(data->conns);
			data->conns = NULL;
		}

		it = it->next;
	}

	g_list_free_full (data, g_free);
}

static void
kms_sip_rtp_endpoint_clone_to_new_ep (KmsSipRtpEndpoint *self, KmsSipRtpEndpoint *cloned, const gchar* sdp_str, gboolean continue_audio_stream, gboolean continue_video_stream)
{
	GHashTable * sessions = kms_base_sdp_endpoint_get_sessions (KMS_BASE_SDP_ENDPOINT(self));
	GList *sessionKeys = g_hash_table_get_keys (sessions);
	gint i;
	GList *sessionsData = NULL;
	guint32 remote_audio_ssrc = 0;
	guint32 remote_video_ssrc = 0;
	GstSDPMessage *sdp;

	gst_sdp_message_new (&sdp);
	if (gst_sdp_message_parse_buffer ((const guint8*) sdp_str, strlen (sdp_str), sdp) != GST_SDP_OK)
		GST_ERROR("Could not parse SDP answer");

	if (!kms_sip_rtp_endpoint_get_expected_ssrc (sdp, &remote_audio_ssrc, &remote_video_ssrc)) {
		GST_INFO("Could not find SSRCs on SDP answer, assuming first SSRC different from previous is valid");
	}

	gst_sdp_message_free (sdp);

	// In fact SipRtpEndpoint should have only one session, if not, this loop should be revised
	for (i = 0; i < g_hash_table_size(sessions); i++) {
		gpointer sesKey = sessionKeys->data;
		KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION (g_hash_table_lookup (sessions, sesKey));
		KmsSipRtpEndpointCloneData *data = kms_sip_rtp_endpoint_create_clone_data (self, ses, remote_audio_ssrc, remote_video_ssrc, continue_audio_stream, continue_video_stream);

		sessionsData = g_list_append (sessionsData, (gpointer)data);
	}
	g_list_free(sessionKeys);

	KMS_ELEMENT_LOCK (cloned);
	if (cloned->priv->sessionData != NULL) {
		kms_sip_rtp_endpoint_free_clone_data (cloned->priv->sessionData);
	}
	cloned->priv->sessionData = sessionsData;
	KMS_ELEMENT_UNLOCK (cloned);
}

static void
kms_sip_rtp_endpoint_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  guint ssrc;
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  KMS_ELEMENT_LOCK (self);

  switch (prop_id) {
    case PROP_AUDIO_SSRC:
    	ssrc = g_value_get_uint (value);

    	self->priv->current_ssrc_audio_track = ssrc;
    	break;
    case PROP_VIDEO_SSRC:
    	ssrc = g_value_get_uint (value);

    	self->priv->current_ssrc_video_track = ssrc;
    	break;
	case PROP_QOS_DSCP:
		self->priv->dscp_value = g_value_get_int (value);
		break;
    case PROP_MAX_KBPS:
		self->priv->max_kbps = g_value_get_int (value);
		kms_sip_rtp_endpoint_set_max_kbps (self);
		break;
    case PROP_MAX_BUCKET_SIZE:
		self->priv->max_bucket_size = g_value_get_int (value);
		kms_sip_rtp_endpoint_set_max_bucket_size (self);
		break;
    case PROP_MAX_BUCKET_STORAGE:
		self->priv->max_bucket_storage_size = g_value_get_long (value);
		kms_sip_rtp_endpoint_set_max_bucket_storage (self);
		break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  KMS_ELEMENT_UNLOCK (self);
}

static void
kms_sip_rtp_endpoint_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  KMS_ELEMENT_LOCK (self);

  switch (prop_id) {
    case PROP_AUDIO_SSRC:
       	g_value_set_uint (value, self->priv->current_ssrc_audio_track);
    	break;
    case PROP_VIDEO_SSRC:
       	g_value_set_uint (value, self->priv->current_ssrc_video_track);
    	break;
	case PROP_QOS_DSCP:
		g_value_set_int (value, self->priv->dscp_value);
		break;
	case PROP_MAX_KBPS:
		g_value_set_int (value, self->priv->max_kbps);
		break;
	case PROP_MAX_BUCKET_SIZE:
		g_value_set_int (value, self->priv->max_bucket_size);
		break;
	case PROP_MAX_BUCKET_STORAGE:
		g_value_set_int (value, self->priv->max_bucket_storage_size);
		break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  KMS_ELEMENT_UNLOCK (self);
}

static void
kms_sip_rtp_endpoint_finalize (GObject * object)
{
  	KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  	GST_DEBUG_OBJECT (self, "finalize");

	g_hash_table_destroy(self->priv->selector_pads);
  	g_hash_table_destroy(self->priv->pads_to_ssrc);

	if (self->priv->audio_track_selector != NULL) {
		gst_object_unref(self->priv->audio_track_selector);
	}
	if (self->priv->video_track_selector != NULL) {
		gst_object_unref(self->priv->video_track_selector);
	}

	if (self->priv->pad_added_signal != 0) {
		g_signal_handler_disconnect (self->priv->rtpbin, self->priv->pad_added_signal);
	}
	if (self->priv->rtpbin != NULL) {
		gst_object_unref (self->priv->rtpbin);
	}

	if (self->priv->sessionData != NULL)
		kms_sip_rtp_endpoint_free_clone_data(self->priv->sessionData);

	GST_DEBUG ("Finalizing Sip RTP Endpoint %p", object);

	/* chain up */
	G_OBJECT_CLASS (parent_class)->finalize (object);
}


static void
kms_sip_rtp_endpoint_class_init (KmsSipRtpEndpointClass * klass)
{
  GObjectClass *gobject_class;
  KmsBaseSdpEndpointClass *base_sdp_endpoint_class;
  GstElementClass *gstelement_class;

  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->set_property = kms_sip_rtp_endpoint_set_property;
  gobject_class->get_property = kms_sip_rtp_endpoint_get_property;
  gobject_class->finalize = kms_sip_rtp_endpoint_finalize;

  gstelement_class = GST_ELEMENT_CLASS (klass);
  gst_element_class_set_details_simple (gstelement_class,
      "SipRtpEndpoint",
      "SIP RTP/Stream/RtpEndpoint",
      "Sip Rtp Endpoint element",
      "Saul Pablo Labajo Izquierdo <slabajo@naevatec.com>");
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, PLUGIN_NAME, 0, PLUGIN_NAME);

  base_sdp_endpoint_class = KMS_BASE_SDP_ENDPOINT_CLASS (klass);
  base_sdp_endpoint_class->create_session_internal =
      kms_sip_rtp_endpoint_create_session_internal;
  base_sdp_endpoint_class->start_transport_send =
      kms_sip_rtp_endpoint_start_transport_send;

  base_sdp_endpoint_class->process_answer =
		  kms_sip_rtp_endpoint_process_answer;

  /* Media handler management */
  base_sdp_endpoint_class->create_media_handler =
      kms_sip_rtp_endpoint_create_media_handler;


  base_sdp_endpoint_class->configure_media = kms_sip_rtp_endpoint_configure_media;

  klass->clone_to_new_ep = kms_sip_rtp_endpoint_clone_to_new_ep;

   /**
   * GstTrafficShaper:max-kbps:
   *
   * The maximum number of kilobits to let through per second. Setting this
   * property to a positive value enables network congestion simulation using
   * a token bucket algorithm. Also see the "max-bucket-size" property,
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_MAX_KBPS,
      g_param_spec_int ("max-kbps", "Maximum Kbps",
          "The maximum number of kilobits to let through per second "
          "(-1 = unlimited)", -1, G_MAXINT, DEFAULT_MAX_KBPS,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

  /**
   * GstTrafficShaper:max-bucket-size:
   *
   * The size of the token bucket, related to burstiness resilience.
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_MAX_BUCKET_SIZE,
      g_param_spec_int ("max-bucket-size", "Maximum Bucket Size (Kb)",
          "The size of the token bucket, related to burstiness resilience "
          "(-1 = unlimited)", -1, G_MAXINT, DEFAULT_MAX_BUCKET_SIZE,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

  /**
   * GstTrafficShaper:min-bucket-size:
   *
   * The maximum kbits that can be stored delayed to be traffci shaped.
   *
   * Since: 1.14
   */
  g_object_class_install_property (gobject_class, PROP_MAX_BUCKET_STORAGE,
      g_param_spec_long ("max-bucket-storage", "Maximum delayed storage size Size (Bytes)",
          "The maximum amount of storage allowed for delayed packets in kbits "
          "(-1 = unlimited)", -1, G_MAXLONG, DEFAULT_MAX_BUCKET_STORAGE,
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_AUDIO_SSRC,
      g_param_spec_uint ("audio-ssrc",
          "Audio SSRC", "Set to assign the local audio SSRC",
          0, G_MAXUINT, DEFAULT_AUDIO_SSRC,
		  G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_VIDEO_SSRC,
      g_param_spec_uint ("video-ssrc",
          "Video SSRC", "Set to assign the local video SSRC",
		  0, G_MAXUINT, DEFAULT_VIDEO_SSRC,
		  G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_QOS_DSCP,
      g_param_spec_int ("qos-dscp",
          "QoS DSCP", "Set to assign DSCP value for network traffice sent",
		  -1, G_MAXINT, DEFAULT_QOS_DSCP,
		  G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  obj_signals[SIGNAL_CLONE_TO_NEW_EP] =
      g_signal_new ("clone-to-new-ep",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_ACTION | G_SIGNAL_RUN_LAST,
      G_STRUCT_OFFSET (KmsSipRtpEndpointClass, clone_to_new_ep), NULL, NULL,
      NULL, G_TYPE_NONE, 4, G_TYPE_POINTER, G_TYPE_STRING, G_TYPE_BOOLEAN, G_TYPE_BOOLEAN);


  g_type_class_add_private (klass, sizeof (KmsSipRtpEndpointPrivate));

  // Kind of hack to use GLib type system in an unusual way:
  //  RTPEndpoint implementation is very final in the sense that it does not
  //  intend to be subclassed, this makes difficult to reimplement virtual
  //  methods that need chaining up like create_session_internal. The only way
  //  is to call directly the virtual method in the grandparent class
  //  Well, there is another way, to enrich base class implementation to allow
  //  subclasses to reimplement the virtual method (in the particular case of
  //  create_session_internal just need to skip session creation if already created.
  // TODO: When integrate on kms-elements get rid off this hack changing kms_rtp_endpoint_create_session_internal
  GType type =   g_type_parent  (g_type_parent (G_TYPE_FROM_CLASS (klass)));
  // TODO: This introduces a memory leak, this is reserved and never freed, but it is just a pointer (64 bits)
  //       A possible alternative would be to implement the class_finalize method
  gpointer typePointer = g_type_class_ref(type);
  base_sdp_endpoint_type = KMS_BASE_SDP_ENDPOINT_CLASS(typePointer);
}

/* TODO: not add abs-send-time extmap */


static GstElement*
find_rtpbin_in_element(GstBin *self)
{
	GstElement *result = NULL;
	GList* rtpEndpointChildren = GST_BIN_CHILDREN(GST_BIN(self));

	while (rtpEndpointChildren != NULL) {
		gchar* objectName = gst_element_get_name  (GST_ELEMENT(rtpEndpointChildren->data));

		if (g_str_has_prefix (objectName, "rtpbin")) {
			result = GST_ELEMENT(rtpEndpointChildren->data);
			g_free (objectName);
			break;
		}
		g_free (objectName);
		rtpEndpointChildren = rtpEndpointChildren->next;
	}

	return result;
}

static GstElement*
get_depayloader_from_pad (GstPad *src_pad)
{
	GstElement *element = NULL;
	GstPad *peer_sink;

	peer_sink = gst_pad_get_peer (src_pad);
	if (peer_sink != NULL) {
		element = gst_pad_get_parent_element (peer_sink);

		if (element != NULL) {
			GstElementFactory *factory = gst_element_get_factory(element);

			// If no depayloader basertpendpoint set a fakesink, but that is not useful to us
			if (factory != NULL) {
				GstElementFactory *fakesink_factory = gst_element_factory_find ("fakesink");

				if (gst_element_factory_get_element_type (factory) == gst_element_factory_get_element_type (fakesink_factory)) {
					gst_object_unref (element);
					element = NULL;
				}
			}
		}
		gst_object_unref(peer_sink);
	}

	return element;
}

static GstElement*
get_outputagnostic_from_depayloader (GstElement *source_to_agnostic)
{
	GstElement *result = NULL;
	GstPad *src_pad;
	GstPad *peer_sink;

	src_pad = gst_element_get_static_pad (source_to_agnostic, "src");
	if (src_pad != NULL) {
		peer_sink = gst_pad_get_peer(src_pad);
		if (peer_sink != NULL) {
			result = gst_pad_get_parent_element (peer_sink);
			gst_object_unref(peer_sink);
		}
		gst_object_unref (src_pad);
	}
	return result;
}

static void
reconnect_output_agnostic (GstElement *depayloader, GstElement *track_selector, GstElement *output_agnosticbin)
{
	GstPad *src_pad, *peer_sink;

	src_pad = gst_element_get_static_pad (depayloader, "src");
	if (src_pad != NULL) {
		peer_sink = gst_pad_get_peer (src_pad);

		if (peer_sink != NULL) {
			gst_pad_unlink (src_pad, peer_sink);
			gst_element_link (track_selector, output_agnosticbin);
			gst_object_unref(peer_sink);
		}
		gst_object_unref (src_pad);
	}
}

static void
send_force_key_unit_event (GstPad * pad)
{
  GstEvent *event;

  event =
      gst_video_event_new_upstream_force_key_unit (GST_CLOCK_TIME_NONE, FALSE, 0);

  if (GST_PAD_DIRECTION (pad) == GST_PAD_SRC) {
    gst_pad_send_event (pad, event);
  } else {
    gst_pad_push_event (pad, event);
  }
}

static void
kms_sip_rtp_endpoint_connect_depayloader_to_selector (KmsSipRtpEndpoint *self, GstElement *depayloader, GstElement *track_selector, guint ssrc, guint media_type)
{
	GstPadTemplate *templ;
	GstPad *sink_pad, *src_pad;
	
	templ =
      gst_element_class_get_pad_template (GST_ELEMENT_GET_CLASS (track_selector), "sink_%u");
	sink_pad = gst_element_request_pad (track_selector, templ, NULL, NULL);	
	src_pad = gst_element_get_static_pad (depayloader, "src");
	gst_pad_link (src_pad, sink_pad);

	g_object_set(track_selector, "active-pad", sink_pad, NULL);
	GST_DEBUG_OBJECT(self, "Adding track input pad %s to %s track selector with ssrc %u", sink_pad->object.name, (media_type== AUDIO_RTP_SESSION)? "audio":"video", ssrc);
	g_hash_table_insert(self->priv->selector_pads, GINT_TO_POINTER(ssrc), g_object_ref(sink_pad));

	gst_object_unref (src_pad);
	gst_object_unref(sink_pad);
}


static void
kms_sip_rtp_endpoint_add_active_input_to_selector (KmsSipRtpEndpoint *self, GstElement *depayloader, GstElement *output_agnosticbin, guint media_type, guint ssrc, guint pt)
{
	GstElement *track_selector = NULL;

	GST_DEBUG_OBJECT(self, "Adding active input to %s track selector with ssrc %u and payload %d", (media_type == AUDIO_RTP_SESSION)?"audio": "video", ssrc, pt);

	// Ensure the input selector is created
	KMS_ELEMENT_LOCK (self);
	if (media_type == 0) {
		if (self->priv->audio_track_selector == NULL) {
			track_selector = gst_element_factory_make ("input-selector", "audio-track-selector");
			if (track_selector == NULL) {
				GST_ERROR_OBJECT(self, "Cannot build input selector for incoming audio tracks, endpoint cannot work");
				return;
			}
			self->priv->audio_track_selector = gst_object_ref(track_selector);
			gst_bin_add(GST_BIN(self), self->priv->audio_track_selector);
			gst_element_sync_state_with_parent (self->priv->audio_track_selector);
		}
		track_selector = self->priv->audio_track_selector;
	} else if (media_type == 1) {
		if (self->priv->video_track_selector == NULL) {
			track_selector = gst_element_factory_make ("input-selector", "video-track-selector");
			if (track_selector == NULL) {
				GST_ERROR_OBJECT(self, "Cannot build input selector for incoming video tracks, endpoint cannot work");
				return;
			}
			self->priv->video_track_selector = gst_object_ref(track_selector);
			gst_bin_add(GST_BIN(self), self->priv->video_track_selector);
			gst_element_sync_state_with_parent (self->priv->video_track_selector);
		}
		track_selector = self->priv->video_track_selector;
	}

	// Disconnect depayloader from agnostic bin and  connect track selector to agnosticbin
	reconnect_output_agnostic (depayloader, track_selector, output_agnosticbin);
	KMS_ELEMENT_UNLOCK(self);

	// Connect depayloader to agnosticbin
	kms_sip_rtp_endpoint_connect_depayloader_to_selector (self, depayloader, track_selector, ssrc, media_type);
}

static void
kms_sip_rtp_endpoint_rtpbin_pad_added (GstElement * rtpbin, GstPad * pad,
    KmsSipRtpEndpoint * self)
{
	// A new pad has been added to rtpbin, let's see if it is for receiving a new ssrc
	const gchar *pad_name = gst_pad_get_name (pad);

	if (g_str_has_prefix (pad_name, "recv_rtp_src_")) {
 		GST_PAD_STREAM_LOCK (pad);
 		// New pad for incoming media track, let's prepare pipeline for it
		guint media_type, ssrc, pt;
		GstElement *depayloader = get_depayloader_from_pad (pad);
		GstElement *output_agnosticbin;

		if (depayloader == NULL) {
			// No connection possible.
   			GST_PAD_STREAM_UNLOCK (pad);
			return;
		}
		output_agnosticbin = get_outputagnostic_from_depayloader (depayloader);
		sscanf (pad_name, "recv_rtp_src_%u_%u_%u", &media_type, &ssrc, &pt);
		kms_sip_rtp_endpoint_add_active_input_to_selector (self, depayloader, output_agnosticbin, media_type, ssrc, pt);
		gst_object_unref(output_agnosticbin);
		gst_object_unref(depayloader);
 		GST_PAD_STREAM_UNLOCK (pad);
 	}
}


static gboolean
set_output_active_track (KmsSipRtpEndpoint *self, guint ssrc, guint media_type)
{
	gint64 now = g_get_real_time ();
	GstElement *track_selector = NULL;
	GstPad *active_track_pad = NULL;
	gint64 last_ssrc_switch = 0;
	gint current_ssrc;
	const gchar  *media = (media_type == 0) ? "audio" : "video";

	KMS_ELEMENT_LOCK(self);
	if (media_type == AUDIO_RTP_SESSION) {
		current_ssrc = self->priv->current_ssrc_audio_track;
	} else if (media_type == VIDEO_RTP_SESSION) {
		current_ssrc = self->priv->current_ssrc_video_track;
	} else {
		KMS_ELEMENT_UNLOCK(self);
		return FALSE;
	}

	// If on same track nothing to do
	if (current_ssrc == ssrc) {
		KMS_ELEMENT_UNLOCK(self);
		return FALSE;
	}

	if (media_type == AUDIO_RTP_SESSION) {
		track_selector = self->priv->audio_track_selector;
		last_ssrc_switch = self->priv->last_audio_ssrc_switch;
		track_selector = self->priv->audio_track_selector;
	} else if (media_type == VIDEO_RTP_SESSION) {
		track_selector = self->priv->video_track_selector;
		last_ssrc_switch = self->priv->last_video_ssrc_switch;
		track_selector = self->priv->video_track_selector;
	}

	// Check if last change was before enough or not (1 second)
	if ((last_ssrc_switch != 0) && ((now-last_ssrc_switch) < SSRC_SWITCH_SAFE_PERIOD_MS )) {
		KMS_ELEMENT_UNLOCK(self);
		return FALSE;
	}

	// switching ssrc, we must update timestamp of ssrc switch, current active track pad and change active pad on input selector.
	GST_DEBUG_OBJECT(self, "Switching ssrc from %u to %u in %s track", current_ssrc, ssrc, media);
	if (media_type == AUDIO_RTP_SESSION) {
		self->priv->last_audio_ssrc_switch = now;
		self->priv->current_ssrc_audio_track = ssrc;
	} else if (media_type == VIDEO_RTP_SESSION) {
		self->priv->last_video_ssrc_switch = now;
		self->priv->current_ssrc_video_track = ssrc;
	}

	active_track_pad = g_hash_table_lookup (self->priv->selector_pads, GINT_TO_POINTER(ssrc));
	if ((track_selector != NULL) && (active_track_pad != NULL)) {
		GST_DEBUG_OBJECT(self, "set_output_active_track: switching track selector %s  from ssrc %u to %u in pad %s", track_selector->object.name, current_ssrc, ssrc, active_track_pad->object.name);
		g_object_set (track_selector, "active-pad", active_track_pad, NULL);
	}

	KMS_ELEMENT_UNLOCK(self);

	// Also if track type is video, ask for a keyframe
	if ((media_type == VIDEO_RTP_SESSION) && (active_track_pad != NULL)) {
		send_force_key_unit_event (active_track_pad);
	}
	return TRUE;
}

static gboolean
set_output_active_audio_track (KmsSipRtpEndpoint *self, guint ssrc)
{
	return set_output_active_track (self, ssrc, AUDIO_RTP_SESSION);
}

static gboolean
set_output_active_video_track (KmsSipRtpEndpoint *self, guint ssrc)
{
	return set_output_active_track (self, ssrc, VIDEO_RTP_SESSION);
}

static GstPadProbeReturn
video_sync_rtp_probe (GstPad * pad, GstPadProbeInfo * info, gpointer elem)
{
	KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT(elem);
	guint ssrc = GPOINTER_TO_UINT(g_hash_table_lookup(self->priv->pads_to_ssrc, pad));

	if (ssrc == 0) {
		GST_ERROR_OBJECT(self, "video_sync_rtp_probe, no video SSRC");
		return GST_PAD_PROBE_DROP;
	}

	// check if  switching to a different ssrc
	set_output_active_video_track (self, ssrc);

	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
audio_sync_rtp_probe (GstPad * pad, GstPadProbeInfo * info, gpointer elem)
{
	KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT(elem);
	guint ssrc = GPOINTER_TO_UINT(g_hash_table_lookup(self->priv->pads_to_ssrc, pad));

	if (ssrc == 0) {
		GST_ERROR_OBJECT(self, "audio_sync_rtp_probe, no audio SSRC");
		return GST_PAD_PROBE_DROP;
	}

	// Check if switching to a different ssrc
	set_output_active_audio_track (self, ssrc);

	return GST_PAD_PROBE_OK;
}

static void 
kms_sip_rtp_endpoint_deactivate_audio_synchronizer (KmsSipRtpEndpoint *self, GstElement *jitterbuffer, guint ssrc)
{
	GstPad *src_pad;

	GST_INFO_OBJECT (jitterbuffer, "kms_sip_rtp_endpoint_deactivate_audio_synchronizer: deactivate sycnhronizer");
	src_pad = gst_element_get_static_pad (jitterbuffer, "src");
	g_hash_table_insert(self->priv->pads_to_ssrc, g_object_ref(src_pad), GUINT_TO_POINTER(ssrc));
	gst_pad_add_probe (src_pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST,
      (GstPadProbeCallback) audio_sync_rtp_probe, self, NULL);
  	g_object_unref (src_pad);
}

static void 
kms_sip_rtp_endpoint_deactivate_video_synchronizer (KmsSipRtpEndpoint *self, GstElement *jitterbuffer, guint ssrc)
{
	GstPad *src_pad;

	GST_INFO_OBJECT (jitterbuffer, "kms_sip_rtp_endpoint_deactivate_video_synchronizer: Adjust video jitterbuffer PTS out");
	src_pad = gst_element_get_static_pad (jitterbuffer, "src");
	g_hash_table_insert(self->priv->pads_to_ssrc, g_object_ref(src_pad), GUINT_TO_POINTER(ssrc));
	gst_pad_add_probe (src_pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST,
      (GstPadProbeCallback) video_sync_rtp_probe, self, NULL);
  	g_object_unref (src_pad);
}

static void
kms_sip_rtp_endpoint_rtpbin_new_jitterbuffer (GstElement * rtpbin,
    GstElement * jitterbuffer,
    guint session, guint ssrc, KmsSipRtpEndpoint * self)
{
  switch (session) {
    case AUDIO_RTP_SESSION: {
		kms_sip_rtp_endpoint_deactivate_audio_synchronizer (self, jitterbuffer, ssrc);
		break;
    }
    case VIDEO_RTP_SESSION: {
		kms_sip_rtp_endpoint_deactivate_video_synchronizer (self, jitterbuffer, ssrc);
		break;
    }
    default:
      break;
  }
}


static void 
kms_sip_rtp_endpoint_intercept_jitter_buffers (KmsSipRtpEndpoint * self)
{
	GstElement *rtpbin = self->priv->rtpbin;

	if (rtpbin == NULL) {
		return;
	}
	g_signal_connect (rtpbin, "new-jitterbuffer",
		G_CALLBACK (kms_sip_rtp_endpoint_rtpbin_new_jitterbuffer), self);
}

static void
kms_sip_rtp_endpoint_init (KmsSipRtpEndpoint * self)
{
	GstElement *rtpbin = find_rtpbin_in_element(GST_BIN(self));
	
	self->priv = KMS_SIP_RTP_ENDPOINT_GET_PRIVATE (self);
	
	self->priv->use_sdes_cache = -1;
	self->priv->sessionData = NULL;
	self->priv->dscp_value = DEFAULT_QOS_DSCP;
	if (rtpbin != NULL) {
		self->priv->rtpbin = gst_object_ref(rtpbin);
	} else {
		self->priv->rtpbin = NULL;
	}
	self->priv->audio_track_selector = NULL;
	self->priv->video_track_selector = NULL;self->priv->last_audio_ssrc_switch = 0;
	self->priv->last_video_ssrc_switch = 0;
	self->priv->current_ssrc_video_track = 0;
	self->priv->pads_to_ssrc = g_hash_table_new_full (NULL, NULL, gst_object_unref, NULL);
	self->priv->selector_pads = g_hash_table_new_full (NULL, NULL, NULL, gst_object_unref);
	
	kms_sip_rtp_endpoint_intercept_jitter_buffers (self);
	if (self->priv->rtpbin != NULL) {
		self->priv->pad_added_signal =  g_signal_connect_data (self->priv->rtpbin, "pad-added",
			G_CALLBACK (kms_sip_rtp_endpoint_rtpbin_pad_added), self, NULL, G_CONNECT_AFTER);
  	}

  	GST_DEBUG ("Initialized RTP Endpoint %p", self);
}

gboolean
kms_sip_rtp_endpoint_plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, PLUGIN_NAME, GST_RANK_NONE,
      KMS_TYPE_SIP_RTP_ENDPOINT);
}

gboolean
kms_sip_rtp_endpoint_library_init (GstPlugin * plugin)
{
  if (!kms_sip_rtp_endpoint_plugin_init (plugin))
    return FALSE;

  if (!gst_traffic_shaper_plugin_init (plugin))
    return FALSE;

  return TRUE;
 }



GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    siprtpendpoint,
    "Kurento SIP rtp endpoint",
    kms_sip_rtp_endpoint_library_init, VERSION, GST_LICENSE_UNKNOWN,
    "NaevaTec Kurento utils", "http://www.naevatec.com")
