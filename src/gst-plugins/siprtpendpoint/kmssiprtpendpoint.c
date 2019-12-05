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

#include <string.h>
#include <nice/interfaces.h>
#include "kmssiprtpendpoint.h"
#include "kmssiprtpsession.h"
#include "kmssipsrtpsession.h"
#include <commons/kmsbasesdpendpoint.h>
#include <commons/constants.h>

#define PLUGIN_NAME "siprtpendpoint"

GST_DEBUG_CATEGORY_STATIC (kms_sip_rtp_endpoint_debug);
#define GST_CAT_DEFAULT kms_sip_rtp_endpoint_debug

#define kms_sip_rtp_endpoint_parent_class parent_class
G_DEFINE_TYPE (KmsSipRtpEndpoint, kms_sip_rtp_endpoint, KMS_TYPE_RTP_ENDPOINT);


#define KMS_SIP_RTP_ENDPOINT_GET_PRIVATE(obj) (  \
  G_TYPE_INSTANCE_GET_PRIVATE (              \
    (obj),                                   \
    KMS_TYPE_SIP_RTP_ENDPOINT,                   \
    KmsSipRtpEndpointPrivate                    \
  )                                          \
)


typedef struct _KmsSipRtpEndpointCloneData KmsSipRtpEndpointCloneData;


struct _KmsSipRtpEndpointCloneData
{
	guint32 audio_ssrc;
	guint32 video_ssrc;

	GHashTable *conns;
};

struct _KmsSipRtpEndpointPrivate
{
  gboolean *use_sdes_cache;

  GList *sessionData;

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

static void
kms_sip_rtp_endpoint_clone_rtp_session (GstElement * rtpbin, guint sessionId, guint32 ssrc, gchar *rtpbin_pad_name)
{
	GObject *rtpSession;
    GstPad *pad;

	/* Create RtpSession requesting the pad */
	pad = gst_element_get_request_pad (rtpbin, rtpbin_pad_name);
	g_object_unref (pad);

	g_signal_emit_by_name (rtpbin, "get-internal-session", sessionId, &rtpSession);
	if (rtpSession != NULL) {
		g_object_set (rtpSession, "internal-ssrc", ssrc, NULL);
	}

	g_object_unref(rtpSession);

}
static GstElement*
kms_sip_rtp_endpoint_get_rtpbin (KmsSipRtpEndpoint * self)
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


static void
kms_sip_rtp_endpoint_clone_session (KmsSipRtpEndpoint * self, KmsSdpSession ** sess)
{
	GstElement *rtpbin = kms_sip_rtp_endpoint_get_rtpbin (self);
	GList *sessionToClone = self->priv->sessionData;

	if (rtpbin != NULL) {

		// TODO: Multisession seems not used on RTPEndpoint, anyway we are doing something probably incorrect
		// once multisession is used, that is to assume that creation order of sessions are maintained among all
		// endpoints, and so order can be used to correlate internal rtp sessions.
		KmsBaseRtpSession *clonedSes = KMS_BASE_RTP_SESSION (*sess);
		KmsSipRtpSession *clonedSipSes = KMS_SIP_RTP_SESSION (*sess);
		//GHashTable *origConns = ((KmsSipRtpEndpointCloneData*)sessionToClone->data)->conns;
		guint32 ssrc;

		/* TODO: think about this when multiple audio/video medias */
		// Audio
		//      Clone SSRC
		ssrc = ((KmsSipRtpEndpointCloneData*)sessionToClone->data)->audio_ssrc;
		clonedSes->local_audio_ssrc = ssrc;
		kms_sip_rtp_endpoint_clone_rtp_session (rtpbin, AUDIO_RTP_SESSION, ssrc, AUDIO_RTPBIN_SEND_RTP_SINK);

		// Video
		//        Clone SSRC
		ssrc = ((KmsSipRtpEndpointCloneData*)sessionToClone->data)->video_ssrc;
		clonedSes->local_video_ssrc = ssrc;
		kms_sip_rtp_endpoint_clone_rtp_session (rtpbin, VIDEO_RTP_SESSION, ssrc, VIDEO_RTPBIN_SEND_RTP_SINK);

		KMS_SIP_RTP_SESSION_CLASS(G_OBJECT_GET_CLASS(clonedSipSes))->clone_connections (clonedSipSes,
				((KmsSipRtpEndpointCloneData*)sessionToClone->data)->conns);

		////       Clone sockets
		//kms_sip_rtp_endpoint_clone_connections (origConns, clonedSes);
	}
}



static gboolean isUseSdes (KmsSipRtpEndpoint * self)
{
	if (self->priv->use_sdes_cache == NULL) {
		gboolean useSdes;

		g_object_get (G_OBJECT(self), "use-sdes", &useSdes, NULL);
		self->priv->use_sdes_cache = g_malloc(sizeof(gboolean));
		*self->priv->use_sdes_cache = useSdes;
	}
	return *self->priv->use_sdes_cache;
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

  /* Get ip address now that session is bein created */
  kms_sip_rtp_endpoint_set_addr (self);

  g_object_get (self, "use-ipv6", &use_ipv6, NULL);
  if (isUseSdes(self)) {
    *sess =
        KMS_SDP_SESSION (kms_sip_srtp_session_new (base_sdp, id, manager,
            use_ipv6));
  } else {
    *sess =
        KMS_SDP_SESSION (kms_sip_rtp_session_new (base_sdp, id, manager, use_ipv6));
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


static void
kms_sip_rtp_endpoint_start_transport_send (KmsBaseSdpEndpoint *base_sdp_endpoint,
    KmsSdpSession *sess, gboolean offerer)
{
	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->start_transport_send (base_sdp_endpoint, sess, offerer);

}

static KmsSipRtpEndpointCloneData*
kms_sip_rtp_endpoint_create_clone_data (guint32 ssrcAudio, guint32 ssrcVideo, GHashTable *conns)
{
	KmsSipRtpEndpointCloneData *data = g_malloc(sizeof (KmsSipRtpEndpointCloneData));

	data->audio_ssrc = ssrcAudio;
	data->video_ssrc = ssrcVideo;
	data->conns = g_hash_table_ref(conns);

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
kms_sip_rtp_endpoint_clone_to_new_ep (KmsSipRtpEndpoint *self, KmsSipRtpEndpoint *cloned)
{
	GHashTable * sessions = kms_base_sdp_endpoint_get_sessions (KMS_BASE_SDP_ENDPOINT(self));
	GList *sessionKeys = g_hash_table_get_keys (sessions);
	gint i;
	GList *sessionsData = NULL;

	for (i = 0; i < g_hash_table_size(sessions); i++) {
		gpointer sesKey = sessionKeys->data;
		KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION (g_hash_table_lookup (sessions, sesKey));
		guint32 localAudioSsrc = ses->local_audio_ssrc;
		guint32 localVIdeoSsrc = ses->local_video_ssrc;
		KmsSipRtpEndpointCloneData *data = kms_sip_rtp_endpoint_create_clone_data (localAudioSsrc, localVIdeoSsrc, ses->conns);

		sessionsData = g_list_append (sessionsData, (gpointer)data);
	}

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
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  KMS_ELEMENT_LOCK (self);

  switch (prop_id) {
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

  if (self->priv->use_sdes_cache != NULL)
	  g_free (self->priv->use_sdes_cache);

  if (self->priv->sessionData != NULL)
	  kms_sip_rtp_endpoint_free_clone_data(self->priv->sessionData);

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

  /* Media handler management */
  base_sdp_endpoint_class->create_media_handler =
      kms_sip_rtp_endpoint_create_media_handler;

  base_sdp_endpoint_class->configure_media = kms_sip_rtp_endpoint_configure_media;

  klass->clone_to_new_ep = kms_sip_rtp_endpoint_clone_to_new_ep;

  obj_signals[SIGNAL_CLONE_TO_NEW_EP] =
      g_signal_new ("clone-to-new-ep",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_ACTION | G_SIGNAL_RUN_LAST,
      G_STRUCT_OFFSET (KmsSipRtpEndpointClass, clone_to_new_ep), NULL, NULL,
      NULL, G_TYPE_NONE, 1, G_TYPE_POINTER);


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

static void
kms_sip_rtp_endpoint_init (KmsSipRtpEndpoint * self)
{
  self->priv = KMS_SIP_RTP_ENDPOINT_GET_PRIVATE (self);

  self->priv->use_sdes_cache = NULL;
  self->priv->sessionData = NULL;

}

gboolean
kms_sip_rtp_endpoint_plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, PLUGIN_NAME, GST_RANK_NONE,
      KMS_TYPE_SIP_RTP_ENDPOINT);
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    kmssiprtpendpoint,
    "Kurento SIP rtp endpoint",
    kms_sip_rtp_endpoint_plugin_init, VERSION, GST_LICENSE_UNKNOWN,
    "Kurento Elements", "http://kurento.com/")
