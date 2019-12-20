/*
 * (C) Copyright 2015 Kurento (http://kurento.org/)
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

#include "kmssipsrtpconnection.h"
#include "kmssocketutils.h"
#include <commons/constants.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtp/gstrtcpbuffer.h>



// TODO: this hack can be removed when we integrate this into kms-elements and make kms_rtp_connection_new  able to
// get an object factory
struct _KmsSrtpConnectionPrivate
{
  GSocket *rtp_socket;
  GstElement *rtp_udpsink;
  GstElement *rtp_udpsrc;

  GSocket *rtcp_socket;
  GstElement *rtcp_udpsink;
  GstElement *rtcp_udpsrc;

  GstElement *srtpenc;
  GstElement *srtpdec;

  gboolean added;
  gboolean connected;
  gboolean is_client;

  gchar *r_key;
  guint r_auth;
  guint r_cipher;
  gboolean r_updated;
  gboolean r_key_set;
};

static gchar *auths[] = {
  NULL,
  "hmac-sha1-32",
  "hmac-sha1-80"
};

static gchar *ciphers[] = {
  NULL,
  "aes-128-icm",
  "aes-256-icm"
};



void
kms_sip_srtp_connection_retrieve_sockets (GHashTable *conns, const GstSDPMedia * media, GSocket **rtp, GSocket **rtcp)
{
	gchar *media_key;
	KmsSrtpConnection *conn;

	const gchar *media_str = gst_sdp_media_get_media (media);

	/* TODO: think about this when multiple audio/video medias */
	if (g_strcmp0 (AUDIO_STREAM_NAME, media_str) == 0) {
	  media_key = AUDIO_RTP_SESSION_STR;
	} else if (g_strcmp0 (VIDEO_STREAM_NAME, media_str) == 0) {
		  media_key = VIDEO_RTP_SESSION_STR;
	} else {
		  media_key = "";
	}

	conn = KMS_SRTP_CONNECTION (g_hash_table_lookup (conns, media_key));
	if (conn != NULL) {
		// Retrieve the sockets
		*rtcp = g_object_ref (conn->priv->rtcp_socket);
		*rtp = g_object_ref (conn->priv->rtp_socket);

		// remove sockets from multiudpsink and udpsrc so that they are disconnected from previous endpoint
		//  so that they are not released on previoues endpoint finalization
		g_object_set (conn->priv->rtp_udpsink, "close-socket", FALSE, NULL);
		g_object_set (conn->priv->rtcp_udpsink, "close-socket", FALSE, NULL);
		g_object_set (conn->priv->rtp_udpsink, "socket", NULL);
	    g_object_set (conn->priv->rtp_udpsrc, "socket", NULL);
		g_object_set (conn->priv->rtcp_udpsink, "socket", NULL);
		g_object_set (conn->priv->rtcp_udpsrc, "socket", NULL);

		conn->priv->rtcp_socket = NULL;
		conn->priv->rtp_socket = NULL;
	}
}

static gboolean
check_ssrc (guint32 ssrc, GList *old_ssrc)
{
	GList *it = old_ssrc;

	while (it != NULL) {
		if (ssrc == GPOINTER_TO_UINT(it->data))
			return TRUE;
		it = it->next;
	}
	return FALSE;
}

static GstPadProbeReturn
filter_old_ssrc_rtp_buffer (GstBuffer *buffer, GList *old_ssrc)
{
	GstRTPBuffer rtp_buffer =  GST_RTP_BUFFER_INIT;

	if (gst_rtp_buffer_map (buffer, GST_MAP_READ, &rtp_buffer)) {
		GST_DEBUG ("filter old ssrc RTP buffer");
		guint32 checked_ssrc = gst_rtp_buffer_get_ssrc (&rtp_buffer);

		gst_rtp_buffer_unmap (&rtp_buffer);
		if (check_ssrc (checked_ssrc, old_ssrc)) {
			GST_INFO ("RTP packet dropped from a previous RTP flow with SSRC %u", checked_ssrc);
			return GST_PAD_PROBE_DROP;
		} else {
			// We are pushing an EXPECTED SSRC, so after its processing this probe is no longer needed
			GST_DEBUG ("filter old ssrc forwarded buffer %u", checked_ssrc);
			return GST_PAD_PROBE_OK;
		}
	}

	GST_WARNING ("Buffer not mapped to RTP");
	return GST_PAD_PROBE_OK;
}


static gboolean
filter_buffer (GstBuffer ** buffer, guint idx, gpointer user_data)
{
	GList *old_ssrc = user_data;

	if (filter_old_ssrc_rtp_buffer(*buffer, old_ssrc) == GST_PAD_PROBE_DROP)
		*buffer = NULL;

	return TRUE;
}

static GstPadProbeReturn
filter_old_ssrc_rtp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	GList *old_ssrc = user_data;
	GstBuffer *buffer;

	GST_DEBUG ("Filtering RTP packets from previous flows to this receiver");
	buffer = GST_PAD_PROBE_INFO_BUFFER (info);
	if (buffer != NULL) {
		GST_DEBUG ("RTP buffer received from Filtering RTP packets from previous flows to this receiver");

		return filter_old_ssrc_rtp_buffer (buffer, old_ssrc);
	} else  {
		GstBufferList *buffer_list;

		buffer_list = gst_pad_probe_info_get_buffer_list (info);

		if (buffer_list != NULL) {
			GST_DEBUG ("filter old ssrc buffer list RTP");
			if (!gst_buffer_list_foreach(buffer_list, filter_buffer, user_data))
				GST_WARNING("Filtering buffer list for old ssrc failed");
		}
	}
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
filter_old_ssrc_rtcp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	GList *old_ssrc = user_data;
	GstBuffer *buffer;

	buffer = GST_PAD_PROBE_INFO_BUFFER (info);

	GstRTCPBuffer rtcp_buffer = GST_RTCP_BUFFER_INIT;

	GST_DEBUG ("Filtering RTCP buffer from previous flows to this receiver");
    if (gst_rtcp_buffer_map (buffer, GST_MAP_READ, &rtcp_buffer)) {
    	GstRTCPPacket packet;
		gboolean has_packet;

		has_packet = gst_rtcp_buffer_get_first_packet (&rtcp_buffer, &packet);

		GST_DEBUG ("Filtering RTCP packets from previous flows to this receiver");
    	gst_rtcp_buffer_unmap (&rtcp_buffer);
		return  GST_PAD_PROBE_DROP;

    	while (has_packet) {
    		GstRTCPType  packet_type = gst_rtcp_packet_get_type (&packet);

    		if (packet_type == GST_RTCP_TYPE_SR) {
        		guint32 ssrc, rtptime, packet_count, octet_count;
        		guint64 ntptime;

    			gst_rtcp_packet_sr_get_sender_info    (&packet, &ssrc, &ntptime, &rtptime, &packet_count, &octet_count);
    			if (check_ssrc (ssrc, old_ssrc)) {
    				gst_rtcp_packet_remove (&packet);
    			}
    		}
    		has_packet = gst_rtcp_packet_move_to_next (&packet);
    	}
    	gst_rtcp_buffer_unmap (&rtcp_buffer);
	}

    return GST_PAD_PROBE_OK;
}


static gulong
setup_probe_filter_old_ssrc_rtp (GstPad *pad, GList *old_ssrc)
{
    GST_DEBUG("Installing RTP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
    return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST | GST_PAD_PROBE_TYPE_PUSH | GST_PAD_PROBE_TYPE_PULL,
        (GstPadProbeCallback) filter_old_ssrc_rtp, g_list_copy(old_ssrc), (GDestroyNotify) g_list_free);
}

static gulong
setup_probe_filter_old_ssrc_rtcp (GstPad *pad, GList *old_ssrc)
{
    GST_DEBUG("Installing RTCP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
    return gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER,
        (GstPadProbeCallback) filter_old_ssrc_rtcp, g_list_copy(old_ssrc), (GDestroyNotify) g_list_free);
}

static void
kms_sip_srtp_connection_new_pad_cb (GstElement * element, GstPad * pad,
    KmsSrtpConnection * conn)
{
  GstPadTemplate *templ;
  GstPad *sinkpad = NULL;

  templ = gst_pad_get_pad_template (pad);

  if (g_strcmp0 (GST_PAD_TEMPLATE_NAME_TEMPLATE (templ), "rtp_src_%u") == 0) {
    sinkpad = gst_element_get_static_pad (conn->priv->rtp_udpsink, "sink");
  } else if (g_strcmp0 (GST_PAD_TEMPLATE_NAME_TEMPLATE (templ),
          "rtcp_src_%u") == 0) {
    sinkpad = gst_element_get_static_pad (conn->priv->rtcp_udpsink, "sink");
  } else {
    goto end;
  }

  gst_pad_link (pad, sinkpad);

end:
  g_object_unref (templ);
  g_clear_object (&sinkpad);
}

static const gchar *
get_str_auth (guint auth)
{
  const gchar *str_auth = NULL;

  if (auth < G_N_ELEMENTS (auths)) {
    str_auth = auths[auth];
  }

  return str_auth;
}

static const gchar *
get_str_cipher (guint cipher)
{
  const gchar *str_cipher = NULL;

  if (cipher < G_N_ELEMENTS (ciphers)) {
    str_cipher = ciphers[cipher];
  }

  return str_cipher;
}


static GstCaps *
create_key_caps (guint ssrc, const gchar * key, guint auth, guint cipher)
{
  const gchar *str_cipher = NULL, *str_auth = NULL;
  GstBuffer *buff_key;
  guint8 *bin_buff;
  GstCaps *caps;
  gsize len;

  str_cipher = get_str_cipher (cipher);
  str_auth = get_str_auth (auth);

  if (str_cipher == NULL || str_auth == NULL) {
    return NULL;
  }

  bin_buff = g_base64_decode (key, &len);
  buff_key = gst_buffer_new_wrapped (bin_buff, len);

  caps = gst_caps_new_simple ("application/x-srtp",
      "srtp-key", GST_TYPE_BUFFER, buff_key,
      "srtp-cipher", G_TYPE_STRING, str_cipher,
      "srtp-auth", G_TYPE_STRING, str_auth,
      "srtcp-cipher", G_TYPE_STRING, str_cipher,
      "srtcp-auth", G_TYPE_STRING, str_auth, NULL);

  gst_buffer_unref (buff_key);

  return caps;
}


static GstCaps *
kms_sip_srtp_connection_request_remote_key_cb (GstElement * srtpdec, guint ssrc,
    KmsSrtpConnection * conn)
{
  GstCaps *caps = NULL;

  KMS_RTP_BASE_CONNECTION_LOCK (conn);

  if (!conn->priv->r_key_set) {
    GST_DEBUG_OBJECT (conn, "key is not yet set");
    goto end;
  }

  if (!conn->priv->r_updated) {
    GST_DEBUG_OBJECT (conn, "Key is not yet updated");
  } else {
    GST_DEBUG_OBJECT (conn, "Using new key");
    conn->priv->r_updated = FALSE;
  }

  caps = create_key_caps (ssrc, conn->priv->r_key, conn->priv->r_auth,
      conn->priv->r_cipher);

  GST_DEBUG_OBJECT (srtpdec, "Key Caps: %" GST_PTR_FORMAT, caps);

end:
  KMS_RTP_BASE_CONNECTION_UNLOCK (conn);

  return caps;
}

static gint key_soft_limit_signal = -1;

static gint
getKeySoftLimitSignal ()
{
	if (key_soft_limit_signal == -1) {
		key_soft_limit_signal = g_signal_lookup ("key-soft-limit", KMS_TYPE_SRTP_CONNECTION);
	}
	return key_soft_limit_signal;
}

static GstCaps *
kms_sip_srtp_connection_soft_key_limit_cb (GstElement * srtpdec, guint ssrc,
    KmsSrtpConnection * conn)
{
  g_signal_emit (conn, getKeySoftLimitSignal (), 0);

  /* FIXME: Key is about to expire, a new one should be provided */
  /* when renegotiation is supported */

  return NULL;
}



KmsSrtpConnection *
kms_sip_srtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6,
		GSocket *rtp_sock, GSocket *rtcp_sock,
		GList *old_ssrc)
{
	  // TODO: When this integrated in kms-elements we can modify kms_rtp_connection_new to allow espcifying
	  // the gstreamer object factory for the connection, so that we can simplify this function
	  GObject *obj;
	  KmsSrtpConnection *conn;
	  KmsSrtpConnectionPrivate *priv;
	  GSocketFamily socket_family;

	  obj = g_object_new (KMS_TYPE_SRTP_CONNECTION, NULL);
	  conn = KMS_SRTP_CONNECTION (obj);
	  priv = conn->priv;

	  if (use_ipv6) {
	    socket_family = G_SOCKET_FAMILY_IPV6;
	  } else {
	    socket_family = G_SOCKET_FAMILY_IPV4;
	  }

	  // TODO: This is what we need to update on kms_rtp_connection-new
	  if ((rtp_sock != NULL) && (rtcp_sock != NULL)) {
		  priv->rtp_socket = rtp_sock;
		  priv->rtcp_socket = rtcp_sock;
		  GST_ERROR ("Sockets RTP %p and RTCP %p", rtp_sock, rtcp_sock);

	  } else {
		  //   ^^^^^^^^^^^^^^^^^^^^^^^^^
		  // TODO: Up to here
		  if (!kms_rtp_connection_get_rtp_rtcp_sockets
		      (&priv->rtp_socket, &priv->rtcp_socket, min_port, max_port,
		          socket_family)) {
		    GST_ERROR_OBJECT (obj, "Cannot get ports");
		    g_object_unref (obj);
		    return NULL;
		  }
		  GST_ERROR ("Sockets RTP %p and RTCP %p", priv->rtp_socket, priv->rtcp_socket);
	  }

	  priv->r_updated = FALSE;
	  priv->r_key_set = FALSE;

	  priv->srtpenc = gst_element_factory_make ("srtpenc", NULL);
	  priv->srtpdec = gst_element_factory_make ("srtpdec", NULL);
	  g_signal_connect (priv->srtpenc, "pad-added",
	      G_CALLBACK (kms_sip_srtp_connection_new_pad_cb), obj);
	  g_signal_connect (priv->srtpdec, "request-key",
	      G_CALLBACK (kms_sip_srtp_connection_request_remote_key_cb), obj);
	  g_signal_connect (priv->srtpdec, "soft-limit",
	      G_CALLBACK (kms_sip_srtp_connection_soft_key_limit_cb), obj);

	  priv->rtp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  priv->rtp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  priv->rtcp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  priv->rtcp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  if ((rtp_sock != NULL) && (rtcp_sock != NULL)) {
		  // If we are reusing sockets, it is possible that packets from old connection (old ssrcs) arrive to the sockets
		  // They should be avoided as they may auto setup the new connection for old SSRCs, preventing the new connection to succed
		  GstPad *pad;

		  pad = gst_element_get_static_pad (priv->rtcp_udpsrc, "src");

		  setup_probe_filter_old_ssrc_rtcp (pad, old_ssrc);
		  gst_object_unref (pad);

		  pad = gst_element_get_static_pad (priv->rtp_udpsrc, "src");
		  setup_probe_filter_old_ssrc_rtp (pad, old_ssrc);
		  gst_object_unref (pad);
	  }

	  g_object_set (priv->rtp_udpsink, "socket", priv->rtp_socket,
	      "sync", FALSE, "async", FALSE, NULL);
	  g_object_set (priv->rtp_udpsrc, "socket", priv->rtp_socket, "auto-multicast",
	      FALSE, NULL);

	  g_object_set (priv->rtcp_udpsink, "socket", priv->rtcp_socket,
	      "sync", FALSE, "async", FALSE, NULL);
	  g_object_set (priv->rtcp_udpsrc, "socket", priv->rtcp_socket,
	      "auto-multicast", FALSE, NULL);

	  kms_i_rtp_connection_connected_signal (KMS_I_RTP_CONNECTION (conn));

	  return conn;
}


