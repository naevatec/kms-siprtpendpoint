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
#include <kurento/rtpendpoint/kmssocketutils.h>
#include "kmsrtpfilterutils.h"
#include <commons/constants.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtp/gstrtcpbuffer.h>

// TODO: this hack can be removed when we integrate this into kms-elements and make kms_rtp_connection_new  able to
// get an object factory
/*struct _KmsSrtpConnectionPrivate
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
}; */

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
kms_sip_srtp_connection_retrieve_sockets (KmsSrtpConnection *conn, GSocket **rtp, GSocket **rtcp)
{
	if (conn != NULL) {
		// Retrieve the sockets
		*rtcp = g_object_ref (conn->rtcp_socket);
		*rtp = g_object_ref (conn->rtp_socket);

		// remove sockets from multiudpsink and udpsrc so that they are disconnected from previous endpoint
		//  so that they are not released on previoues endpoint finalization
		g_object_set (conn->rtp_udpsink, "close-socket", FALSE, NULL);
		g_object_set (conn->rtcp_udpsink, "close-socket", FALSE, NULL);
		g_object_set (conn->rtp_udpsrc, "close-socket", FALSE, NULL);
		g_object_set (conn->rtcp_udpsrc, "close-socket", FALSE, NULL);
//		g_object_set (conn->rtp_udpsink, "socket", NULL);
//	    g_object_set (conn->rtp_udpsrc, "socket", NULL);
//		g_object_set (conn->rtcp_udpsink, "socket", NULL);
//		g_object_set (conn->rtcp_udpsrc, "socket", NULL);

		conn->rtcp_socket = NULL;
		conn->rtp_socket = NULL;
	}
}


static void
kms_sip_srtp_connection_new_pad_cb (GstElement * element, GstPad * pad,
    KmsSrtpConnection * conn)
{
  GstPadTemplate *templ;
  GstPad *sinkpad = NULL;

  templ = gst_pad_get_pad_template (pad);

  if (g_strcmp0 (GST_PAD_TEMPLATE_NAME_TEMPLATE (templ), "rtp_src_%u") == 0) {
    sinkpad = gst_element_get_static_pad (conn->rtp_udpsink, "sink");
  } else if (g_strcmp0 (GST_PAD_TEMPLATE_NAME_TEMPLATE (templ),
          "rtcp_src_%u") == 0) {
    sinkpad = gst_element_get_static_pad (conn->rtcp_udpsink, "sink");
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

  if (!conn->r_key_set) {
    GST_DEBUG_OBJECT (conn, "key is not yet set");
    goto end;
  }

  if (!conn->r_updated) {
    GST_DEBUG_OBJECT (conn, "Key is not yet updated");
  } else {
    GST_DEBUG_OBJECT (conn, "Using new key");
    conn->r_updated = FALSE;
  }

  caps = create_key_caps (ssrc, conn->r_key, conn->r_auth,
      conn->r_cipher);

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
  g_signal_emit (conn, getKeySoftLimitSignal(), 0);

  /* FIXME: Key is about to expire, a new one should be provided */
  /* when renegotiation is supported */

  return NULL;
}

void
kms_sip_srtp_connection_add_probes (KmsSrtpConnection *conn, SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id)
{
	  // If we are reusing sockets, it is possible that packets from old connection (old ssrcs) arrive to the sockets
	  // They should be avoided as they may auto setup the new connection for old SSRCs, preventing the new connection to succed
	  GstPad *pad;

	  pad = gst_element_get_static_pad (conn->rtcp_udpsrc, "src");

	  *rtcp_probe_id = kms_sip_rtp_filter_setup_probe_rtcp (pad, filter_info);
	  gst_object_unref (pad);

	  pad = gst_element_get_static_pad (conn->rtp_udpsrc, "src");
	  *rtp_probe_id = kms_sip_rtp_filter_setup_probe_rtp (pad, filter_info);
	  gst_object_unref (pad);
}

KmsSrtpConnection *
kms_sip_srtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6,
		GSocket *rtp_sock, GSocket *rtcp_sock,
		SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id)
{
	  // TODO: When this integrated in kms-elements we can modify kms_rtp_connection_new to allow espcifying
	  // the gstreamer object factory for the connection, so that we can simplify this function
	  GObject *obj;
	  KmsSrtpConnection *conn;
	  GSocketFamily socket_family;

	  obj = g_object_new (KMS_TYPE_SRTP_CONNECTION, NULL);
	  conn = KMS_SRTP_CONNECTION (obj);

	  if (use_ipv6) {
	    socket_family = G_SOCKET_FAMILY_IPV6;
	  } else {
	    socket_family = G_SOCKET_FAMILY_IPV4;
	  }

	  // TODO: This is what we need to update on kms_rtp_connection-new
	  if ((rtp_sock != NULL) && (rtcp_sock != NULL)) {
		  conn->rtp_socket = rtp_sock;
		  conn->rtcp_socket = rtcp_sock;
	  } else {
		  //   ^^^^^^^^^^^^^^^^^^^^^^^^^
		  // TODO: Up to here
		  if (!kms_rtp_connection_get_rtp_rtcp_sockets
		      (&conn->rtp_socket, &conn->rtcp_socket, min_port, max_port,
		          socket_family)) {
		    GST_ERROR_OBJECT (obj, "Cannot get ports");
		    g_object_unref (obj);
		    return NULL;
		  }
	  }

	  conn->r_updated = FALSE;
	  conn->r_key_set = FALSE;

	  conn->srtpenc = gst_element_factory_make ("srtpenc", NULL);
	  conn->srtpdec = gst_element_factory_make ("srtpdec", NULL);
	  g_signal_connect (conn->srtpenc, "pad-added",
	      G_CALLBACK (kms_sip_srtp_connection_new_pad_cb), obj);
	  g_signal_connect (conn->srtpdec, "request-key",
	      G_CALLBACK (kms_sip_srtp_connection_request_remote_key_cb), obj);
	  g_signal_connect (conn->srtpdec, "soft-limit",
	      G_CALLBACK (kms_sip_srtp_connection_soft_key_limit_cb), obj);

	  conn->rtp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  conn->rtp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  conn->rtcp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  conn->rtcp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  kms_sip_srtp_connection_add_probes (conn, filter_info, rtp_probe_id, rtcp_probe_id);

	  g_object_set (conn->rtp_udpsink, "socket", conn->rtp_socket,
	      "sync", FALSE, "async", FALSE, NULL);
	  g_object_set (conn->rtp_udpsrc, "socket", conn->rtp_socket, "auto-multicast",
	      FALSE, NULL);

	  g_object_set (conn->rtcp_udpsink, "socket", conn->rtcp_socket,
	      "sync", FALSE, "async", FALSE, NULL);
	  g_object_set (conn->rtcp_udpsrc, "socket", conn->rtcp_socket,
	      "auto-multicast", FALSE, NULL);

	  kms_i_rtp_connection_connected_signal (KMS_I_RTP_CONNECTION (conn));

	  return conn;
}


void
kms_sip_srtp_connection_release_probes (KmsSrtpConnection *conn, gulong rtp_probe_id, gulong rtcp_probe_id)
{
	  GstPad *pad;

	  // Release RTCP probe
	  pad = gst_element_get_static_pad (conn->rtcp_udpsrc, "src");
	  kms_sip_rtp_filter_release_probe_rtcp (pad, rtcp_probe_id);
	  gst_object_unref (pad);

	  // Release RTP probe
	  pad = gst_element_get_static_pad (conn->rtp_udpsrc, "src");
	  kms_sip_rtp_filter_release_probe_rtp (pad, rtp_probe_id);
	  gst_object_unref (pad);
}

