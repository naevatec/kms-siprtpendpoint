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

#include "kmssiprtpconnection.h"
#include "kmssocketutils.h"
#include "kmsrtpfilterutils.h"
#include <commons/constants.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtp/gstrtcpbuffer.h>

// TODO: this hack can be removed when we integrate this into kms-elements and make kms_rtp_connection_new  able to
// get an object factory
struct _KmsRtpConnectionPrivate
{
  GSocket *rtp_socket;
  GstElement *rtp_udpsink;
  GstElement *rtp_udpsrc;

  GSocket *rtcp_socket;
  GstElement *rtcp_udpsink;
  GstElement *rtcp_udpsrc;

  gboolean added;
  gboolean connected;
  gboolean is_client;
};

void
kms_sip_rtp_connection_retrieve_sockets (GHashTable *conns, const GstSDPMedia * media, GSocket **rtp, GSocket **rtcp)
{
	gchar *media_key;
	KmsRtpConnection *conn;

	const gchar *media_str = gst_sdp_media_get_media (media);

	/* TODO: think about this when multiple audio/video medias */
	if (g_strcmp0 (AUDIO_STREAM_NAME, media_str) == 0) {
	  media_key = AUDIO_RTP_SESSION_STR;
	} else if (g_strcmp0 (VIDEO_STREAM_NAME, media_str) == 0) {
	  media_key = VIDEO_RTP_SESSION_STR;
	} else {
	  media_key = "";
	}

	conn = KMS_RTP_CONNECTION (g_hash_table_lookup (conns, media_key));
	if (conn != NULL) {
		// Retrieve the sockets
		*rtcp = g_object_ref (conn->priv->rtcp_socket);
		*rtp = g_object_ref (conn->priv->rtp_socket);

		// remove sockets from multiudpsink and udpsrc so that they are disconnected from previous endpoint
		//  so that they are not released on previoues endpoint finalization
		g_object_set (conn->priv->rtp_udpsink, "close-socket", FALSE, NULL);
		g_object_set (conn->priv->rtcp_udpsink, "close-socket", FALSE, NULL);
		g_object_set (conn->priv->rtp_udpsrc, "close-socket", FALSE, NULL);
		g_object_set (conn->priv->rtcp_udpsrc, "close-socket", FALSE, NULL);

		g_object_set (conn->priv->rtp_udpsink, "socket", NULL);
	    g_object_set (conn->priv->rtp_udpsrc, "socket", NULL);
		g_object_set (conn->priv->rtcp_udpsink, "socket", NULL);
		g_object_set (conn->priv->rtcp_udpsrc, "socket", NULL);

		conn->priv->rtcp_socket = NULL;
		conn->priv->rtp_socket = NULL;
	}
}


void
kms_sip_rtp_connection_add_probes (KmsRtpConnection *conn, guint32 expected_ssrc, gulong *rtp_probe_id, gulong *rtcp_probe_id)
{
	  KmsRtpConnectionPrivate *priv = conn->priv;

	  // If we are reusing sockets, it is possible that packets from old connection (old ssrcs) arrive to the sockets
	  // They should be avoided as they may auto setup the new connection for old SSRCs, preventing the new connection to succed
	  GstPad *pad;

	  pad = gst_element_get_static_pad (priv->rtcp_udpsrc, "src");

	  *rtcp_probe_id = kms_sip_rtp_filter_setup_probe_rtcp (pad, expected_ssrc);
	  gst_object_unref (pad);

	  pad = gst_element_get_static_pad (priv->rtp_udpsrc, "src");
	  *rtp_probe_id = kms_sip_rtp_filter_setup_probe_rtp (pad, expected_ssrc);
	  gst_object_unref (pad);
}


KmsRtpConnection *
kms_sip_rtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6, GSocket *rtp_sock, GSocket *rtcp_sock,
		guint32 expected_ssrc, gulong *rtp_probe_id, gulong *rtcp_probe_id)
{
	  // TODO: When this integrated in kms-elements we can modify kms_rtp_connection_new to allow espcifying
	  // the gstreamer object factory for the connection, so that we can simplify this function
	  GObject *obj;
	  KmsRtpConnection *conn;
	  KmsRtpConnectionPrivate *priv;
	  GSocketFamily socket_family;

	  obj = g_object_new (KMS_TYPE_RTP_CONNECTION, NULL);
	  conn = KMS_RTP_CONNECTION (obj);
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
	  }

	  priv->rtp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  priv->rtp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  priv->rtcp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  priv->rtcp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  if (expected_ssrc != 0) {
		  kms_sip_rtp_connection_add_probes (conn, expected_ssrc, rtp_probe_id, rtcp_probe_id);
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

void
kms_sip_rtp_connection_release_probes (KmsRtpConnection *conn, gulong rtp_probe_id, gulong rtcp_probe_id)
{
	  KmsRtpConnectionPrivate *priv;
	  GstPad *pad;

	  priv = conn->priv;

	  // Release RTCP probe
	  pad = gst_element_get_static_pad (priv->rtcp_udpsrc, "src");
	  kms_sip_rtp_filter_release_probe_rtcp (pad, rtcp_probe_id);
	  gst_object_unref (pad);

	  // Release RTP probe
	  pad = gst_element_get_static_pad (priv->rtp_udpsrc, "src");
	  kms_sip_rtp_filter_release_probe_rtp (pad, rtp_probe_id);
	  gst_object_unref (pad);
}


