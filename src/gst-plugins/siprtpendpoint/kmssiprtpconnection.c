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
		GST_ERROR ("filter old ssrc RTP buffer");
		guint32 checked_ssrc = gst_rtp_buffer_get_ssrc (&rtp_buffer);

		if (check_ssrc (checked_ssrc, old_ssrc)) {
			GST_ERROR ("filter old ssrc dropped buffer %u", checked_ssrc);
			gst_rtp_buffer_unmap (&rtp_buffer);
			return GST_PAD_PROBE_DROP;
		} else {
			// We are pushing an EXPECTED SSRC, so after its processing this probe is no longer needed
			gst_rtp_buffer_unmap (&rtp_buffer);
			GST_ERROR ("filter old ssrc forwarded buffer %u", checked_ssrc);
			return GST_PAD_PROBE_OK;
		}
	}

	GST_ERROR ("Buffer not mapped to RTP");
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
filter_old_ssrc_rtp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	GList *old_ssrc = user_data;
	GstBuffer *buffer;

	GST_ERROR ("filter old ssrc buffer");
	buffer = GST_PAD_PROBE_INFO_BUFFER (info);
	if (buffer != NULL) {
		GST_ERROR ("filter old ssrc buffer RTP");

		return filter_old_ssrc_rtp_buffer (buffer, old_ssrc);
	} else  {
		GstBufferList *buffer_list;

		buffer_list = gst_pad_probe_info_get_buffer_list (info);

		if (buffer_list != NULL) {
			guint num_buffers;
			guint idx = 0;

			num_buffers = gst_buffer_list_length (buffer_list);
			GST_ERROR ("filter old ssrc buffer list (%u) RTP", num_buffers);
			while (idx < num_buffers) {
				GstBuffer *buff = gst_buffer_list_get (buffer_list, idx);
				GstPadProbeReturn result;

				result = filter_old_ssrc_rtp_buffer (buff, old_ssrc);
				if (result == GST_PAD_PROBE_DROP) {
					gst_buffer_list_remove (buffer_list, idx, 1);
					num_buffers = gst_buffer_list_length (buffer_list);
				} else {
					++idx;
				}
			}

		}
	}
	return GST_PAD_PROBE_OK;
}

static GstPadProbeReturn
filter_old_ssrc_rtcp (GstPad *pad, GstPadProbeInfo *info, gpointer user_data)
{
	//GList *old_ssrc = user_data;
	GstBuffer *buffer;

	buffer = GST_PAD_PROBE_INFO_BUFFER (info);

	GstRTCPBuffer rtcp_buffer = GST_RTCP_BUFFER_INIT;

	GST_ERROR ("filter old ssrc RTCP");

	if (TRUE)
		return GST_PAD_PROBE_OK;

    if (gst_rtcp_buffer_map (buffer, GST_MAP_READ, &rtcp_buffer)) {
    	//GstRTCPPacket packet;
		//gboolean has_packet;

		//has_packet = gst_rtcp_buffer_get_first_packet (&rtcp_buffer, &packet);

		GST_ERROR ("filter old ssrc RTCP buffer");
    	gst_rtcp_buffer_unmap (&rtcp_buffer);
		return  GST_PAD_PROBE_DROP;

//    	while (has_packet) {
//    		GstRTCPType  packet_type = gst_rtcp_packet_get_type (&packet);
//    		guint32 ssrc = 0;
//
//    		if (packet_type == GST_RTCP_TYPE_RR) {
//    			ssrc = gst_rtcp_packet_rr_get_ssrc (&packet);
//    		} else if (packet_type == GST_RTCP_TYPE_SDES) {
//    			ssrc = gst_rtcp_packet_sdes_get_ssrc (&packet);
//    		} else {
//    			GST_ERROR("txt");
//    		}
//			if ((ssrc != 0) && check_ssrc (ssrc, old_ssrc)) {
//				gst_rtcp_buffer_unmap (&rtcp_buffer);
//				return GST_PAD_PROBE_DROP;
//			}
//    		has_packet = gst_rtcp_packet_move_to_next (&packet);
//    	}
    	return GST_PAD_PROBE_OK;
	}

    return GST_PAD_PROBE_OK;
}


static void
setup_probe_filter_old_ssrc_rtp (GstPad *pad, GList *old_ssrc)
{
    gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER | GST_PAD_PROBE_TYPE_BUFFER_LIST | GST_PAD_PROBE_TYPE_PUSH | GST_PAD_PROBE_TYPE_PULL,
        (GstPadProbeCallback) filter_old_ssrc_rtp, old_ssrc, NULL);
    GST_ERROR("Installing RTP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
}

static void
setup_probe_filter_old_ssrc_rtcp (GstPad *pad, GList *old_ssrc)
{
    gst_pad_add_probe (pad, GST_PAD_PROBE_TYPE_BUFFER,
        (GstPadProbeCallback) filter_old_ssrc_rtcp, old_ssrc, NULL);
    GST_ERROR("Installing RTCP probe for %s", GST_ELEMENT_NAME(gst_pad_get_parent_element (pad)));
}

KmsRtpConnection *
kms_sip_rtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6, GSocket *rtp_sock, GSocket *rtcp_sock, GList *old_ssrc)
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

	  if (TRUE && (rtp_sock != NULL) && (rtcp_sock != NULL)) {
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



