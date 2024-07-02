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
#include <kurento/rtpendpoint/kmssocketutils.h>
#include "kmsrtpfilterutils.h"
#include <commons/constants.h>
#include <gst/rtp/gstrtpbuffer.h>
#include <gst/rtp/gstrtcpbuffer.h>

#define GST_CAT_DEFAULT kmssiprtpconnection
GST_DEBUG_CATEGORY_STATIC (GST_CAT_DEFAULT);

#define GST_DEFAULT_NAME "kmssiprtpconnection"

#define KMS_SIP_RTP_CONNECTION_GET_PRIVATE(obj) (   \
  G_TYPE_INSTANCE_GET_PRIVATE (                 \
    (obj),                                      \
    KMS_TYPE_SIP_RTP_CONNECTION,                    \
    KmsSipRtpConnectionPrivate                     \
  )                                             \
)

#define DEFAULT_MAX_KBPS -1
#define DEFAULT_MAX_BUCKET_SIZE -1

struct _KmsSipRtpConnectionPrivate
{
  gint max_kbps;
  gint max_bucket_size;
};



enum
{
  PROP_0,
  PROP_MAX_KBPS,
  PROP_MAX_BUCKET_SIZE
};


static void
kms_sip_rtp_connection_interface_init (KmsIRtpConnectionInterface * iface);

G_DEFINE_TYPE_WITH_CODE (KmsSipRtpConnection, kms_sip_rtp_connection,
    KMS_TYPE_RTP_CONNECTION,
    G_IMPLEMENT_INTERFACE (KMS_TYPE_I_RTP_CONNECTION,
        kms_sip_rtp_connection_interface_init));


void
kms_sip_rtp_connection_retrieve_sockets (KmsRtpConnection *conn, GSocket **rtp, GSocket **rtcp)
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

//		g_object_set (conn->priv->rtp_udpsink, "socket", NULL);
//	    g_object_set (conn->priv->rtp_udpsrc, "socket", NULL);
//		g_object_set (conn->priv->rtcp_udpsink, "socket", NULL);
//		g_object_set (conn->priv->rtcp_udpsrc, "socket", NULL);

		conn->rtcp_socket = NULL;
		conn->rtp_socket = NULL;
	}
}


void
kms_sip_rtp_connection_add_probes (KmsRtpConnection *conn, SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id)
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


KmsRtpConnection *
kms_sip_rtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6, GSocket *rtp_sock, GSocket *rtcp_sock,
		SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id, gint dscp_value)
{
	  // TODO: When this integrated in kms-elements we can modify kms_rtp_connection_new to allow espcifying
	  // the gstreamer object factory for the connection, so that we can simplify this function
	  GObject *obj;
	  KmsSipRtpConnection *conn;
	  KmsRtpConnection *rtp_conn;
	  GSocketFamily socket_family;

	  obj = g_object_new (KMS_TYPE_SIP_RTP_CONNECTION, NULL);
	  conn = KMS_SIP_RTP_CONNECTION (obj);
	  rtp_conn = KMS_RTP_CONNECTION(conn);

	  if (use_ipv6) {
	    socket_family = G_SOCKET_FAMILY_IPV6;
	  } else {
	    socket_family = G_SOCKET_FAMILY_IPV4;
	  }

	  // TODO: This is what we need to update on kms_rtp_connection-new
	  if ((rtp_sock != NULL) && (rtcp_sock != NULL)) {
		  rtp_conn->rtp_socket = rtp_sock;
		  rtp_conn->rtcp_socket = rtcp_sock;
	  } else {
		  //   ^^^^^^^^^^^^^^^^^^^^^^^^^
		  // TODO: Up to here
		  if (!kms_rtp_connection_get_rtp_rtcp_sockets
		      (&rtp_conn->rtp_socket, &rtp_conn->rtcp_socket, min_port, max_port,
		          socket_family)) {
		    GST_ERROR_OBJECT (obj, "Cannot get ports");
		    g_object_unref (obj);
		    return NULL;
		  }
	  }
	  
	  conn->traffic_shaper = gst_element_factory_make ("trafficshaper", NULL);
	  if (conn->priv->max_kbps > 0){
		g_object_set (G_OBJECT(conn->traffic_shaper), "max-kbps", conn->priv->max_kbps, NULL);
	  }
	  if (conn->priv->max_bucket_size > 0){
		g_object_set (G_OBJECT(conn->traffic_shaper), "max-bucket-size", conn->priv->max_bucket_size, NULL);
	  }

	  rtp_conn->rtp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  rtp_conn->rtp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  rtp_conn->rtcp_udpsink = gst_element_factory_make ("multiudpsink", NULL);
	  rtp_conn->rtcp_udpsrc = gst_element_factory_make ("udpsrc", NULL);

	  kms_sip_rtp_connection_add_probes (rtp_conn, filter_info, rtp_probe_id, rtcp_probe_id);

	  g_object_set (rtp_conn->rtp_udpsink, "socket", rtp_conn->rtp_socket,
	      "sync", FALSE, "async", FALSE, NULL);
	  g_object_set (rtp_conn->rtp_udpsrc, "socket", rtp_conn->rtp_socket, "auto-multicast",
	      FALSE, NULL);

	  g_object_set (rtp_conn->rtcp_udpsink, "socket", rtp_conn->rtcp_socket,
	      "sync", FALSE, "async", FALSE, NULL);
	  g_object_set (rtp_conn->rtcp_udpsrc, "socket", rtp_conn->rtcp_socket,
	      "auto-multicast", FALSE, NULL);

	  // Set dscp values to multiudpsink, see https://linuxreviews.org/Type_of_Service_(ToS)_and_DSCP_Values
	  if (dscp_value >= 0) {
		  g_object_set (rtp_conn->rtp_udpsink, "qos-dscp",  dscp_value, NULL);
		  g_object_set (rtp_conn->rtcp_udpsink, "qos-dscp",  dscp_value, NULL);		  
	  }

	  kms_i_rtp_connection_connected_signal (KMS_I_RTP_CONNECTION (rtp_conn));

	  if ((rtp_sock != NULL) && (rtcp_sock != NULL)) {
		g_object_unref (rtcp_sock);
		g_object_unref (rtp_sock);
	  }

	  return KMS_RTP_CONNECTION(conn);
}

void
kms_sip_rtp_connection_release_probes (KmsRtpConnection *conn, gulong rtp_probe_id, gulong rtcp_probe_id)
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


static void
kms_sip_rtp_connection_init (KmsSipRtpConnection * self)
{
  self->priv = KMS_SIP_RTP_CONNECTION_GET_PRIVATE (self);

  self->priv->max_bucket_size = -1;
  self->priv->max_kbps = -1;
}

static void
kms_sip_rtp_connection_finalize (GObject * object)
{
  KmsSipRtpConnection *self = KMS_SIP_RTP_CONNECTION (object);

  GST_DEBUG_OBJECT (self, "finalize");

  g_clear_object (&self->traffic_shaper);
  /* chain up */
  G_OBJECT_CLASS (kms_sip_rtp_connection_parent_class)->finalize (object);
}

static void
kms_sip_rtp_connection_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  KmsSipRtpConnection *self = KMS_SIP_RTP_CONNECTION (object);

  switch (prop_id) {
    case PROP_MAX_KBPS:
      self->priv->max_kbps = g_value_get_int (value);
      if (self->traffic_shaper != NULL) {
        g_object_set (G_OBJECT(self->traffic_shaper), "max-kbps", self->priv->max_kbps, NULL);
      }
      break;
    case PROP_MAX_BUCKET_SIZE:
      self->priv->max_bucket_size = g_value_get_int (value);
      if (self->traffic_shaper != NULL) {
        g_object_set (G_OBJECT(self->traffic_shaper), "max-bucket-size", self->priv->max_bucket_size, NULL);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
kms_sip_rtp_connection_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  KmsSipRtpConnection *self = KMS_SIP_RTP_CONNECTION (object);

  switch (prop_id) {
    case PROP_MAX_KBPS:
      g_value_set_int (value, self->priv->max_kbps);
      break;
    case PROP_MAX_BUCKET_SIZE:
      g_value_set_int (value, self->priv->max_bucket_size);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
kms_sip_rtp_connection_class_init (KmsSipRtpConnectionClass * klass)
{
  GObjectClass *gobject_class;

  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
      GST_DEFAULT_NAME);

  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize = kms_sip_rtp_connection_finalize;
  gobject_class->get_property = kms_sip_rtp_connection_get_property;
  gobject_class->set_property = kms_sip_rtp_connection_set_property;

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
 

  g_type_class_add_private (klass, sizeof (KmsSipRtpConnectionPrivate));
}


static KmsIRtpConnectionInterface*
get_parent_iface (KmsSipRtpConnection *object)
{
  KmsRtpConnectionClass *klass = g_type_class_peek (kms_rtp_connection_get_type());

  return g_type_interface_peek (klass, kms_i_rtp_connection_get_type());
}

static void
kms_sip_rtp_connection_add (KmsIRtpConnection * base_rtp_conn, GstBin * bin, gboolean active)
{
  KmsSipRtpConnection *self = KMS_SIP_RTP_CONNECTION (base_rtp_conn);
  KmsRtpConnection *rtp_conn = KMS_RTP_CONNECTION(self);
  static KmsIRtpConnectionInterface *iface = NULL;
  
  if (iface == NULL) {
	iface = get_parent_iface(self);
  }

  iface->sink_sync_state_with_parent (KMS_I_RTP_CONNECTION (self));
  gst_bin_add_many (bin, 
  	g_object_ref (self->traffic_shaper), NULL);
  gst_element_link (self->traffic_shaper, rtp_conn->rtp_udpsink);
}

static void
kms_sip_rtp_connection_sink_sync_state_with_parent (KmsIRtpConnection *base_rtp_conn)
{
  KmsSipRtpConnection *self = KMS_SIP_RTP_CONNECTION (base_rtp_conn);
  static KmsIRtpConnectionInterface *iface = NULL;
  
  if (iface == NULL) {
	iface = get_parent_iface(self);
  }

  iface->sink_sync_state_with_parent (KMS_I_RTP_CONNECTION (self));
  gst_element_sync_state_with_parent (self->traffic_shaper);
}

static GstPad *
kms_sip_rtp_connection_request_rtp_sink (KmsIRtpConnection * base_rtp_conn)
{
  KmsSipRtpConnection *self = KMS_SIP_RTP_CONNECTION (base_rtp_conn);

  return gst_element_get_static_pad (self->traffic_shaper, "sink");
}




#define TYPE_IFACE   (iface_get_type())

static void
kms_sip_rtp_connection_interface_init (KmsIRtpConnectionInterface * iface)
{
  KmsIRtpConnectionInterface *old_iface;
  KmsSipRtpConnectionClass *klass = g_type_class_peek (kms_sip_rtp_connection_get_type());

  if (klass != NULL) {
	old_iface = g_type_interface_peek (klass, kms_i_rtp_connection_get_type());

	iface->add = kms_sip_rtp_connection_add;
	iface->src_sync_state_with_parent = old_iface->src_sync_state_with_parent;
	iface->sink_sync_state_with_parent =
		kms_sip_rtp_connection_sink_sync_state_with_parent;
	iface->request_rtp_sink = kms_sip_rtp_connection_request_rtp_sink;
	iface->request_rtp_src = old_iface->request_rtp_src;
	iface->request_rtcp_sink = old_iface->request_rtp_sink;
	iface->request_rtcp_src = old_iface->request_rtcp_src;
	iface->set_latency_callback = old_iface->set_latency_callback;
	iface->collect_latency_stats = old_iface->collect_latency_stats;
  }
}

