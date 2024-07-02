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

#define DEFAULT_MAX_KBPS -1
#define DEFAULT_MAX_BUCKET_SIZE -1



#define GST_CAT_DEFAULT kmssipsrtpconnection
GST_DEBUG_CATEGORY_STATIC (GST_CAT_DEFAULT);

#define GST_DEFAULT_NAME "kmssipsrtpconnection"

#define KMS_SIP_SRTP_CONNECTION_GET_PRIVATE(obj) (   \
  G_TYPE_INSTANCE_GET_PRIVATE (                 \
    (obj),                                      \
    KMS_TYPE_SIP_SRTP_CONNECTION,                    \
    KmsSipSrtpConnectionPrivate                     \
  )                                             \
)

struct _KmsSipSrtpConnectionPrivate
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
kms_sip_srtp_connection_interface_init (KmsIRtpConnectionInterface * iface);

G_DEFINE_TYPE_WITH_CODE (KmsSipSrtpConnection, kms_sip_srtp_connection,
    KMS_TYPE_SRTP_CONNECTION,
    G_IMPLEMENT_INTERFACE (KMS_TYPE_I_RTP_CONNECTION,
        kms_sip_srtp_connection_interface_init));



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
		SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id, gint dscp_value)
{
	  // TODO: When this integrated in kms-elements we can modify kms_rtp_connection_new to allow espcifying
	  // the gstreamer object factory for the connection, so that we can simplify this function
	  GObject *obj;
	  KmsSrtpConnection *conn;
    KmsSipSrtpConnection *sip_conn;
	  GSocketFamily socket_family;

	  obj = g_object_new (KMS_TYPE_SIP_SRTP_CONNECTION, NULL);
	  conn = KMS_SRTP_CONNECTION (obj);
    sip_conn = KMS_SIP_SRTP_CONNECTION(conn);

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

	  sip_conn->traffic_shaper = gst_element_factory_make ("trafficshaper", NULL);
	  if (sip_conn->priv->max_kbps > 0){
		  g_object_set (G_OBJECT(sip_conn->traffic_shaper), "max-kbps", sip_conn->priv->max_kbps, NULL);
	  }
	  if (sip_conn->priv->max_bucket_size > 0){
		  g_object_set (G_OBJECT(sip_conn->traffic_shaper), "max-bucket-size", sip_conn->priv->max_bucket_size, NULL);
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

    if (dscp_value >= 0) {
      g_object_set (conn->rtp_udpsink, "qos-dscp", dscp_value, NULL);
      g_object_set (conn->rtcp_udpsink, "qos-dscp", dscp_value, NULL);
    }

	  kms_i_rtp_connection_connected_signal (KMS_I_RTP_CONNECTION (conn));

	  if ((rtp_sock != NULL) && (rtcp_sock != NULL)) {
		g_object_unref (rtcp_sock);
		g_object_unref (rtp_sock);
	  }

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


static void
kms_sip_srtp_connection_init (KmsSipSrtpConnection * self)
{
  self->priv = KMS_SIP_SRTP_CONNECTION_GET_PRIVATE (self);

  self->priv->max_bucket_size = -1;
  self->priv->max_kbps = -1;
}

static void
kms_sip_srtp_connection_finalize (GObject * object)
{
  KmsSipSrtpConnection *self = KMS_SIP_SRTP_CONNECTION (object);

  GST_DEBUG_OBJECT (self, "finalize");

  g_clear_object (&self->traffic_shaper);
  /* chain up */
  G_OBJECT_CLASS (kms_sip_srtp_connection_parent_class)->finalize (object);
}

static void
kms_sip_srtp_connection_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  KmsSipSrtpConnection *self = KMS_SIP_SRTP_CONNECTION (object);

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
kms_sip_srtp_connection_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  KmsSipSrtpConnection *self = KMS_SIP_SRTP_CONNECTION (object);

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
kms_sip_srtp_connection_class_init (KmsSipSrtpConnectionClass * klass)
{
  GObjectClass *gobject_class;

  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
      GST_DEFAULT_NAME);

  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize = kms_sip_srtp_connection_finalize;
  gobject_class->get_property = kms_sip_srtp_connection_get_property;
  gobject_class->set_property = kms_sip_srtp_connection_set_property;

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
 

  g_type_class_add_private (klass, sizeof (KmsSipSrtpConnectionPrivate));
}


static KmsIRtpConnectionInterface*
get_parent_iface (KmsSipSrtpConnection *object)
{
  KmsSrtpConnectionClass *klass = g_type_class_peek (kms_srtp_connection_get_type());

  return g_type_interface_peek (klass, kms_i_rtp_connection_get_type());
}

static void
kms_sip_srtp_connection_add (KmsIRtpConnection * base_rtp_conn, GstBin * bin, gboolean active)
{
  KmsSipSrtpConnection *self = KMS_SIP_SRTP_CONNECTION (base_rtp_conn);
  KmsSrtpConnection *rtp_conn = KMS_SRTP_CONNECTION(self);
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
kms_sip_srtp_connection_sink_sync_state_with_parent (KmsIRtpConnection *base_rtp_conn)
{
  KmsSipSrtpConnection *self = KMS_SIP_SRTP_CONNECTION (base_rtp_conn);
  static KmsIRtpConnectionInterface *iface = NULL;
  
  if (iface == NULL) {
	iface = get_parent_iface(self);
  }

  iface->sink_sync_state_with_parent (KMS_I_RTP_CONNECTION (self));
  gst_element_sync_state_with_parent (self->traffic_shaper);
}

static GstPad *
kms_sip_srtp_connection_request_rtp_sink (KmsIRtpConnection * base_rtp_conn)
{
  KmsSipSrtpConnection *self = KMS_SIP_SRTP_CONNECTION (base_rtp_conn);

  return gst_element_get_static_pad (self->traffic_shaper, "sink");
}




#define TYPE_IFACE   (iface_get_type())

static void
kms_sip_srtp_connection_interface_init (KmsIRtpConnectionInterface * iface)
{
  KmsIRtpConnectionInterface *old_iface;
  KmsSipSrtpConnectionClass *klass = g_type_class_peek (kms_sip_srtp_connection_get_type());

  if (klass != NULL) {
	old_iface = g_type_interface_peek (klass, kms_i_rtp_connection_get_type());

	iface->add = kms_sip_srtp_connection_add;
	iface->src_sync_state_with_parent = old_iface->src_sync_state_with_parent;
	iface->sink_sync_state_with_parent =
		kms_sip_srtp_connection_sink_sync_state_with_parent;
	iface->request_rtp_sink = kms_sip_srtp_connection_request_rtp_sink;
	iface->request_rtp_src = old_iface->request_rtp_src;
	iface->request_rtcp_sink = old_iface->request_rtp_sink;
	iface->request_rtcp_src = old_iface->request_rtcp_src;
	iface->set_latency_callback = old_iface->set_latency_callback;
	iface->collect_latency_stats = old_iface->collect_latency_stats;
  }
}
