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

#ifndef __KMS_SIP_SRTP_CONNECTION_H__
#define __KMS_SIP_SRTP_CONNECTION_H__

#include <kurento/rtpendpoint/kmssrtpconnection.h>
#include "kmsrtpfilterutils.h"
#include <gio/gio.h>
#include <gst/sdp/gstsdpmessage.h>

G_BEGIN_DECLS


#define KMS_TYPE_SIP_SRTP_CONNECTION \
  (kms_sip_srtp_connection_get_type())
#define KMS_SIP_SRTP_CONNECTION(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),KMS_TYPE_SIP_SRTP_CONNECTION,KmsSipSrtpConnection))
#define KMS_SIP_SRTP_CONNECTION_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),KMS_TYPE_SIP_SRTP_CONNECTION,KmsRtpConnectionClass))
#define KMS_IS_SIP_SRTP_CONNECTION(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),KMS_TYPE_SIP_SRTP_CONNECTION))
#define KMS_IS_SIP_SRTP_CONNECTION_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),KMS_TYPE_SIP_SRTP_CONNECTION))
#define KMS_SIP_SRTP_CONNECTION_CAST(obj) ((KmsSipSrtpConnection*)(obj))
typedef struct _KmsSipSrtpConnectionPrivate KmsSipSrtpConnectionPrivate;
typedef struct _KmsSipSrtpConnection KmsSipSrtpConnection;
typedef struct _KmsSipSrtpConnectionClass KmsSipSrtpConnectionClass;

struct _KmsSipSrtpConnection
{
  KmsSrtpConnection parent;

  GstElement *traffic_shaper;

  KmsSipSrtpConnectionPrivate *priv;
};

struct _KmsSipSrtpConnectionClass
{
  KmsSrtpConnectionClass parent_class;
};

GType kms_sip_srtp_connection_get_type (void);


KmsSrtpConnection *
kms_sip_srtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6,
		GSocket *rtp_sock, GSocket *rtcp_sock,
		SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id,  gulong *rtp_sink_signal_id, gulong *rtcp_sink_signal_id, gint dscp_value);

void
kms_sip_srtp_connection_add_probes (KmsSrtpConnection *conn, SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id, gulong *rtp_sink_signal_id, gulong *rtcp_sink_signal_id);

void
kms_sip_srtp_connection_release_probes (KmsSrtpConnection *conn, gulong rtp_probe_id, gulong rtcp_probe_id, gulong rtp_sink_signal_id, gulong rtcp_sink_signal_id);

void kms_sip_srtp_connection_retrieve_sockets (KmsSrtpConnection *conn, GSocket **rtp, GSocket **rtcp);

void kms_sip_srtp_connection_set_key (KmsSrtpConnection *conn, const gchar *key, guint auth, guint cipher, gboolean local);

G_END_DECLS
#endif /* __KMS_SIP_SRTP_CONNECTION_H__ */
