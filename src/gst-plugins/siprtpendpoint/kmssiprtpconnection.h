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

#ifndef __KMS_SIP_RTP_CONNECTION_H__
#define __KMS_SIP_RTP_CONNECTION_H__

#include <kurento/rtpendpoint/kmsrtpconnection.h>
#include <gio/gio.h>
#include <gst/sdp/gstsdpmessage.h>
#include "kmsrtpfilterutils.h"

G_BEGIN_DECLS

KmsRtpConnection *
kms_sip_rtp_connection_new (guint16 min_port, guint16 max_port, gboolean use_ipv6, GSocket *rtp_sock, GSocket *rtcp_sock,
		SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id);

void
kms_sip_rtp_connection_add_probes (KmsRtpConnection *conn, SipFilterSsrcInfo* filter_info, gulong *rtp_probe_id, gulong *rtcp_probe_id);

void
kms_sip_rtp_connection_release_probes (KmsRtpConnection *conn, gulong rtp_probe_id, gulong rtcp_probe_id);

void kms_sip_rtp_connection_retrieve_sockets (KmsRtpConnection *conn, GSocket **rtp, GSocket **rtcp);

G_END_DECLS
#endif /* __KMS_SIP_RTP_CONNECTION_H__ */
