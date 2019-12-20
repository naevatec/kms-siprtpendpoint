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

#ifndef __KMS_SIP_RTP_SESSION_H__
#define __KMS_SIP_RTP_SESSION_H__

#include <gst/gst.h>
#include <kmsrtpsession.h>
#include "kmssiprtpconnection.h"

G_BEGIN_DECLS

typedef struct _KmsIRtpSessionManager KmsIRtpSessionManager;

/* #defines don't like whitespacey bits */
#define KMS_TYPE_SIP_RTP_SESSION \
  (kms_sip_rtp_session_get_type())
#define KMS_SIP_RTP_SESSION(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),KMS_TYPE_SIP_RTP_SESSION,KmsSipRtpSession))
#define KMS_SIP_RTP_SESSION_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),KMS_TYPE_SIP_RTP_SESSION,KmsSipRtpSessionClass))
#define KMS_IS_SIP_RTP_SESSION(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),KMS_TYPE_SIP_RTP_SESSION))
#define KMS_IS_SIP_RTP_SESSION_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),KMS_TYPE_SIP_RTP_SESSION))
#define KMS_SIP_RTP_SESSION_CAST(obj) ((KmsSipRtpSession*)(obj))

typedef struct _KmsSipRtpSession KmsSipRtpSession;
typedef struct _KmsSipRtpSessionClass KmsSipRtpSessionClass;
typedef struct _KmsSipRtpSessionPrivate KmsSipRtpSessionPrivate;

struct _KmsSipRtpSession
{
  KmsRtpSession parent;

  gboolean use_ipv6;

  GList *old_audio_ssrc;
  GList *old_video_ssrc;

  KmsSipRtpSessionPrivate *priv;
};

struct _KmsSipRtpSessionClass
{
  KmsRtpSessionClass parent_class;

  /* signals */
  void (*clone_connections) (KmsSipRtpSession *self, GHashTable *conns);

};

GType kms_sip_rtp_session_get_type (void);

KmsSipRtpSession * kms_sip_rtp_session_new (KmsBaseSdpEndpoint * ep, guint id, KmsIRtpSessionManager * manager, gboolean use_ipv6);

G_END_DECLS
#endif /* __KMS_SIP_RTP_SESSION_H__ */
