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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "kmssipsrtpsession.h"
#include <commons/kmsbasertpsession.h>
#include <commons/constants.h>
#include <gio/gio.h>

#define GST_DEFAULT_NAME "kmssipsrtpsession"
#define GST_CAT_DEFAULT kms_sip_srtp_session_debug
GST_DEBUG_CATEGORY_STATIC (GST_CAT_DEFAULT);

#define kms_sip_srtp_session_parent_class parent_class

G_DEFINE_TYPE (KmsSipSrtpSession, kms_sip_srtp_session, KMS_TYPE_SRTP_SESSION);

#define KMS_SIP_SRTP_SESSION_GET_PRIVATE(obj) (  \
  G_TYPE_INSTANCE_GET_PRIVATE (                   \
    (obj),                                        \
    KMS_TYPE_SIP_SRTP_SESSION,                   \
    KmsSipSrtpSessionPrivate                     \
  )                                               \
)


struct _KmsSipSrtpSessionPrivate
{
	GHashTable *conns;
};



KmsSipSrtpSession *
kms_sip_srtp_session_new (KmsBaseSdpEndpoint * ep, guint id,
    KmsIRtpSessionManager * manager, gboolean use_ipv6)
{
  GObject *obj;
  KmsSipSrtpSession *self;

  obj = g_object_new (KMS_TYPE_SIP_SRTP_SESSION, NULL);
  self = KMS_SIP_SRTP_SESSION (obj);
  KMS_SRTP_SESSION_CLASS (G_OBJECT_GET_CLASS (self))->post_constructor
      (KMS_SRTP_SESSION(self), ep, id, manager, use_ipv6);

  return self;
}

/* Connection management begin */


static KmsIRtpConnection *
kms_sip_srtp_session_create_connection (KmsBaseRtpSession * base_rtp_sess,
    const GstSDPMedia * media, const gchar * name, guint16 min_port,
    guint16 max_port)
{
  KmsSipSrtpSession *self = KMS_SIP_SRTP_SESSION(base_rtp_sess);

  // TODO: Here is where we need to interacto to clone connecitons from a previous session
  // 	kms_rtp_connection_new creates a KmsRtpConnection, and creates its multiudpsink and udpsrc
  //    and creates the sockets for RTP and RTCP iterating to fid free ports
  //  We need to define a kms_sip_rtp_connection_new that if no previous session to clone should
  //  behave exactly as kms_rtp_connection_new and if not should create the connection recovering the
  //  sockets from the previous session (the equivalent connection). correlation should be done using ssrc and media type
  GSocket *rtp_sock = NULL;
  GSocket *rtcp_sock = NULL;
  GList *old_ssrc = NULL;

  if (self->priv->conns != NULL) {
	  kms_sip_srtp_connection_retrieve_sockets (self->priv->conns, media, &rtp_sock, &rtcp_sock);

	  const gchar *media_str = gst_sdp_media_get_media (media);

	  if (g_strcmp0 (VIDEO_STREAM_NAME, media_str) == 0) {
	      old_ssrc = self->old_video_ssrc;
	  }else if (g_strcmp0 (AUDIO_STREAM_NAME, media_str) == 0) {
	      old_ssrc = self->old_audio_ssrc;
	  }
  }
  KmsSrtpConnection *conn = kms_sip_srtp_connection_new (min_port, max_port,
      KMS_SRTP_SESSION (base_rtp_sess)->use_ipv6, rtp_sock, rtcp_sock, old_ssrc);

  return KMS_I_RTP_CONNECTION (conn);
}

static void
kms_sip_srtp_session_clone_connections (KmsSipSrtpSession *self, GHashTable *conns)
{
	self->priv->conns = g_hash_table_ref (conns);
}

/* Connection management end */

static void
kms_sip_srtp_session_post_constructor (KmsSrtpSession * self,
    KmsBaseSdpEndpoint * ep, guint id, KmsIRtpSessionManager * manager,
    gboolean use_ipv6)
{
  KmsBaseRtpSession *base_rtp_session = KMS_BASE_RTP_SESSION (self);

  self->use_ipv6 = use_ipv6;
  KMS_BASE_RTP_SESSION_CLASS (parent_class)->post_constructor (base_rtp_session,
      ep, id, manager);
}

static void
kms_sip_srtp_session_init (KmsSipSrtpSession * self)
{
	  self->priv = KMS_SIP_SRTP_SESSION_GET_PRIVATE (self);

	  self->priv->conns = NULL;
}

static void
kms_sip_srtp_session_finalize (GObject *object)
{
  KmsSipSrtpSession *self = KMS_SIP_SRTP_SESSION(object);

  if (self->priv->conns != NULL) {
	  g_hash_table_unref (self->priv->conns);
  }

  g_list_free (self->old_audio_ssrc);
  g_list_free (self->old_video_ssrc);
}


static void
kms_sip_srtp_session_class_init (KmsSipSrtpSessionClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class = GST_ELEMENT_CLASS (klass);
  KmsBaseRtpSessionClass *base_rtp_session_class;
  KmsSrtpSessionClass *srtp_session_class;

  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
      GST_DEFAULT_NAME);

  gobject_class = G_OBJECT_CLASS(klass);
  gobject_class->finalize = kms_sip_srtp_session_finalize;

  srtp_session_class = KMS_SRTP_SESSION_CLASS (klass);

  srtp_session_class->post_constructor = kms_sip_srtp_session_post_constructor;

  base_rtp_session_class = KMS_BASE_RTP_SESSION_CLASS (klass);
  /* Connection management */
  base_rtp_session_class->create_connection =
      kms_sip_srtp_session_create_connection;

  klass->clone_connections = kms_sip_srtp_session_clone_connections;

  gst_element_class_set_details_simple (gstelement_class,
      "SipSrtpSession",
      "Generic",
      "Base bin to manage elements related with a SIP SRTP session.",
      "Saul Pablo Labajo Izquierdo <slabajo@naevatec.com>");

  g_type_class_add_private (klass, sizeof (KmsSipSrtpSessionPrivate));

}
