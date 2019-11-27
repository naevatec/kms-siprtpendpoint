/*
 * (C) Copyright 2013 Kurento (http://kurento.org/)
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

#include <string.h>
#include <nice/interfaces.h>
#include "kmssiprtpendpoint.h"
#include "kmssiprtpsession.h"
#include "kmssipsrtpsession.h"
#include <commons/kmsbasesdpendpoint.h>
//#include <kmsrtpbaseconnection.h>
#include <commons/constants.h>
//#include <commons/kmsbasertpendpoint.h>
//#include <commons/sdp_utils.h>
//#include <commons/sdpagent/kmssdprtpsavpfmediahandler.h>
//#include <commons/sdpagent/kmssdprtpavpfmediahandler.h>
//#include <commons/sdpagent/kmssdpsdesext.h>
//#include <commons/kmsrefstruct.h>
//#include "kms-rtp-enumtypes.h"
//#include "kmsrtpsdescryptosuite.h"
//#include "kmsrandom.h"

#define PLUGIN_NAME "siprtpendpoint"

GST_DEBUG_CATEGORY_STATIC (kms_sip_rtp_endpoint_debug);
#define GST_CAT_DEFAULT kms_sip_rtp_endpoint_debug

#define kms_sip_rtp_endpoint_parent_class parent_class
G_DEFINE_TYPE (KmsSipRtpEndpoint, kms_sip_rtp_endpoint, KMS_TYPE_RTP_ENDPOINT);

//#define DEFAULT_USE_SDES FALSE
//#define DEFAULT_MASTER_KEY NULL
//#define DEFAULT_CRYPTO_SUITE KMS_RTP_SDES_CRYPTO_SUITE_NONE
//#define DEFAULT_KEY_TAG 1
//
//#define KMS_SIP_SRTP_AUTH_HMAC_SHA1_32 1
//#define KMS_SIP_SRTP_AUTH_HMAC_SHA1_80 2
//#define KMS_SIP_SRTP_CIPHER_AES_CM_128 1
//#define KMS_SIP_SRTP_CIPHER_AES_CM_256 2
//#define KMS_SIP_SRTP_CIPHER_AES_CM_128_SIZE ((gsize)30)
//#define KMS_SIP_SRTP_CIPHER_AES_CM_256_SIZE ((gsize)46)

#define KMS_SIP_RTP_ENDPOINT_GET_PRIVATE(obj) (  \
  G_TYPE_INSTANCE_GET_PRIVATE (              \
    (obj),                                   \
    KMS_TYPE_SIP_RTP_ENDPOINT,                   \
    KmsSipRtpEndpointPrivate                    \
  )                                          \
)

//typedef struct _SdesExtData
//{
//  KmsRefStruct ref;
//  gchar *media;
//  KmsSipRtpEndpoint *rtpep;
//} SdesExtData;
//
//typedef struct _SdesKeys
//{
//  KmsRefStruct ref;
//  GValue local;
//  GValue remote;
//  KmsRtpBaseConnection *conn;
//  KmsISdpMediaExtension *ext;
//} SdesKeys;
//
//typedef struct _KmsComedia KmsComedia;
//struct _KmsComedia
//{
//  GHashTable *rtp_conns; // GHashTable<RTPSession*, KmsIRtpConnection*>
//  GHashTable *signal_ids; // GHashTable<RTPSession*, int>
//};

typedef struct _KmsSipRtpEndpointCloneData KmsSipRtpEndpointCloneData;


struct _KmsSipRtpEndpointCloneData
{
	guint32 audio_ssrc;
	guint32 video_ssrc;

};

struct _KmsSipRtpEndpointPrivate
{
  gboolean *use_sdes_cache;

  GList *sessionData;

//  gboolean use_sdes;
//  GHashTable *sdes_keys;
//
//  gchar *master_key;  // SRTP Master Key, base64 encoded
//  KmsRtpSDESCryptoSuite crypto;
//
//  /* COMEDIA (passive port discovery) */
//  KmsComedia comedia;
};

/* Signals and args */
enum
{
  /* signals */
  SIGNAL_CLONE_TO_NEW_EP,

  LAST_SIGNAL
};

static guint obj_signals[LAST_SIGNAL] = { 0 };
//
//enum
//{
//  PROP_0,
//  PROP_USE_SDES,
//  PROP_MASTER_KEY,
//  PROP_CRYPTO_SUITE
//};

static KmsBaseSdpEndpointClass *base_sdp_endpoint_type;


/*----------- Session cloning ---------------*/

static void
kms_sip_rtp_endpoint_clone_rtp_session (GstElement * rtpbin, guint sessionId, guint32 ssrc, gchar *rtpbin_pad_name)
{
	GObject *rtpSession;
    GstPad *pad;

	/* Create RtpSession requesting the pad */
	pad = gst_element_get_request_pad (rtpbin, rtpbin_pad_name);
	g_object_unref (pad);

	g_signal_emit_by_name (rtpbin, "get-internal-session", sessionId, &rtpSession);
	if (rtpSession != NULL) {
		g_object_set (rtpSession, "internal-ssrc", ssrc, NULL);
	}

	g_object_unref(rtpSession);

}
static GstElement*
kms_sip_rtp_endpoint_get_rtpbin (KmsSipRtpEndpoint * self)
{
	GstElement *result = NULL;
	GList* rtpEndpointChildren = GST_BIN_CHILDREN(GST_BIN(self));

	while (rtpEndpointChildren != NULL) {
		gchar* objectName = gst_element_get_name  (GST_ELEMENT(rtpEndpointChildren->data));

		if (g_str_has_prefix (objectName, "rtpbin")) {
			result = GST_ELEMENT(rtpEndpointChildren->data);
			g_free (objectName);
			break;
		}
		g_free (objectName);
		rtpEndpointChildren = rtpEndpointChildren->next;
	}
	return result;
}

static void
kms_sip_rtp_endpoint_clone_session (KmsSipRtpEndpoint * self, KmsSdpSession ** sess)
{
	GstElement *rtpbin = kms_sip_rtp_endpoint_get_rtpbin (self);
	GList *sessionToClone = self->priv->sessionData;

	if (rtpbin != NULL) {

		// TODO: Multisession seems not used on RTPEndpoint, anyway we are doing something probably incorrect
		// once multisession is used, that is to assume that creation order of sessions are maintained among all
		// endpoints, and so order can be used to correlate internal rtp sessions.
		KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION (sess);
		guint32 ssrc;

		/* TODO: think about this when multiple audio/video medias */
		// Audio
		ssrc = ((KmsSipRtpEndpointCloneData*)sessionToClone->data)->audio_ssrc;
		ses->local_audio_ssrc = ssrc;
		kms_sip_rtp_endpoint_clone_rtp_session (rtpbin, AUDIO_RTP_SESSION, ssrc, AUDIO_RTPBIN_SEND_RTP_SINK);

		// Video
		ssrc = ((KmsSipRtpEndpointCloneData*)sessionToClone->data)->video_ssrc;
		ses->local_video_ssrc = ssrc;
		kms_sip_rtp_endpoint_clone_rtp_session (rtpbin, VIDEO_RTP_SESSION, ssrc, VIDEO_RTPBIN_SEND_RTP_SINK);
	}
}


//static void
//sdes_ext_data_destroy (SdesExtData * edata)
//{
//  g_free (edata->media);
//
//  g_slice_free (SdesExtData, edata);
//}
//
//static SdesExtData *
//sdes_ext_data_new (KmsSipRtpEndpoint * ep, const gchar * media)
//{
//  SdesExtData *edata;
//
//  edata = g_slice_new0 (SdesExtData);
//  kms_ref_struct_init (KMS_REF_STRUCT_CAST (edata),
//      (GDestroyNotify) sdes_ext_data_destroy);
//
//  edata->media = g_strdup (media);
//  edata->rtpep = ep;
//
//  return edata;
//}
//
//static void
//sdes_keys_destroy (SdesKeys * keys)
//{
//  if (G_IS_VALUE (&keys->local)) {
//    g_value_unset (&keys->local);
//  }
//
//  if (G_IS_VALUE (&keys->remote)) {
//    g_value_unset (&keys->remote);
//  }
//
//  g_clear_object (&keys->conn);
//  g_clear_object (&keys->ext);
//
//  g_slice_free (SdesKeys, keys);
//}
//
//static SdesKeys *
//sdes_keys_new (KmsISdpMediaExtension * ext)
//{
//  SdesKeys *keys;
//
//  keys = g_slice_new0 (SdesKeys);
//  kms_ref_struct_init (KMS_REF_STRUCT_CAST (keys),
//      (GDestroyNotify) sdes_keys_destroy);
//
//  keys->ext = g_object_ref (ext);
//
//  return keys;
//}
//
//static gboolean
//get_auth_cipher_from_crypto (SrtpCryptoSuite crypto, guint * auth,
//    guint * cipher)
//{
//  switch (crypto) {
//    case KMS_SDES_EXT_AES_CM_128_HMAC_SHA1_32:
//      *auth = KMS_SIP_SRTP_AUTH_HMAC_SHA1_32;
//      *cipher = KMS_SIP_SRTP_CIPHER_AES_CM_128;
//      return TRUE;
//    case KMS_SDES_EXT_AES_CM_128_HMAC_SHA1_80:
//      *auth = KMS_SIP_SRTP_AUTH_HMAC_SHA1_80;
//      *cipher = KMS_SIP_SRTP_CIPHER_AES_CM_128;
//      return TRUE;
//    case KMS_SDES_EXT_AES_256_CM_HMAC_SHA1_32:
//      *auth = KMS_SIP_SRTP_AUTH_HMAC_SHA1_32;
//      *cipher = KMS_SIP_SRTP_CIPHER_AES_CM_256;
//      return TRUE;
//    case KMS_SDES_EXT_AES_256_CM_HMAC_SHA1_80:
//      *auth = KMS_SIP_SRTP_AUTH_HMAC_SHA1_80;
//      *cipher = KMS_SIP_SRTP_CIPHER_AES_CM_256;
//      return TRUE;
//    default:
//      *auth = *cipher = 0;
//      return FALSE;
//  }
//}
//
//static gboolean
//kms_sip_rtp_endpoint_set_local_srtp_connection_key (KmsSipRtpEndpoint * self,
//    const gchar * media, SdesKeys * sdes_keys)
//{
//  SrtpCryptoSuite crypto;
//  guint auth, cipher;
//  gchar *key;
//
//  if (!G_IS_VALUE (&sdes_keys->local)) {
//
//    return FALSE;
//  }
//
//  if (!kms_sdp_sdes_ext_get_parameters_from_key (&sdes_keys->local,
//          KMS_SDES_KEY_FIELD, G_TYPE_STRING, &key, KMS_SDES_CRYPTO, G_TYPE_UINT,
//          &crypto, NULL)) {
//
//    return FALSE;
//  }
//
//  if (!get_auth_cipher_from_crypto (crypto, &auth, &cipher)) {
//    g_free (key);
//
//    return FALSE;
//  }
//
//  kms_sip_srtp_connection_set_key (KMS_SIP_SRTP_CONNECTION (sdes_keys->conn),
//      key, auth, cipher, TRUE);
//  g_free (key);
//
//  return TRUE;
//}
//
//static void
//kms_sip_rtp_endpoint_set_remote_srtp_connection_key (KmsSipRtpEndpoint * self,
//    const gchar * media, SdesKeys * sdes_keys)
//{
//  SrtpCryptoSuite my_crypto, rem_crypto;
//  guint my_tag, rem_tag;
//  gchar *rem_key = NULL;
//  gboolean done = FALSE;
//  guint auth, cipher;
//
//  if (!G_IS_VALUE (&sdes_keys->local) || !G_IS_VALUE (&sdes_keys->remote)) {
//    GST_DEBUG_OBJECT (self, "Keys are not yet negotiated");
//    return;
//  }
//
//  if (!kms_sdp_sdes_ext_get_parameters_from_key (&sdes_keys->local,
//          KMS_SDES_TAG_FIELD, G_TYPE_UINT, &my_tag, KMS_SDES_CRYPTO,
//          G_TYPE_UINT, &my_crypto, NULL)) {
//    goto end;
//  }
//
//  if (!kms_sdp_sdes_ext_get_parameters_from_key (&sdes_keys->remote,
//          KMS_SDES_TAG_FIELD, G_TYPE_UINT, &rem_tag, KMS_SDES_CRYPTO,
//          G_TYPE_UINT, &rem_crypto, KMS_SDES_KEY_FIELD, G_TYPE_STRING, &rem_key,
//          NULL)) {
//    goto end;
//  }
//
//  if (my_tag != rem_tag || my_crypto != rem_crypto) {
//    goto end;
//  }
//
//  if (!get_auth_cipher_from_crypto (rem_crypto, &auth, &cipher)) {
//    goto end;
//  }
//
//  kms_sip_srtp_connection_set_key (KMS_SIP_SRTP_CONNECTION (sdes_keys->conn), rem_key,
//      auth, cipher, FALSE);
//
//  done = TRUE;
//
//end:
//  if (!done) {
//    GST_ERROR_OBJECT (self, "Can not configure remote connection key");
//  }
//
//  g_free (rem_key);
//}
//
//static void
//conn_soft_limit_cb (KmsSipSrtpConnection * conn, gpointer user_data)
//{
//  SdesExtData *data = (SdesExtData *) user_data;
//  KmsSipRtpEndpoint *self = data->rtpep;
//
//  g_signal_emit (self, obj_signals[SIGNAL_KEY_SOFT_LIMIT], 0, data->media);
//}

static gboolean isUseSdes (KmsSipRtpEndpoint * self)
{
	if (self->priv->use_sdes_cache == NULL) {
		gboolean useSdes;

		g_object_get (G_OBJECT(self), "use-sdes", &useSdes, NULL);
		self->priv->use_sdes_cache = g_malloc(sizeof(gboolean));
		*self->priv->use_sdes_cache = useSdes;
	}
	return *self->priv->use_sdes_cache;
}

//static KmsRtpBaseConnection *
//kms_sip_rtp_endpoint_get_connection (KmsSipRtpEndpoint * self, KmsSdpSession * sess,
//    KmsSdpMediaHandler * handler, const GstSDPMedia * media)
//{
//  if (isUseSdes(self)) {
//    KmsRtpBaseConnection *conn;
//    SdesExtData *data;
//
//    conn = kms_sip_srtp_session_get_connection (KMS_SIP_SRTP_SESSION (sess), handler);
//
//    data = sdes_ext_data_new (self, gst_sdp_media_get_media (media));
//
//    g_signal_connect_data (conn, "key-soft-limit",
//        G_CALLBACK (conn_soft_limit_cb), data,
//        (GClosureNotify) kms_ref_struct_unref, 0);
//    return conn;
//  } else {
//    return kms_sip_rtp_session_get_connection (KMS_SIP_RTP_SESSION (sess), handler);
//  }
//}
//
/* Internal session management begin */

static void
kms_sip_rtp_endpoint_set_addr (KmsSipRtpEndpoint * self)
{
  GList *ips, *l;
  gboolean done = FALSE;

  ips = nice_interfaces_get_local_ips (FALSE);
  for (l = ips; l != NULL && !done; l = l->next) {
    GInetAddress *addr;
    gboolean is_ipv6 = FALSE;

    GST_DEBUG_OBJECT (self, "Check local address: %s", (const gchar*)l->data);
    addr = g_inet_address_new_from_string (l->data);

    if (G_IS_INET_ADDRESS (addr)) {
      switch (g_inet_address_get_family (addr)) {
        case G_SOCKET_FAMILY_INVALID:
        case G_SOCKET_FAMILY_UNIX:
          /* Ignore this addresses */
          break;
        case G_SOCKET_FAMILY_IPV6:
          is_ipv6 = TRUE;
        case G_SOCKET_FAMILY_IPV4:
        {
          gchar *addr_str;
          gboolean use_ipv6;

          g_object_get (self, "use-ipv6", &use_ipv6, NULL);
          if (is_ipv6 != use_ipv6) {
            GST_DEBUG_OBJECT (self, "Skip address (wanted IPv6: %d)", use_ipv6);
            break;
          }

          addr_str = g_inet_address_to_string (addr);
          if (addr_str != NULL) {
            g_object_set (self, "addr", addr_str, NULL);
            g_free (addr_str);
            done = TRUE;
          }
          break;
        }
      }
    }

    if (G_IS_OBJECT (addr)) {
      g_object_unref (addr);
    }
  }

  g_list_free_full (ips, g_free);

  if (!done) {
    GST_WARNING_OBJECT (self, "Addr not set");
  }
}

static void
kms_sip_rtp_endpoint_create_session_internal (KmsBaseSdpEndpoint * base_sdp,
    gint id, KmsSdpSession ** sess)
{
  KmsIRtpSessionManager *manager = KMS_I_RTP_SESSION_MANAGER (base_sdp);
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (base_sdp);
  gboolean use_ipv6 = FALSE;

  /* Get ip address now that session is bein created */
  kms_sip_rtp_endpoint_set_addr (self);

  g_object_get (self, "use-ipv6", &use_ipv6, NULL);
  if (isUseSdes(self)) {
    *sess =
        KMS_SDP_SESSION (kms_sip_srtp_session_new (base_sdp, id, manager,
            use_ipv6));
  } else {
    *sess =
        KMS_SDP_SESSION (kms_sip_rtp_session_new (base_sdp, id, manager, use_ipv6));
  }

  /* Chain up */
  base_sdp_endpoint_type->create_session_internal (base_sdp, id, sess);
//  KMS_BASE_SDP_ENDPOINT_CLASS(
//  (KMS_RTP_ENDPOINT_CLASS
//      (kms_sip_rtp_endpoint_parent_class)->parent_class)->
//	  ->create_session_internal (base_sdp, id, sess);

  if (self->priv->sessionData != NULL) {
	  kms_sip_rtp_endpoint_clone_session (self, sess);
  }

}

/* Internal session management end */

///* Media handler management begin */
//
//static guint
//get_max_key_size (SrtpCryptoSuite crypto)
//{
//  switch (crypto) {
//    case KMS_SDES_EXT_AES_CM_128_HMAC_SHA1_32:
//    case KMS_SDES_EXT_AES_CM_128_HMAC_SHA1_80:
//      return KMS_SIP_SRTP_CIPHER_AES_CM_128_SIZE;
//    case KMS_SDES_EXT_AES_256_CM_HMAC_SHA1_32:
//    case KMS_SDES_EXT_AES_256_CM_HMAC_SHA1_80:
//      return KMS_SIP_SRTP_CIPHER_AES_CM_256_SIZE;
//    default:
//      return 0;
//  }
//}
//
//static void
//enhanced_g_value_copy (const GValue * src, GValue * dest)
//{
//  if (G_IS_VALUE (dest)) {
//    g_value_unset (dest);
//  }
//
//  g_value_init (dest, G_VALUE_TYPE (src));
//  g_value_copy (src, dest);
//}
//
//static gboolean
//kms_sip_rtp_endpoint_create_new_key (KmsSipRtpEndpoint * self, guint tag, GValue * key)
//{
//  if (self->priv->crypto == KMS_RTP_SDES_CRYPTO_SUITE_NONE) {
//    return FALSE;
//  }
//
//  if (self->priv->master_key == NULL) {
//    guint size;
//
//    GST_INFO_OBJECT (self, "Master key unset, generate random one");
//
//    size = get_max_key_size ((SrtpCryptoSuite) self->priv->crypto);
//    self->priv->master_key = generate_random_key (size);
//  }
//
//  if (self->priv->master_key == NULL) {
//    return FALSE;
//  }
//
//  return kms_sdp_sdes_ext_create_key_detailed (tag, self->priv->master_key,
//      (SrtpCryptoSuite) self->priv->crypto, NULL, NULL, NULL, key, NULL);
//}
//
//static GArray *
//kms_sip_rtp_endpoint_on_offer_keys_cb (KmsSdpSdesExt * ext, SdesExtData * edata)
//{
//  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (edata->rtpep);
//  GValue key = G_VALUE_INIT;
//  SdesKeys *sdes_keys;
//  GArray *keys;
//
//  KMS_ELEMENT_LOCK (self);
//
//  sdes_keys = g_hash_table_lookup (self->priv->sdes_keys, edata->media);
//
//  if (sdes_keys == NULL) {
//    GST_ERROR_OBJECT (self, "No keys configured for media %s", edata->media);
//    KMS_ELEMENT_UNLOCK (self);
//
//    return NULL;
//  }
//
//  if (!kms_sip_rtp_endpoint_create_new_key (self, DEFAULT_KEY_TAG, &key)) {
//    GST_ERROR_OBJECT (self, "Can not generate master key for media %s",
//        edata->media);
//    KMS_ELEMENT_UNLOCK (self);
//
//    return NULL;
//  }
//
//  enhanced_g_value_copy (&key, &sdes_keys->local);
//
//  KMS_ELEMENT_UNLOCK (self);
//
//  keys = g_array_sized_new (FALSE, FALSE, sizeof (GValue), 1);
//
//  /* Sets a function to clear an element of array */
//  g_array_set_clear_func (keys, (GDestroyNotify) g_value_unset);
//
//  g_array_append_val (keys, key);
//
//  return keys;
//}
//
//static gboolean
//kms_sip_rtp_endpoint_is_supported_key (KmsSipRtpEndpoint * self, GValue * key)
//{
//  SrtpCryptoSuite crypto;
//
//  if (!kms_sdp_sdes_ext_get_parameters_from_key (key, KMS_SDES_CRYPTO,
//          G_TYPE_UINT, &crypto, NULL)) {
//    return FALSE;
//  }
//
//  switch (crypto) {
//    case KMS_SDES_EXT_AES_CM_128_HMAC_SHA1_32:
//    case KMS_SDES_EXT_AES_CM_128_HMAC_SHA1_80:
//    case KMS_SDES_EXT_AES_256_CM_HMAC_SHA1_32:
//    case KMS_SDES_EXT_AES_256_CM_HMAC_SHA1_80:
//      return (SrtpCryptoSuite) self->priv->crypto == crypto;
//    default:
//      return FALSE;
//  }
//}
//
//static GValue *
//kms_sip_rtp_endpoint_get_supported_key (KmsSipRtpEndpoint * self, const GArray * keys)
//{
//  guint i;
//
//  for (i = 0; i < keys->len; i++) {
//    GValue *key;
//
//    key = &g_array_index (keys, GValue, 0);
//
//    if (key != NULL && kms_sip_rtp_endpoint_is_supported_key (self, key)) {
//      return key;
//    }
//  }
//
//  return NULL;
//}
//
//static gboolean
//kms_sip_rtp_endpoint_on_answer_keys_cb (KmsSdpSdesExt * ext, const GArray * keys,
//    GValue * key, SdesExtData * edata)
//{
//  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (edata->rtpep);
//  SdesKeys *sdes_keys;
//  GValue *offer_key;
//  gboolean ret = FALSE;
//  guint tag;
//
//  if (keys->len == 0) {
//    GST_ERROR_OBJECT (self, "No key provided in offer");
//    return FALSE;
//  }
//
//  KMS_ELEMENT_LOCK (self);
//
//  offer_key = kms_sip_rtp_endpoint_get_supported_key (self, keys);
//
//  if (offer_key == NULL) {
//    GST_ERROR_OBJECT (self, "No supported keys provided");
//    goto end;
//  }
//
//  sdes_keys = g_hash_table_lookup (self->priv->sdes_keys, edata->media);
//
//  if (sdes_keys == NULL) {
//    GST_ERROR_OBJECT (self, "No key configured for media %s", edata->media);
//    goto end;
//  }
//
//  if (!kms_sdp_sdes_ext_get_parameters_from_key (offer_key, KMS_SDES_TAG_FIELD,
//          G_TYPE_UINT, &tag, NULL)) {
//    GST_ERROR_OBJECT (self, "Invalid key offered");
//    goto end;
//  }
//
//  if (!kms_sip_rtp_endpoint_create_new_key (self, tag, key)) {
//    GST_ERROR_OBJECT (self, "Can not generate master key for media %s",
//        edata->media);
//    goto end;
//  }
//
//  enhanced_g_value_copy (key, &sdes_keys->local);
//  enhanced_g_value_copy (offer_key, &sdes_keys->remote);
//
//  ret = TRUE;
//
//end:
//  KMS_ELEMENT_UNLOCK (self);
//
//  return ret;
//}
//
//static void
//kms_sip_rtp_endpoint_on_selected_key_cb (KmsSdpSdesExt * ext, const GValue * key,
//    SdesExtData * edata)
//{
//  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (edata->rtpep);
//  SdesKeys *sdes_keys;
//
//  KMS_ELEMENT_LOCK (self);
//
//  sdes_keys = g_hash_table_lookup (self->priv->sdes_keys, edata->media);
//
//  if (sdes_keys == NULL) {
//    GST_ERROR_OBJECT (self, "Can not configure keys for connection");
//    goto end;
//  }
//
//  enhanced_g_value_copy (key, &sdes_keys->remote);
//
//  kms_sip_rtp_endpoint_set_remote_srtp_connection_key (self, edata->media,
//      sdes_keys);
//
//end:
//  KMS_ELEMENT_UNLOCK (self);
//}
//
//static KmsSdpMediaHandler *
//kms_sip_rtp_endpoint_provide_sdes_handler (KmsSipRtpEndpoint * self,
//    const gchar * media)
//{
//  KmsSdpMediaHandler *handler;
//  SdesKeys *sdes_keys;
//  SdesExtData *edata;
//  KmsSdpSdesExt *ext;
//
//  handler = KMS_SDP_MEDIA_HANDLER (kms_sdp_rtp_savpf_media_handler_new ());
//
//  /* Let's use sdes extension */
//  ext = kms_sdp_sdes_ext_new ();
//  if (!kms_sdp_media_handler_add_media_extension (handler,
//          KMS_I_SDP_MEDIA_EXTENSION (ext))) {
//    GST_ERROR_OBJECT (self, "Can not use SDES in handler %" GST_PTR_FORMAT,
//        handler);
//    goto end;
//  }
//
//  edata = sdes_ext_data_new (self, media);
//
//  g_signal_connect_data (ext, "on-offer-keys",
//      G_CALLBACK (kms_sip_rtp_endpoint_on_offer_keys_cb), edata,
//      (GClosureNotify) kms_ref_struct_unref, 0);
//  g_signal_connect_data (ext, "on-answer-keys",
//      G_CALLBACK (kms_sip_rtp_endpoint_on_answer_keys_cb),
//      kms_ref_struct_ref (KMS_REF_STRUCT_CAST (edata)),
//      (GClosureNotify) kms_ref_struct_unref, 0);
//  g_signal_connect_data (ext, "on-selected-key",
//      G_CALLBACK (kms_sip_rtp_endpoint_on_selected_key_cb),
//      kms_ref_struct_ref (KMS_REF_STRUCT_CAST (edata)),
//      (GClosureNotify) kms_ref_struct_unref, 0);
//
//  sdes_keys = sdes_keys_new (KMS_I_SDP_MEDIA_EXTENSION (ext));
//
//  KMS_ELEMENT_LOCK (self);
//
//  g_hash_table_insert (self->priv->sdes_keys, g_strdup (media), sdes_keys);
//
//  KMS_ELEMENT_UNLOCK (self);
//
//end:
//  return handler;
//}
//
//static KmsSdpMediaHandler *
//kms_sip_rtp_endpoint_get_media_handler (KmsSipRtpEndpoint * self, const gchar * media)
//{
//  KmsSdpMediaHandler *handler;
//
//  KMS_ELEMENT_LOCK (self);
//
//  if (isUseSdes(self)) {
//    handler = kms_rtp_endpoint_provide_sdes_handler (KMS_RTP_ENDPOINT(self), media);
//  } else {
//    handler = KMS_SDP_MEDIA_HANDLER (kms_sdp_rtp_avpf_media_handler_new ());
//  }
//
//  KMS_ELEMENT_UNLOCK (self);
//
//  return handler;
//}

static void
kms_sip_rtp_endpoint_create_media_handler (KmsBaseSdpEndpoint * base_sdp,
    const gchar * media, KmsSdpMediaHandler ** handler)
{
	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->create_media_handler (base_sdp, media, handler);

//  if (g_strcmp0 (media, "audio") == 0 || g_strcmp0 (media, "video") == 0) {
//    *handler = kms_sip_rtp_endpoint_get_media_handler (KMS_SIP_RTP_ENDPOINT (base_sdp),
//        media);
//  }
//
//  /* Chain up */
//  KMS_BASE_SDP_ENDPOINT_CLASS
//      (kms_sip_rtp_endpoint_parent_class)->create_media_handler (base_sdp, media,
//      handler);
}

///* Media handler management end */
//
//static void
//kms_sip_rtp_endpoint_configure_connection_keys (KmsSipRtpEndpoint * self,
//    KmsRtpBaseConnection * conn, const gchar * media)
//{
//  SdesKeys *sdes_keys;
//
//  KMS_ELEMENT_LOCK (self);
//
//  sdes_keys = g_hash_table_lookup (self->priv->sdes_keys, media);
//
//  if (sdes_keys == NULL) {
//    GST_ERROR_OBJECT (self, "No keys configured for %s connection", media);
//    goto end;
//  } else {
//    sdes_keys->conn = g_object_ref (conn);
//  }
//
//  if (!kms_sip_rtp_endpoint_set_local_srtp_connection_key (self, media, sdes_keys)) {
//    GST_ERROR_OBJECT (self, "Can not configure local connection key");
//    goto end;
//  }
//
//  kms_sip_rtp_endpoint_set_remote_srtp_connection_key (self, media, sdes_keys);
//
//end:
//  KMS_ELEMENT_UNLOCK (self);
//}



/* Configure media SDP begin */
static gboolean
kms_sip_rtp_endpoint_configure_media (KmsBaseSdpEndpoint * base_sdp_endpoint,
    KmsSdpSession * sess, KmsSdpMediaHandler * handler, GstSDPMedia * media)
{
  gboolean ret = TRUE;

  /* Chain up */
  ret = 	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->
		  	  configure_media (base_sdp_endpoint, sess, handler, media);
  return ret;
}

/* Configure media SDP end */

//static void
//kms_sip_rtp_endpoint_comedia_on_ssrc_active(GObject *rtpsession,
//    GObject *rtpsource, KmsSipRtpEndpoint *self)
//{
//  GstStructure* source_stats = NULL;
//  gchar *rtp_from = NULL;
//  gchar *rtcp_from = NULL;
//  GNetworkAddress *rtp_addr = NULL;
//  GNetworkAddress *rtcp_addr = NULL;
//  gboolean ok;
//
//  guint ssrc;
//  gboolean is_validated;
//  gboolean is_sender;
//
//  // Each session has a minimum of 2 source SSRCs: sender and receiver.
//  // Here we look for stats from the sender which had COMEDIA enabled
//  // (by setting "a=direction:active" in the SDP negotiation).
//
//  // Property RTPSource::ssrc, doc: GStreamer/rtpsource.c
//  g_object_get (rtpsource,
//      "ssrc", &ssrc, "is-validated", &is_validated, "is-sender", &is_sender, NULL);
//
//  if (!is_validated || !is_sender) {
//    GST_DEBUG_OBJECT (rtpsession,
//        "Ignore uninteresting RTPSource, SSRC: %u", ssrc);
//    return;
//  }
//
//  GST_INFO_OBJECT (rtpsession, "COMEDIA: Get port info, SSRC: %u", ssrc);
//
//  g_object_get (rtpsource, "stats", &source_stats, NULL);
//  if (!source_stats) {
//    GST_ERROR_OBJECT (rtpsession, "COMEDIA: RTPSource lacks stats");
//    return;
//  }
//
//  ok = gst_structure_get (source_stats,
//      "rtp-from", G_TYPE_STRING, &rtp_from, NULL);
//  if (!ok) {
//    GST_WARNING_OBJECT (rtpsession, "COMEDIA: 'rtp-from' not available yet");
//    goto end;
//  } else {
//    GST_INFO_OBJECT (rtpsession, "COMEDIA: 'rtp-from' found: '%s'", rtp_from);
//  }
//
//  ok = gst_structure_get (source_stats,
//      "rtcp-from", G_TYPE_STRING, &rtcp_from, NULL);
//  if (!ok) {
//    GST_WARNING_OBJECT (rtpsession, "COMEDIA: 'rtcp-from' not available yet");
//    goto end;
//  } else {
//    GST_INFO_OBJECT (rtpsession, "COMEDIA: 'rtcp-from' found: '%s'", rtcp_from);
//  }
//
//  rtp_addr = G_NETWORK_ADDRESS (g_network_address_parse (rtp_from, 5004, NULL));
//  if (!rtp_addr) {
//    GST_ERROR_OBJECT (rtpsession, "COMEDIA: Cannot parse 'rtp-from'");
//    goto end;
//  }
//
//  rtcp_addr = G_NETWORK_ADDRESS (
//      g_network_address_parse (rtcp_from, 5005, NULL));
//  if (!rtcp_addr) {
//    GST_ERROR_OBJECT (rtpsession, "COMEDIA: Cannot parse 'rtcp-from'");
//    goto end;
//  }
//
//  KmsRtpBaseConnection *conn =
//    g_hash_table_lookup (self->priv->comedia.rtp_conns, rtpsession);
//
//  kms_rtp_base_connection_set_remote_info(conn,
//    g_network_address_get_hostname (rtcp_addr),
//    g_network_address_get_port (rtp_addr),
//    g_network_address_get_port (rtcp_addr));
//
//  GST_INFO_OBJECT (rtpsession, "COMEDIA: Parsed route: IP: %s, RTP: %u, RTCP: %u",
//    g_network_address_get_hostname (rtcp_addr),
//    g_network_address_get_port (rtp_addr),
//    g_network_address_get_port (rtcp_addr));
//
//  gulong signal_id =
//    GPOINTER_TO_UINT(
//      g_hash_table_lookup (self->priv->comedia.signal_ids, rtpsession));
//
//  GST_INFO_OBJECT (rtpsession, "COMEDIA: Disconnect from signal 'on_ssrc_active'");
//  g_signal_handler_disconnect (rtpsession, signal_id);
//
//end:
//  if (rtp_addr) { g_object_unref (rtp_addr); }
//  if (rtcp_addr) { g_object_unref (rtcp_addr); }
//  if (rtp_from) { g_free(rtp_from); }
//  if (rtcp_from) { g_free(rtcp_from); }
//  gst_structure_free (source_stats);
//}
//
//static void
//kms_sip_rtp_endpoint_comedia_manager_create(KmsSipRtpEndpoint *self,
//    const GstSDPMedia *media, KmsRtpBaseConnection *conn)
//{
//  const gchar *media_str = gst_sdp_media_get_media (media);
//  guint session_id;
//
//  /* TODO: think about this when multiple audio/video medias */
//  if (g_strcmp0 (AUDIO_STREAM_NAME, media_str) == 0) {
//    session_id = AUDIO_RTP_SESSION;
//  } else if (g_strcmp0 (VIDEO_STREAM_NAME, media_str) == 0) {
//    session_id = VIDEO_RTP_SESSION;
//  } else {
//    GST_WARNING_OBJECT (self, "Media '%s' not supported", media_str);
//    return;
//  }
//
//  GObject *rtpsession = kms_base_rtp_endpoint_get_internal_session (
//      KMS_BASE_RTP_ENDPOINT(self), session_id);
//  if (!rtpsession) {
//    GST_WARNING_OBJECT (self,
//        "Abort: No RTP Session with ID %u", session_id);
//    return;
//  }
//
//  gulong signal_id = g_signal_connect (rtpsession, "on-ssrc-active",
//      G_CALLBACK (kms_sip_rtp_endpoint_comedia_on_ssrc_active), self);
//
//  g_hash_table_insert (self->priv->comedia.rtp_conns, g_object_ref (rtpsession),
//      conn);
//  g_hash_table_insert (self->priv->comedia.signal_ids,
//      g_object_ref (rtpsession), GUINT_TO_POINTER(signal_id));
//
//  g_object_unref (rtpsession);
//}

static void
kms_sip_rtp_endpoint_start_transport_send (KmsBaseSdpEndpoint *base_sdp_endpoint,
    KmsSdpSession *sess, gboolean offerer)
{
	KMS_BASE_SDP_ENDPOINT_CLASS(kms_sip_rtp_endpoint_parent_class)->start_transport_send (base_sdp_endpoint, sess, offerer);

}

static KmsSipRtpEndpointCloneData*
kms_sip_rtp_endpoint_create_clone_data (guint32 ssrcAudio, guint32 ssrcVideo)
{
	KmsSipRtpEndpointCloneData *data = g_malloc(sizeof (KmsSipRtpEndpointCloneData));

	data->audio_ssrc = ssrcAudio;
	data->video_ssrc = ssrcVideo;

	return data;
}

static void
kms_sip_rtp_endpoint_free_clone_data (GList *data)
{
	g_list_free_full (data, g_free);
}

static void
kms_sip_rtp_endpoint_clone_to_new_ep (KmsSipRtpEndpoint *self, KmsSipRtpEndpoint *cloned)
{
	GHashTable * sessions = kms_base_sdp_endpoint_get_sessions (KMS_BASE_SDP_ENDPOINT(self));
	GList *sessionKeys = g_hash_table_get_keys (sessions);
	gint i;
	GList *sessionsData = NULL;

	for (i = 0; i < g_hash_table_size(sessions); i++) {
		gpointer sesKey = sessionKeys->data;
		KmsBaseRtpSession *ses = KMS_BASE_RTP_SESSION (g_hash_table_lookup (sessions, sesKey));
		guint32 localAudioSsrc = ses->local_audio_ssrc;
		guint32 localVIdeoSsrc = ses->local_video_ssrc;
		KmsSipRtpEndpointCloneData *data = kms_sip_rtp_endpoint_create_clone_data (localAudioSsrc, localVIdeoSsrc);

		sessionsData = g_list_append (sessionsData, (gpointer)data);
	}

	KMS_ELEMENT_LOCK (cloned);
	if (cloned->priv->sessionData != NULL) {
		kms_sip_rtp_endpoint_free_clone_data (cloned->priv->sessionData);
	}
	cloned->priv->sessionData = sessionsData;
	KMS_ELEMENT_UNLOCK (cloned);
}

static void
kms_sip_rtp_endpoint_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  KMS_ELEMENT_LOCK (self);

  switch (prop_id) {
//    case PROP_MASTER_KEY:{
//      const gchar *key_b64 = g_value_get_string (value);
//      if (key_b64 == NULL) {
//        break;
//      }
//
//      gsize key_data_size;
//      guchar *tmp_b64 = g_base64_decode (key_b64, &key_data_size);
//      if (!tmp_b64) {
//        GST_ERROR_OBJECT (self, "Master key is not valid Base64");
//        break;
//      }
//      g_free (tmp_b64);
//
//      if (key_data_size != KMS_SIP_SRTP_CIPHER_AES_CM_128_SIZE
//          && key_data_size != KMS_SIP_SRTP_CIPHER_AES_CM_256_SIZE)
//      {
//        GST_ERROR_OBJECT (self,
//            "Bad Base64-decoded master key size: got %lu, expected %lu or %lu",
//            key_data_size, KMS_SIP_SRTP_CIPHER_AES_CM_128_SIZE,
//            KMS_SIP_SRTP_CIPHER_AES_CM_256_SIZE);
//        break;
//      }
//
//      g_free (self->priv->master_key);
//      self->priv->master_key = g_value_dup_string (value);
//      break;
//    }
//    case PROP_CRYPTO_SUITE:
//      self->priv->crypto = g_value_get_enum (value);
//      self->priv->use_sdes =
//          self->priv->crypto != KMS_RTP_SDES_CRYPTO_SUITE_NONE;
//      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  KMS_ELEMENT_UNLOCK (self);
}

static void
kms_sip_rtp_endpoint_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  KMS_ELEMENT_LOCK (self);

  switch (prop_id) {
//    case PROP_USE_SDES:
//      g_value_set_boolean (value, self->priv->use_sdes);
//      break;
//    case PROP_MASTER_KEY:
//      g_value_set_string (value, self->priv->master_key);
//      break;
//    case PROP_CRYPTO_SUITE:
//      g_value_set_enum (value, self->priv->crypto);
//      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  KMS_ELEMENT_UNLOCK (self);
}

static void
kms_sip_rtp_endpoint_finalize (GObject * object)
{
  KmsSipRtpEndpoint *self = KMS_SIP_RTP_ENDPOINT (object);

  GST_DEBUG_OBJECT (self, "finalize");

  if (self->priv->use_sdes_cache != NULL)
	  g_free (self->priv->use_sdes_cache);

  if (self->priv->sessionData != NULL)
	  g_list_free (self->priv->sessionData);

//  g_free (self->priv->master_key);
//  g_hash_table_unref (self->priv->sdes_keys);
//
//  g_hash_table_unref (self->priv->comedia.rtp_conns);
//  g_hash_table_unref (self->priv->comedia.signal_ids);
//
  /* chain up */
  G_OBJECT_CLASS (parent_class)->finalize (object);
}


static void
kms_sip_rtp_endpoint_class_init (KmsSipRtpEndpointClass * klass)
{
  GObjectClass *gobject_class;
  KmsBaseSdpEndpointClass *base_sdp_endpoint_class;
  GstElementClass *gstelement_class;

  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->set_property = kms_sip_rtp_endpoint_set_property;
  gobject_class->get_property = kms_sip_rtp_endpoint_get_property;
  gobject_class->finalize = kms_sip_rtp_endpoint_finalize;

  gstelement_class = GST_ELEMENT_CLASS (klass);
  gst_element_class_set_details_simple (gstelement_class,
      "SipRtpEndpoint",
      "SIP RTP/Stream/RtpEndpoint",
      "Sip Rtp Endpoint element",
      "Saul Pablo Labajo Izquierdo <slabajo@naevatec.com>");
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, PLUGIN_NAME, 0, PLUGIN_NAME);

  base_sdp_endpoint_class = KMS_BASE_SDP_ENDPOINT_CLASS (klass);
  base_sdp_endpoint_class->create_session_internal =
      kms_sip_rtp_endpoint_create_session_internal;
  base_sdp_endpoint_class->start_transport_send =
      kms_sip_rtp_endpoint_start_transport_send;

  /* Media handler management */
  base_sdp_endpoint_class->create_media_handler =
      kms_sip_rtp_endpoint_create_media_handler;

  base_sdp_endpoint_class->configure_media = kms_sip_rtp_endpoint_configure_media;

  klass->clone_to_new_ep = kms_sip_rtp_endpoint_clone_to_new_ep;

  obj_signals[SIGNAL_CLONE_TO_NEW_EP] =
      g_signal_new ("clone-to-new-ep",
      G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_ACTION | G_SIGNAL_RUN_LAST,
      G_STRUCT_OFFSET (KmsSipRtpEndpointClass, clone_to_new_ep), NULL, NULL,
      NULL, G_TYPE_NONE, 1, G_TYPE_POINTER);

//  g_object_class_install_property (gobject_class, PROP_USE_SDES,
//      g_param_spec_boolean ("use-sdes",
//          "Use SDES", "Set if Session Description Protocol Decurity"
//          " Description (SDES) is used", DEFAULT_USE_SDES,
//          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
//
//  g_object_class_install_property (gobject_class, PROP_MASTER_KEY,
//          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));
//      g_param_spec_string ("master-key",
//          "Master key", "Master key (either 30 or 46 bytes, depending on the"
//          " crypto-suite used)",
//          DEFAULT_MASTER_KEY,
//
//  g_object_class_install_property (gobject_class, PROP_CRYPTO_SUITE,
//      g_param_spec_enum ("crypto-suite",
//          "Crypto suite",
//          "Describes the encryption and authentication algorithms",
//          KMS_TYPE_RTP_SDES_CRYPTO_SUITE, DEFAULT_CRYPTO_SUITE,
//          G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));
//
//  obj_signals[SIGNAL_KEY_SOFT_LIMIT] =
//      g_signal_new ("key-soft-limit",
//      G_TYPE_FROM_CLASS (klass),
//      G_SIGNAL_RUN_LAST,
//      G_STRUCT_OFFSET (KmsSipRtpEndpointClass, key_soft_limit), NULL, NULL,
//      g_cclosure_marshal_VOID__STRING, G_TYPE_NONE, 1, G_TYPE_STRING);

  g_type_class_add_private (klass, sizeof (KmsSipRtpEndpointPrivate));

  // Kind of hack to use GLib type system in an unusual way:
  //  RTPEndpoint implementation is very final in the sense that it does not
  //  intend to be subclassed, this makes difficult to reimplement virtual
  //  methods that need chaining up like create_session_internal. The only way
  //  is to call directly the virtual method in the grandparent class
  //  Well, there is another way, to enrich base class implementation to allow
  //  subclasses to reimplement the virtual method (in the particular case of
  //  create_session_internal just need to skip session creation if already created.
  // TODO: When integrate on kms-elements get rid off this hack changing kms_rtp_endpoint_create_session_internal
  GType type =   g_type_parent  (g_type_parent (G_TYPE_FROM_CLASS (klass)));
  // TODO: This introduces a memory leak, this is reserved and never freed, but it is just a pointer (64 bits)
  //       A possible alternative would be to implement the class_finalize method
  gpointer typePointer = g_type_class_ref(type);
  base_sdp_endpoint_type = KMS_BASE_SDP_ENDPOINT_CLASS(typePointer);
}

/* TODO: not add abs-send-time extmap */

static void
kms_sip_rtp_endpoint_init (KmsSipRtpEndpoint * self)
{
  self->priv = KMS_SIP_RTP_ENDPOINT_GET_PRIVATE (self);

  self->priv->use_sdes_cache = NULL;
  self->priv->sessionData = NULL;

//  self->priv->sdes_keys = g_hash_table_new_full (g_str_hash, g_str_equal,
//      g_free, (GDestroyNotify) kms_ref_struct_unref);
//
//  self->priv->comedia.rtp_conns = g_hash_table_new_full (NULL, NULL,
//      g_object_unref, NULL);
//  self->priv->comedia.signal_ids = g_hash_table_new_full (NULL, NULL,
//      g_object_unref, NULL);
//
//  g_object_set (G_OBJECT (self), "bundle",
//      FALSE, "rtcp-mux", FALSE, "rtcp-nack", TRUE, "rtcp-remb", TRUE,
//      "max-video-recv-bandwidth", 0, NULL);
//  /* FIXME: remove max-video-recv-bandwidth when it b=AS:X is in the SDP offer */
}

gboolean
kms_sip_rtp_endpoint_plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, PLUGIN_NAME, GST_RANK_NONE,
      KMS_TYPE_SIP_RTP_ENDPOINT);
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    kmssiprtpendpoint,
    "Kurento SIP rtp endpoint",
    kms_sip_rtp_endpoint_plugin_init, VERSION, GST_LICENSE_UNKNOWN,
    "Kurento Elements", "http://kurento.com/")
