/*
 * (C) Copyright 2016 Kurento (http://kurento.org/)
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
#include <gst/gst.h>
#include "MediaPipeline.hpp"
#include <PassThroughImpl.hpp>
#include <SipRtpEndpointImplFactory.hpp>
#include <jsonrpc/JsonSerializer.hpp>
#include <KurentoException.hpp>
#include <gst/gst.h>
#include <CryptoSuite.hpp>
#include <FacadeRtpEndpointImpl.hpp>
#include <SDES.hpp>
#include <DSCPValue.hpp>
#include <SignalHandler.hpp>
#include <memory>

#define GST_CAT_DEFAULT kurento_sip_rtp_endpoint_impl
GST_DEBUG_CATEGORY_STATIC (GST_CAT_DEFAULT);
#define GST_DEFAULT_NAME "KurentoSipRtpEndpointImpl"

#define FACTORY_NAME "siprtpendpoint"

/* In theory the Master key can be shorter than the maximum length, but
 * the GStreamer's SRTP plugin enforces using the maximum length possible
 * for the type of cypher used (in file 'gstsrtpenc.c'). So, KMS also expects
 * that the maximum Master key size is used. */
#define KMS_SRTP_CIPHER_AES_CM_128_SIZE  ((gsize)30)
#define KMS_SRTP_CIPHER_AES_CM_256_SIZE  ((gsize)46)

#define PARAM_QOS_DSCP "qos-dscp"
#define PARAM_AUDIO_CODECS "audioCodecs"
#define PARAM_VIDEO_CODECS "videoCodecs"
#define PARAM_PUBLIC_IPV4 "externalIPv4"
#define PARAM_PUBLIC_IPV6 "externalIPv6"
#define PARAM_MAX_KBPS "max-kbps"
#define PARAM_MAX_BUCKET_SIZE "max-bucket-size"
#define PARAM_MAX_BUCKET_STORAGE "max-bucket-storage"



namespace kurento
{

static gint
get_dscp_value (std::shared_ptr<DSCPValue> qosDscp)
{
  switch (qosDscp->getValue () )  {
  case DSCPValue::AF11:
    return 10;

  case DSCPValue::AF12:
    return 12;

  case DSCPValue::AF13:
    return 14;

  case DSCPValue::AF21:
    return 18;

  case DSCPValue::AF22:
    return 20;

  case DSCPValue::AF23:
    return 22;

  case DSCPValue::AF31:
    return 26;

  case DSCPValue::AF32:
    return 28;

  case DSCPValue::AF33:
    return 30;

  case DSCPValue::AF41:
    return 34;

  case DSCPValue::AF42:
    return 36;

  case DSCPValue::AF43:
    return 38;

  case DSCPValue::AUDIO_HIGH:
    return 46;

  case DSCPValue::AUDIO_LOW:
    return 0;

  case DSCPValue::AUDIO_MEDIUM:
    return 46;

  case DSCPValue::AUDIO_VERYLOW:
    return 1;

  case DSCPValue::CHROME_HIGH:
    return 56;

  case DSCPValue::CHROME_LOW:
    return 0;

  case DSCPValue::CHROME_MEDIUM:
    return 56;

  case DSCPValue::CHROME_VERYLOW:
    return 8;

  case DSCPValue::CS0:
    return 0;

  case DSCPValue::CS1:
    return 8;

  case DSCPValue::CS2:
    return 16;

  case DSCPValue::CS3:
    return 24;

  case DSCPValue::CS4:
    return 32;

  case DSCPValue::CS5:
    return 40;

  case DSCPValue::CS6:
    return 48;

  case DSCPValue::CS7:
    return 56;

  case DSCPValue::DATA_HIGH:
    return 18;

  case DSCPValue::DATA_LOW:
    return 0;

  case DSCPValue::DATA_MEDIUM:
    return 10;

  case DSCPValue::DATA_VERYLOW:
    return 1;
  
  case DSCPValue::EF:
    return 46;

  case DSCPValue::LE:
    return 1;

  case DSCPValue::NO_DSCP:
    return -1;

  case DSCPValue::NO_VALUE:
    return -1;

  case DSCPValue::VIDEO_HIGH:
    return 36;

  case DSCPValue::VIDEO_HIGH_THROUGHPUT:
    return 34;

  case DSCPValue::VIDEO_LOW:
    return 0;

  case DSCPValue::VIDEO_MEDIUM:
    return 36;

  case DSCPValue::VIDEO_MEDIUM_THROUGHPUT:
    return 38;

  case DSCPValue::VIDEO_VERYLOW:
    return 1;

  case DSCPValue::VOICEADMIT:
    return 44;

  default:
    return -1;
  }
}

static std::list<std::string> get_codecs_list (std::string value) 
{
  std::list<std::string> result = {};

  std::stringstream ss(value);
 
  while (ss.good()) {
      std::string substr;
      getline(ss, substr, ',');
      if (!substr.empty ()) {
        result.push_back(substr);
      }
  }

  return result;
}

static void append_value_to_array (GArray *array, const char *val)
{
  GValue v = G_VALUE_INIT;
  GstStructure *s;

  g_value_init (&v, GST_TYPE_STRUCTURE);

  s = gst_structure_new_empty (val);
  if (s == NULL) {
    std::string message =
        std::string () + "Invalid codec name in config: '" + val + "'";
    GST_ERROR ("%s", message.c_str ());
    throw KurentoException (SDP_PARSE_ERROR, message);
  }

  gst_value_set_structure (&v, s);
  gst_structure_free (s);
  g_array_append_val (array, v);
}

static GArray* get_codec_array (std::list<std::string> list)
{
  GArray *array;

  array = g_array_new (FALSE, TRUE, sizeof (GValue) );

  for (std::list<std::string>::iterator it = list.begin(); it != list.end();++it) {
    append_value_to_array (array, it->c_str());
  }
  return array;
}



static std::string
setSdpPublicIP (const std::string &sdp, const std::string public_ip_v4, const std::string public_ip_v6)
{
	GstSDPMessage *sdpMessage;
  const GstSDPConnection *conn;
  const gchar *ip = NULL;
	gchar *modifiedSDPStr;
  std::string modifiedSdp;
  const gchar *addrtype;

	gst_sdp_message_new (&sdpMessage);
	gst_sdp_message_parse_buffer((const guint8*)sdp.c_str(), sdp.length(), sdpMessage);

  conn = gst_sdp_message_get_connection (sdpMessage);

  if (g_str_equal ("IP4", conn->addrtype)) {
    if (!public_ip_v4.empty()) {
      ip = public_ip_v4.c_str();
      addrtype = "IP4";
    }
  } else if (g_str_equal ("IP6", conn->addrtype)) {
    if (!public_ip_v6.empty()) {
      ip = public_ip_v6.c_str();
      addrtype = "IP6";
    }
  }
  if (ip != NULL) {
    gst_sdp_message_set_connection (sdpMessage, "IN", addrtype, ip, conn->ttl, conn->addr_number);
  }

	modifiedSDPStr = gst_sdp_message_as_text  (sdpMessage);
  modifiedSdp = modifiedSDPStr;
	gst_sdp_message_free (sdpMessage);
	g_free (modifiedSDPStr);

  return modifiedSdp;
}



SipRtpEndpointImpl::SipRtpEndpointImpl (const boost::property_tree::ptree &conf,
                                        std::shared_ptr<MediaPipeline> mediaPipeline,
                                        std::shared_ptr<SDES> crypto,
                                        bool useIpv6,
                                        std::shared_ptr<DSCPValue> qosDscp,
                                        std::string externalIPv4,
                                        std::string externalIPv6)
  : BaseRtpEndpointImpl (conf,
                         std::dynamic_pointer_cast<MediaObjectImpl> (mediaPipeline),
                         FACTORY_NAME, useIpv6)
{
  std::string maxKbpsValue;
  std::string maxBucketSizeValue;
  std::string maxBucketStorageValue;
  int maxKbps = 0;
  int maxBucketSize = 0;
  long maxBucketStorage = 0;

  this->qosDscp = qosDscp;

  if (qosDscp->getValue () == DSCPValue::NO_VALUE) {
    std::string cfg_dscp_value;

    if (getConfigValue<std::string,SipRtpEndpoint>(&cfg_dscp_value, 
        PARAM_QOS_DSCP)) {
      GST_INFO ("QOS-DSCP default configured value is %s", cfg_dscp_value.c_str() );
      qosDscp = std::make_shared<DSCPValue> (cfg_dscp_value);
    }
  }

  if ( (qosDscp->getValue () != DSCPValue::NO_VALUE) 
       && (qosDscp->getValue () != DSCPValue::NO_DSCP) ) {
    GST_INFO ("Setting QOS-DSCP value to %s", qosDscp->getString().c_str() );
    g_object_set (element, "qos-dscp", get_dscp_value (qosDscp), NULL);
  } else {
    GST_INFO ("No QOS-DSCP feature set");
  }

  std::string audio_codecs_str;
  std::string video_codecs_str;

  getConfigValue<std::string,SipRtpEndpoint>(&audio_codecs_str, PARAM_AUDIO_CODECS);
  this->audio_codecs = get_codecs_list (audio_codecs_str);

  getConfigValue<std::string,SipRtpEndpoint>(&video_codecs_str, PARAM_VIDEO_CODECS);
  this->video_codecs = get_codecs_list (video_codecs_str);

  if (audio_codecs.size() > 0) {
    g_object_set (element, 
                  "audio-codecs", get_codec_array(audio_codecs), 
                  NULL);
  }
  if (video_codecs.size() > 0) {
    g_object_set (element, 
                  "video-codecs", get_codec_array(video_codecs), 
                  NULL);
  }

  this->externalIPv4 = externalIPv4;
  if (this->externalIPv4.empty()) {
    std::string externalIPv4_value;

    if (getConfigValue<std::string,SipRtpEndpoint>(&externalIPv4_value, 
        PARAM_PUBLIC_IPV4)) {
      GST_INFO ("Public IP v4 default configured value is %s", externalIPv4_value.c_str() );
      this->externalIPv4 = externalIPv4_value;
    }

  }

  this->externalIPv6 = externalIPv6;
  if (this->externalIPv6.empty()) {
    std::string externalIPv6_value;

    if (getConfigValue<std::string,SipRtpEndpoint>(&externalIPv6_value, 
        PARAM_PUBLIC_IPV6)) {
      GST_INFO ("Public IP v6 default configured value is %s", externalIPv6_value.c_str() );
      this->externalIPv6 = externalIPv6_value;
    }

  }

  if (getConfigValue<std::string,SipRtpEndpoint>(&maxKbpsValue, PARAM_MAX_KBPS)) {
    GST_INFO ("MAX-KBPS default configured value is %s", maxKbpsValue.c_str() );
    try {
      maxKbps = std::stoi (maxKbpsValue);
    } catch (...) { }
  }

  if (getConfigValue<std::string,SipRtpEndpoint>(&maxBucketSizeValue, PARAM_MAX_BUCKET_SIZE)) {
    GST_INFO ("MAX-BUCKET-SIZE default configured value is %s", maxBucketSizeValue.c_str() );
    try {
      maxBucketSize = std::stoi (maxBucketSizeValue);
    } catch (...) { }
  }

  if (getConfigValue<std::string,SipRtpEndpoint>(&maxBucketStorageValue, PARAM_MAX_BUCKET_STORAGE)) {
    GST_INFO ("MAX-BUCKET-STORAGE default configured value is %s", maxBucketStorageValue.c_str() );
    try {
      maxBucketStorage = std::stoi (maxBucketStorageValue);
    } catch (...) { }
  }

  if (maxKbps > 0) {
    g_object_set (element, "max-kbps", maxKbps, NULL);
  }
  if (maxBucketSize > 0) {
    g_object_set (element, "max-bucket-size", maxBucketSize, NULL);
  }
  if (maxBucketStorage > 0) {
    g_object_set (element, "max-bucket-storage", maxBucketStorage, NULL);
  }

  if (!crypto->isSetCrypto() ) {
    return;
  }

  if (!crypto->isSetKey() && !crypto->isSetKeyBase64() ) {
    /* Use random key */
    g_object_set (element, "crypto-suite", crypto->getCrypto()->getValue(),
                  NULL);
    return;
  }

  gsize expect_size;

  switch (crypto->getCrypto()->getValue() ) {
  case CryptoSuite::AES_128_CM_HMAC_SHA1_32:
  case CryptoSuite::AES_128_CM_HMAC_SHA1_80:
    expect_size = KMS_SRTP_CIPHER_AES_CM_128_SIZE;
    break;

  case CryptoSuite::AES_256_CM_HMAC_SHA1_32:
  case CryptoSuite::AES_256_CM_HMAC_SHA1_80:
    expect_size = KMS_SRTP_CIPHER_AES_CM_256_SIZE;
    break;

  default:
    throw KurentoException (MEDIA_OBJECT_ILLEGAL_PARAM_ERROR,
                            "Invalid crypto suite");
  }

  std::string key_b64;
  gsize key_data_size = 0;

  if (crypto->isSetKey() ) {
    std::string tmp = crypto->getKey();
    key_data_size = tmp.length();

    gchar *tmp_b64 = g_base64_encode ((const guchar *)tmp.data(), tmp.length() );
    key_b64 = std::string (tmp_b64);
    g_free (tmp_b64);
  }
  else if (crypto->isSetKeyBase64() ) {
    key_b64 = crypto->getKeyBase64();
    guchar *tmp_b64 = g_base64_decode (key_b64.data(), &key_data_size);

    if (!tmp_b64) {
      GST_ERROR_OBJECT (element, "Master key is not valid Base64");
      throw KurentoException (MEDIA_OBJECT_ILLEGAL_PARAM_ERROR,
                              "Master key is not valid Base64");
    }

    g_free (tmp_b64);
  }

  if (key_data_size != expect_size) {
    GST_ERROR_OBJECT (element,
                      "Bad Base64-decoded master key size: got %lu, expected %lu",
                      key_data_size, expect_size);
    throw KurentoException (MEDIA_OBJECT_ILLEGAL_PARAM_ERROR,
                            "Master key size is wrong");
  }

  g_object_set (element, "master-key", key_b64.data(),
                "crypto-suite", crypto->getCrypto()->getValue(), NULL);
}


SipRtpEndpointImpl::~SipRtpEndpointImpl()
{
  if (handlerOnKeySoftLimit > 0) {
    unregister_signal_handler (element, handlerOnKeySoftLimit);
  }
}

void
SipRtpEndpointImpl::postConstructor ()
{
  BaseRtpEndpointImpl::postConstructor ();

  handlerOnKeySoftLimit = register_signal_handler (G_OBJECT (element),
                          "key-soft-limit",
                          std::function <void (GstElement *, gchar *) >
                          (std::bind (&SipRtpEndpointImpl::onKeySoftLimit, this,
                                      std::placeholders::_2) ),
                          std::dynamic_pointer_cast<SipRtpEndpointImpl>
                          (shared_from_this() ) );
}

MediaObjectImpl *
SipRtpEndpointImplFactory::createObject (const boost::property_tree::ptree &conf,
                                         std::shared_ptr<MediaPipeline> mediaPipeline,
                                         std::shared_ptr<SDES> crypto,
                                         bool cryptoAgnostic,
                                         bool useIpv6,
                                         std::shared_ptr<DSCPValue> qosDscp,
                                         const std::string &externalIPv4,
                                         const std::string &externalIPv6) const
{
  // Here we have made a real special construct to deal with Kurento object system to inreface with
  // an implementation of and object composed of others.
  // When Kurento compiles the interface of a remote object generates an schema to execute the
  // methods in the remote object that the client demands. This consist of implementing the
  // invoke mnethod for the Impl class in the generated sources (so that it cannot be changed)
  // and also chains its execution to base classes
  // Here we need to implement a "fake" class that resembles the interface we defined
  // but that in fact is composed of other objects.
  // SO, in fact we createObject a different class that acts as Facade of this
  // and that needs to implement all methods from this object interface and surely
  // delegate on this class (or other depending on the funtionality).
  return new FacadeRtpEndpointImpl (conf, mediaPipeline, crypto, cryptoAgnostic, 
                                    useIpv6, qosDscp, externalIPv4, externalIPv6);
}



void
SipRtpEndpointImpl::onKeySoftLimit (gchar *media)
{
  std::shared_ptr<MediaType> type;

  if (g_strcmp0 (media, "audio") == 0) {
    type = std::make_shared<MediaType> (MediaType::AUDIO);
  } else if (g_strcmp0 (media, "video") == 0) {
    type = std::make_shared<MediaType> (MediaType::VIDEO);
  } else if (g_strcmp0 (media, "data") == 0) {
    type = std::make_shared<MediaType> (MediaType::DATA);
  } else {
    GST_ERROR ("Unsupported media %s", media);
    return;
  }

  try {
    OnKeySoftLimit event (shared_from_this (), OnKeySoftLimit::getName (),
                          type);
    sigcSignalEmit (signalOnKeySoftLimit, event);
  } catch (const std::bad_weak_ptr &e) {
    // shared_from_this()
    GST_ERROR ("BUG creating %s: %s", OnKeySoftLimit::getName ().c_str (),
               e.what ());
  }
}
SipRtpEndpointImpl::StaticConstructor SipRtpEndpointImpl::staticConstructor;

SipRtpEndpointImpl::StaticConstructor::StaticConstructor()
{
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
                           GST_DEFAULT_NAME);
}

std::shared_ptr<SipRtpEndpointImpl> SipRtpEndpointImpl::getCleanEndpoint (
  const boost::property_tree::ptree &conf,
  std::shared_ptr<MediaPipeline> mediaPipeline,
  std::shared_ptr<SDES> crypto, bool useIpv6,
  std::shared_ptr<DSCPValue> qosDscp,
  std::string externalIPv4,
  std::string externalIPv6,
  const std::string &sdp,
  bool continue_audio_stream,
  bool continue_video_stream)
{
	std::shared_ptr<SipRtpEndpointImpl> newEndpoint = 
    std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (conf, 
                                        mediaPipeline, crypto, useIpv6, qosDscp, externalIPv4, externalIPv6));

	// Recover ports (sockets) from last SipRtpEndpoint and SSRCs to filter out old traffic
	this->cloneToNewEndpoint (newEndpoint, sdp, continue_audio_stream, 
                            continue_video_stream);
	return newEndpoint;
}

std::shared_ptr<SipRtpEndpointImpl> SipRtpEndpointImpl::cloneToNewEndpoint (
	std::shared_ptr<SipRtpEndpointImpl> newEp,
	const std::string &sdp,
	bool continue_audio_stream,
	bool continue_video_stream)
{
	g_signal_emit_by_name (element, "clone-to-new-ep", newEp->element, 
                         sdp.c_str());

	return newEp;
}

void SipRtpEndpointImpl::setAudioSsrc (guint32 ssrc)
{
  g_object_set (element, "audio_ssrc", ssrc, NULL);
}

void SipRtpEndpointImpl::setVideoSsrc (guint32 ssrc)
{
  g_object_set (element, "video_ssrc", ssrc, NULL);
}

std::string 
SipRtpEndpointImpl::generateOffer ()
{
  std::string offer;

  offer = BaseRtpEndpointImpl::generateOffer();
  return offer;
}

std::string 
SipRtpEndpointImpl::generateOffer (std::shared_ptr<OfferOptions> options)
{
  std::string offer;

  offer = BaseRtpEndpointImpl::generateOffer(options);
  return setSdpPublicIP (offer, this->externalIPv4, this->externalIPv6);
}

std::string 
SipRtpEndpointImpl::processOffer (const std::string &offer)
{
  std::string answer;

  answer = BaseRtpEndpointImpl::processOffer(offer);
  return setSdpPublicIP (answer, this->externalIPv4, this->externalIPv6);
}

std::string 
SipRtpEndpointImpl::processAnswer (const std::string &answer)
{
  std::string local;

  local = BaseRtpEndpointImpl::processAnswer(answer);
  return setSdpPublicIP (local, this->externalIPv4, this->externalIPv6);
}

std::string 
SipRtpEndpointImpl::getLocalSessionDescriptor ()
{
  return setSdpPublicIP (BaseRtpEndpointImpl::getLocalSessionDescriptor(), this->externalIPv4, this->externalIPv6);
}


} /* kurento */
