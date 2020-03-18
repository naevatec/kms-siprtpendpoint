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
#include <glib.h>
#include <gst/gst.h>
#include "MediaPipeline.hpp"
#include "ComposedObjectImpl.hpp"
#include <PassThroughImpl.hpp>
#include <MediaElementImpl.hpp>
#include <SipRtpEndpointImplFactory.hpp>
#include <jsonrpc/JsonSerializer.hpp>
#include <KurentoException.hpp>
#include <gst/gst.h>
#include <CryptoSuite.hpp>
#include <FacadeRtpEndpointImpl.hpp>
#include <SDES.hpp>
#include <CryptoSuite.hpp>
#include <memory>
#include <string>
#include <sstream>
#include <list>
#include <MediaFlowInStateChange.hpp>
#include <MediaFlowState.hpp>


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

namespace kurento
{

FacadeRtpEndpointImpl::FacadeRtpEndpointImpl (const boost::property_tree::ptree &conf,
                                  std::shared_ptr<MediaPipeline> mediaPipeline,
                                  std::shared_ptr<SDES> crypto,
								  bool cryptoAgnostic,
								  bool useIpv6)
  : ComposedObjectImpl (conf,
                         std::dynamic_pointer_cast<MediaPipeline> (mediaPipeline)), cryptoCache (crypto), useIpv6Cache (useIpv6)
{
  this->cryptoAgnostic = cryptoAgnostic;

  rtp_ep = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, mediaPipeline, crypto, useIpv6));
  audioCapsSet = NULL;
  videoCapsSet = NULL;
  rembParamsSet = NULL;

  // Magic values to assess no change on SSRC
  this->agnosticMediaAudioSsrc = 0;
  this->agnosticMediaVideoSsrc = 0;
}

FacadeRtpEndpointImpl::~FacadeRtpEndpointImpl()
{
	linkMediaElement(NULL, NULL);
}

void
FacadeRtpEndpointImpl::postConstructor ()
{
  ComposedObjectImpl::postConstructor ();

  rtp_ep->postConstructor();
  linkMediaElement(rtp_ep, rtp_ep);

}


FacadeRtpEndpointImpl::StaticConstructor FacadeRtpEndpointImpl::staticConstructor;

FacadeRtpEndpointImpl::StaticConstructor::StaticConstructor()
{
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
                           GST_DEFAULT_NAME);
}


// The methods connect and invoke are automatically generated in the SipRtpEndpoint class
// but no in the Facadde, so we have to redirect the implementation to the one in SipRtpEndpoint
bool FacadeRtpEndpointImpl::connect (const std::string &eventType, std::shared_ptr<EventHandler> handler)
{
    std::weak_ptr<EventHandler> wh = handler;

    if ("OnKeySoftLimit" == eventType){
    	sigc::connection conn = connectEventToExternalHandler<OnKeySoftLimit> (signalOnKeySoftLimit, wh);
	    handler->setConnection (conn);
	    return true;
    }
	if ("MediaStateChanged" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<MediaStateChanged> (signalMediaStateChanged, wh);
	    handler->setConnection (conn);
	    return true;
	}
	if ("ConnectionStateChanged" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<ConnectionStateChanged> (signalConnectionStateChanged, wh);
	    handler->setConnection (conn);
	    return true;
	}
	if ("MediaSessionStarted" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<MediaSessionStarted> (signalMediaSessionStarted, wh);
	    handler->setConnection (conn);
	    return true;
	}
	if ("MediaSessionTerminated" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<MediaSessionTerminated> (signalMediaSessionTerminated, wh);
	    handler->setConnection (conn);
	    return true;
	}
	return ComposedObjectImpl::connect (eventType, handler);
}


void FacadeRtpEndpointImpl::invoke (std::shared_ptr<MediaObjectImpl> obj,
                     const std::string &methodName, const Json::Value &params,
                     Json::Value &response)
{
	this->rtp_ep->invoke(obj, methodName, params, response);
}




/*--------------------- Implementation of SipRtpEndpoint specific features ---------------------------------*/

std::string FacadeRtpEndpointImpl::generateOffer ()
{
	std::string offer;

	try {
		offer =  this->rtp_ep->generateOffer();
		if (this->isCryptoAgnostic()) {
			this->generateCryptoAgnosticOffer (offer);
			GST_INFO ("GenerateOffer: Generated crypto agnostic offer");
		}
		GST_DEBUG("GenerateOffer: \n%s", offer.c_str());
		return offer;
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ALREADY_NEGOTIATED) {
			GST_INFO("Consecutive generate Offer on %s, cloning endpoint", this->getId().c_str());
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}
	std::shared_ptr<SipRtpEndpointImpl> newEndpoint = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, getMediaPipeline (), cryptoCache, useIpv6Cache));

	newEndpoint->postConstructor();
	renewInternalEndpoint (newEndpoint);
	offer = newEndpoint->generateOffer();
	if (this->isCryptoAgnostic()) {
		this->generateCryptoAgnosticOffer (offer);
		GST_INFO ("Generated crypto agnostic offer");
	}
	GST_DEBUG("2nd try GenerateOffer: \n%s", offer.c_str());
	GST_INFO("Consecutive generate Offer on %s, endpoint cloned and offer processed", this->getId().c_str());
	return offer;
}

static std::list<GstSDPMedia*>
getMediasFromSdp (GstSDPMessage *sdp)
{
	std::list<GstSDPMedia*> mediaList;
	guint idx = 0;
	guint medias_len;

	// Get media lines from SDP offer
	medias_len = gst_sdp_message_medias_len  (sdp);
	while (idx < medias_len) {
		const GstSDPMedia*   sdpMedia;

		sdpMedia = gst_sdp_message_get_media (sdp, idx);
		if (sdpMedia != NULL) {
			idx++;
			mediaList.push_back((GstSDPMedia*)sdpMedia);
		}
	}

	return mediaList;
}

static GstSDPMessage*
parseSDP (const std::string& sdp) {
	GstSDPMessage *sdpObject = NULL;

	if (gst_sdp_message_new (&sdpObject) != GST_SDP_OK) {
		GST_ERROR("Could not create SDP object");
		return NULL;
	}
	if (gst_sdp_message_parse_buffer ((const guint8*) sdp.c_str(), strlen (sdp.c_str()), sdpObject) != GST_SDP_OK) {
		GST_ERROR("Could not parse SDP answer");
		return NULL;
	}
	return sdpObject;
}


std::string FacadeRtpEndpointImpl::processOffer (const std::string &offer)
{
	std::string answer;
	std::shared_ptr<SDES> cryptoToUse (new SDES());
	std::shared_ptr<SipRtpEndpointImpl> newEndpoint;
	std::string modifiableOffer (offer);

	try {
		bool renewEp = false;

		GST_DEBUG("ProcessOffer: \n%s", offer.c_str());
		if (this->isCryptoAgnostic ())
			renewEp = this->checkCryptoOffer (modifiableOffer, cryptoToUse);

		if (!renewEp) {
			answer = this->rtp_ep->processOffer(modifiableOffer);
			GST_DEBUG ("Generated Answer: \n%s", answer.c_str());
			return answer;
		} else {
			GST_INFO("ProcessOffer: Regenerating endpoint for crypto agnostic");
		}
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ALREADY_NEGOTIATED) {
			GST_INFO("Consecutive process Offer on %s, cloning endpoint", this->getId().c_str());
			cryptoToUse = cryptoCache;
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}

	// If we get here is either SDP offer didn't match existing endpoint regarding crypto
	// or existing endpoint was already negotiated.
	// In either case, cryptoToUse contains the cryptoCofniguration needed to instantiate new SipRtpEndpoint
	newEndpoint = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, getMediaPipeline (), cryptoToUse, useIpv6Cache));
	newEndpoint->postConstructor();
	renewInternalEndpoint (newEndpoint);
	answer = newEndpoint->processOffer(modifiableOffer);
	GST_DEBUG ("2nd try Generated Answer: \n%s", answer.c_str());
	GST_INFO("Consecutive process Offer on %s, endpoint cloned and offer processed", this->getId().c_str());
	return answer;
}

static std::shared_ptr<SDES>
copySDES (std::shared_ptr<SDES> origSdes)
{
	std::shared_ptr<SDES> sdes (new SDES ());

	if (origSdes != NULL) {
		if (origSdes->isSetCrypto())
			sdes->setCrypto(origSdes->getCrypto());
		if (origSdes->isSetKey())
			sdes->setKey(origSdes->getKey());
		if (origSdes->isSetKeyBase64())
			sdes->setKeyBase64(origSdes->getKeyBase64());
	}
	return sdes;
}

std::string FacadeRtpEndpointImpl::processAnswer (const std::string &answer)
{
	std::string result;
	std::shared_ptr<SDES> cryptoToUse  = copySDES (this->cryptoCache);
	std::shared_ptr<SipRtpEndpointImpl> newEndpoint;
	std::string modifiableAnswer (answer);

	try {
		bool renewEp = false;

		GST_DEBUG("ProcessAnswer: \n%s", answer.c_str());
		if (this->isCryptoAgnostic ())
			renewEp = this->checkCryptoAnswer (modifiableAnswer, cryptoToUse);

		if (!renewEp) {
			result = this->rtp_ep->processAnswer(modifiableAnswer);
			GST_DEBUG ("ProcessAnswer: \n%s", result.c_str());
			return result;
		} else {
			GST_INFO ("ProcessAnswer: Regenerating endpoint for crypto agnostic");
		}
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ANSWER_ALREADY_PROCCESED) {
			GST_INFO("Consecutive process Answer on %s, cloning endpoint", this->getId().c_str());
			cryptoToUse = cryptoCache;
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}
	std::string unusedOffer;
	std::shared_ptr<SipRtpEndpointImpl> oldEndpoint;

	newEndpoint = rtp_ep->getCleanEndpoint (config, getMediaPipeline (), cryptoToUse, useIpv6Cache, answer);
	if (this->agnosticMediaAudioSsrc != 0) {
		newEndpoint->setAudioSsrc (this->agnosticMediaAudioSsrc);
	}
	if (this->agnosticMediaVideoSsrc != 0) {
		newEndpoint->setVideoSsrc (this->agnosticMediaVideoSsrc);
	}
	newEndpoint->postConstructor();
	oldEndpoint = renewInternalEndpoint (newEndpoint);
	unusedOffer = newEndpoint->generateOffer();
	GST_DEBUG ("2nd try ProcessAnswer - Unused offer: \n%s", unusedOffer.c_str());
	result = newEndpoint->processAnswer(modifiableAnswer);
	GST_DEBUG ("2nd try ProcessAnswer: \n%s", result.c_str());
	GST_INFO("Consecutive process Answer on %s, endpoint cloned and answer processed", this->getId().c_str());
	return result;
}

std::string FacadeRtpEndpointImpl::getLocalSessionDescriptor ()
{
	return this->rtp_ep->getLocalSessionDescriptor();
}

std::string FacadeRtpEndpointImpl::getRemoteSessionDescriptor ()
{
	return this->rtp_ep->getRemoteSessionDescriptor();
}


bool
FacadeRtpEndpointImpl::isCryptoAgnostic ()
{
	return this->cryptoAgnostic;
}

void
FacadeRtpEndpointImpl::replaceSsrc (GstSDPMedia *media, guint idx, gchar *newSsrcStr)
{
	const GstSDPAttribute *attr;
	GstSDPAttribute *new_attr;
	std::string ssrc;
	std::string oldSsrc;
    GRegex *regex;
	std::string newSsrc;
	std::size_t ssrcIdx;
    GMatchInfo *match_info = NULL;

	attr = gst_sdp_media_get_attribute (media, idx);
	if (attr != NULL) {
		new_attr = (GstSDPAttribute*) g_malloc (sizeof(GstSDPAttribute));
		ssrc = attr->value;

		regex = g_regex_new ("^(?<ssrc>[0-9]+)(.*)?$", (GRegexCompileFlags)0, (GRegexMatchFlags)0, NULL);
		g_regex_match (regex, ssrc.c_str(), (GRegexMatchFlags)0, &match_info);
		if (g_match_info_matches (match_info)) {
			oldSsrc = g_match_info_fetch_named (match_info, "ssrc");
		}
		g_match_info_free (match_info);
		g_regex_unref (regex);

		ssrcIdx = ssrc.find(oldSsrc);
		if (ssrcIdx != std::string::npos) {
			newSsrc = ssrc.substr(0, ssrcIdx).append(newSsrcStr).append (ssrc.substr(ssrcIdx+oldSsrc.length(), std::string::npos));
		}

		gst_sdp_attribute_set  (new_attr, "ssrc", newSsrc.c_str());
		gst_sdp_media_replace_attribute (media, idx, new_attr);
	}
}

guint32
FacadeRtpEndpointImpl::replaceAllSsrcAttrs (GstSDPMedia *media, std::list<guint> sscrIdxs)
{
	// set the ssrc attribute
	guint32 newSsrc = g_random_int ();
	gchar newSsrcStr [11];

	g_snprintf (newSsrcStr, 11, "%u", newSsrc);
	for (std::list<guint>::iterator it=sscrIdxs.begin(); it != sscrIdxs.end(); ++it) {
		replaceSsrc (media, *it, newSsrcStr);
	}
	return newSsrc;
}

void
FacadeRtpEndpointImpl::removeCryptoAttrs (GstSDPMedia *media, std::list<guint> cryptoIdx)
{
	// Remove the crypto attributes, to not change atttribute index we go backward
	for (std::list<guint>::reverse_iterator rit=cryptoIdx.rbegin(); rit!= cryptoIdx.rend(); ++rit) {
		gst_sdp_media_remove_attribute (media, *rit);
	}
}

void
FacadeRtpEndpointImpl::addAgnosticMedia (GstSDPMedia *media, GstSDPMessage *sdpOffer)
{
	std::list<guint> sscrIdxs, cryptoIdxs;
	GstSDPMedia* newMedia;
	guint idx, attrs_len;
	guint32 agnosticMediaSsrc;

	if (gst_sdp_media_copy (media, &newMedia) != GST_SDP_OK) {
		GST_ERROR ("Could not copy media, cannot generate secure agnostic media");
		return;
	}

	// Only non crypto lines should need to be generated
	if (g_strcmp0 (gst_sdp_media_get_proto (media), "RTP/SAVP") == 0) {
		gst_sdp_media_set_proto (newMedia, "RTP/AVP");
	} else if (g_strcmp0 (gst_sdp_media_get_proto (media), "RTP/SAVPF") == 0) {
		gst_sdp_media_set_proto (newMedia, "RTP/AVPF");
	} else {
		// Not supported protocol not processing
		gst_sdp_media_free (newMedia);
		return;
	}

	// Gets relevant attributes
	idx = 0;
	attrs_len = gst_sdp_media_attributes_len (newMedia);
	while (idx < attrs_len) {
		const GstSDPAttribute *attr;

		attr = gst_sdp_media_get_attribute (newMedia, idx);
		if (g_strcmp0(attr->key, "ssrc") == 0) {
			sscrIdxs.push_back(idx);
		} else 	if (g_strcmp0(attr->key, "crypto") == 0) {
			cryptoIdxs.push_back(idx);
		}
		idx++;
	}

	agnosticMediaSsrc = replaceAllSsrcAttrs (newMedia, sscrIdxs);
	if (g_strcmp0(gst_sdp_media_get_media (newMedia), "audio") == 0) {
		this->agnosticMediaAudioSsrc = agnosticMediaSsrc;
	} else if (g_strcmp0(gst_sdp_media_get_media (newMedia), "video") == 0) {
		this->agnosticMediaVideoSsrc = agnosticMediaSsrc;
	}

	// Remove crypto attribute
	removeCryptoAttrs (newMedia, cryptoIdxs);

	// Add new media to the offer so it is crypto agnostic
	gst_sdp_message_add_media (sdpOffer, newMedia);
}

static bool
isMediaActive (GstSDPMedia *media)
{
	const gchar *inactive;

	inactive = gst_sdp_media_get_attribute_val (media, "inactive");

	if (inactive == NULL)
		return (gst_sdp_media_get_port (media) != 0);

	return false;
}


static void
splitMediaByCrypto (std::list<GstSDPMedia*> &nonCryptoList, std::list<GstSDPMedia*> &cryptoList)
{
	// For each media we check if it is using a crypto protocol or not
	for (std::list<GstSDPMedia*>::iterator it=nonCryptoList.begin(); it != nonCryptoList.end(); ){
		GstSDPMedia *media = (GstSDPMedia*) *it;
		if ((g_strcmp0 (gst_sdp_media_get_proto (media), "RTP/SAVP") == 0)
			|| (g_strcmp0 (gst_sdp_media_get_proto (media), "RTP/SAVPF") == 0)) {
			if (isMediaActive (media)) {
				cryptoList.push_back(media);
				it = nonCryptoList.erase (it);
				continue;
			}
		}
		++it;
	}
}

bool
FacadeRtpEndpointImpl::generateCryptoAgnosticOffer (std::string& offer)
{
	std::list<GstSDPMedia*> mediaList;
	GstSDPMessage *sdpOffer;
	gchar* result;

	// If not crypto configured, cannot generate crypto agnostic offer
	if (this->cryptoCache == NULL) {
		GST_WARNING ("cryptoAgnostic configured, but no crypto info set, cannot generate cryptoAgnostic endpoint, reverting to non crypto endpoint");
		return false;
	}

	sdpOffer = parseSDP (offer);
	if (sdpOffer == NULL)
		return false;
	mediaList = getMediasFromSdp (sdpOffer);

	// For each media line we generate a new line with different ssrc, same port and different protocol (is current protocol is RTP/SAVP,
	// new one is RTP/AVP)
	// Keep in mind that we already have crypto lines, so only non-crypto lines must be generated
	for (std::list<GstSDPMedia*>::iterator it=mediaList.begin(); it != mediaList.end(); ++it) {
		addAgnosticMedia (*it, sdpOffer);
	}

	result = gst_sdp_message_as_text (sdpOffer);
	offer = result;
	g_free (result);
	gst_sdp_message_free (sdpOffer);
	return true;
}

static std::shared_ptr<CryptoSuite>
get_crypto_suite_from_str (gchar* str)
{
	if (g_strcmp0 (str, "AES_CM_128_HMAC_SHA1_32") == 0)
		return std::shared_ptr<CryptoSuite> (new CryptoSuite(CryptoSuite::AES_128_CM_HMAC_SHA1_32));
	if (g_strcmp0 (str, "AES_CM_128_HMAC_SHA1_80") == 0)
		return std::shared_ptr<CryptoSuite> (new CryptoSuite(CryptoSuite::AES_128_CM_HMAC_SHA1_80));
	if (g_strcmp0 (str, "AES_256_CM_HMAC_SHA1_32") == 0)
		return std::shared_ptr<CryptoSuite> (new CryptoSuite(CryptoSuite::AES_256_CM_HMAC_SHA1_32));
	if (g_strcmp0 (str, "AES_256_CM_HMAC_SHA1_80") == 0)
		return std::shared_ptr<CryptoSuite> (new CryptoSuite(CryptoSuite::AES_256_CM_HMAC_SHA1_80));
	return NULL;
}

static std::string
get_crypto_key_from_str (gchar* str)
{
	gchar **attrs;
	std::string result;

	attrs = g_strsplit (str, "|", 0);

    if (attrs[0] == NULL) {
    	GST_WARNING ("Noy key provided in crypto attribute");
	    return result;
    }
    result = attrs [0];
    g_strfreev (attrs);
    return result;
}

static std::shared_ptr<SDES>
build_crypto (std::shared_ptr<CryptoSuite> suite, std::string &key)
{
	std::shared_ptr<SDES> sdes (new SDES ());

	sdes->setCrypto (suite);
	sdes->setKeyBase64 (key.c_str());
	return sdes;
}

static bool
get_valid_crypto_info_from_offer (GstSDPMedia *media, std::shared_ptr<SDES>& crypto)
{
	guint idx, attrs_len;

	attrs_len = gst_sdp_media_attributes_len (media);
	for (idx = 0; idx < attrs_len; idx++) {
		// We can only support the same crypto information for all medias (audio and video) in an offer
		// RtpEndpoint currently only supports that
		// And as the offer may have several crypto to select, we choose the first one that may be supported
		const gchar* cryptoStr = gst_sdp_media_get_attribute_val_n (media, "crypto", idx);

		if (cryptoStr != NULL) {
			gchar** attrs;
			std::string key;
			std::shared_ptr<CryptoSuite> cryptoSuite = NULL;

			attrs = g_strsplit (cryptoStr, " ", 0);
			if (attrs[0] == NULL) {
			    GST_WARNING ("Bad crypto attribute format");
			    goto next_iter;
			}
		    if (attrs[1] == NULL) {
		    	GST_WARNING ("No crypto suite provided");
			    goto next_iter;
			}
		    cryptoSuite = get_crypto_suite_from_str (attrs[1]);
		    if (cryptoSuite == NULL) {
		    	GST_WARNING ("No valid crypto suite");
			    goto next_iter;
		    }
		    if (attrs[2] == NULL) {
		    	GST_WARNING ( "No key parameters provided");
			    goto next_iter;
		    }
		    if (!g_str_has_prefix (attrs[2], "inline:")) {
		    	GST_WARNING ("Unsupported key method provided");
			    goto next_iter;
		    }
		    key = get_crypto_key_from_str (attrs[2] + strlen ("inline:"));
		    if (key.length () == 0) {
		    	GST_WARNING ("No key provided");
			    goto next_iter;
		    }
		    crypto = build_crypto (cryptoSuite, key);
		    GST_INFO ("Crypto offer and valid key found");
		    g_strfreev (attrs);
		    return true;

next_iter:
		    g_strfreev (attrs);
		}
	}
	return false;
}

static std::shared_ptr<SDES>
is_crypto_sdp (std::list<GstSDPMedia*> mediaList)
{
	std::shared_ptr<SDES> sdes (new SDES());
	std::list<GstSDPMedia*> cryptoMediaList;

	splitMediaByCrypto (mediaList, cryptoMediaList);

	if (cryptoMediaList.size () > 0) {
		// Offer has crypto info, so we need to ensure
		// - First, that the endpoint supports crypto
		// - Second, that crypto suite and master key correspond to that in the offer
		if (!get_valid_crypto_info_from_offer (cryptoMediaList.front (), sdes)) {
			// No valid key found,
			GST_ERROR ("Crypto offer found, but no supported key found in offer, cannot answer");
		} else {
			GST_INFO ("Valid crypto info found in offer");
		}
	} else {
		GST_INFO ("No crypto offer found");
	}

	return sdes;
}

bool
FacadeRtpEndpointImpl::checkCryptoOffer (std::string& offer, std::shared_ptr<SDES>& crypto)
{
	std::list<GstSDPMedia*> mediaList;
	GstSDPMessage* sdpOffer;
	std::shared_ptr<SDES> sdes;

	sdpOffer = parseSDP (offer);
	if (sdpOffer == NULL)
		return false;

	mediaList = getMediasFromSdp (sdpOffer);

	sdes = is_crypto_sdp (mediaList);

	// The easiest way to proceed is recreate the endpoint in any case
	crypto = sdes;
	gst_sdp_message_free (sdpOffer);
	return true;
}

static bool
isCryptoCompatible (std::shared_ptr<SDES> original, std::shared_ptr<SDES> answer)
{
	bool result = true;

	if (original->isSetCrypto() != answer->isSetCrypto()) {
		result = false;
	} else {
		if (original->isSetCrypto()) {
			if (original->getCrypto()->getValue() != answer->getCrypto()->getValue())
				result = false;
		} else {
			return !(answer->isSetCrypto ());
		}
	}
	return result;
}

static void
removeMediaLines (GstSDPMessage* sdpAnswer, std::list<GstSDPMedia*> mediaList)
{
	std::list<guint> mediaIdxToRemove;
	guint idx = 0;
	bool got_audio = false, got_video = false;

	// For each media we check if it is using a crypto protocol or not
	for (std::list<GstSDPMedia*>::iterator it=mediaList.begin(); it != mediaList.end(); ){
		GstSDPMedia *media = (GstSDPMedia*) *it;

		// We just get the first audio and first video that are active (or port != 0
		if (!isMediaActive (media)) {
			mediaIdxToRemove.push_back (idx);
		} else {
			if (g_strcmp0 (media->media, "audio") == 0) {
				if (!got_audio) {
					got_audio = true;
				} else {
					mediaIdxToRemove.push_back (idx);
				}
			} else if (g_strcmp0 (media->media, "video") == 0) {
				if (!got_video) {
					got_video = true;
				} else {
					mediaIdxToRemove.push_back (idx);
				}

			}
		}
		++it;
		++idx;
	}

	// We cannot remove all medias, we need to leave at least one audio and one video
	// If mediaIdxToRemove has all medias, we just remove two last ones
	if (mediaIdxToRemove.size () == mediaList.size()) {
		mediaIdxToRemove.pop_back ();
		mediaIdxToRemove.pop_back ();
	}

	// Remove media lines that are not <crypto> if there are other lines
	// on mediaIdxToRemote we have the indexes of media lines that are not <crypto>
	// So we remove thos indexes only if there are other media lines.
	if ((mediaIdxToRemove.size () > 0) && (mediaList.size() > mediaIdxToRemove.size ())) {
		for (std::list<guint>::reverse_iterator it=mediaIdxToRemove.rbegin(); it != mediaIdxToRemove.rend(); ++it) {
			g_array_remove_index (sdpAnswer->medias, *it);
		}
	}
}

static std::shared_ptr<SDES>
fitMediaAnswer (std::string& answer, bool isLocalCrypto)
{
	std::list<GstSDPMedia*> mediaList;
	GstSDPMessage* sdpAnswer;
	std::shared_ptr<SDES> sdes;
	gchar * newAnswer;

	sdpAnswer = parseSDP (answer);
	if (sdpAnswer == NULL)
		return sdes;

	mediaList = getMediasFromSdp (sdpAnswer);

	sdes = is_crypto_sdp (mediaList);

	removeMediaLines (sdpAnswer, mediaList);
	newAnswer = gst_sdp_message_as_text (sdpAnswer);
	answer = newAnswer;
	g_free ((gpointer)newAnswer);

	gst_sdp_message_free (sdpAnswer);

	return sdes;
}

bool
FacadeRtpEndpointImpl::checkCryptoAnswer (std::string& answer, std::shared_ptr<SDES>& crypto)
{
	std::shared_ptr<SDES> sdes;
	bool isLocalCrypto = crypto->isSetCrypto() && (crypto->getCrypto() != NULL);

	sdes = fitMediaAnswer (answer, isLocalCrypto);
	// If the sdp answer is cryptocompatible with the endpoint, we need not regenerate the endpoint
	if (isCryptoCompatible (crypto, sdes)) {
		return false;
	} else {
		crypto = sdes;
	}
	return true;
}



void
FacadeRtpEndpointImpl::disconnectForwardSignals ()
{
	connMediaStateChanged.disconnect ();
	connConnectionStateChanged.disconnect ();
	connMediaSessionStarted.disconnect ();
	connMediaSessionTerminated.disconnect ();
	connOnKeySoftLimit.disconnect ();
}

void
FacadeRtpEndpointImpl::connectForwardSignals ()
{

	  connMediaStateChanged = std::dynamic_pointer_cast<BaseRtpEndpointImpl>(rtp_ep)->signalMediaStateChanged.connect([ & ] (
			  MediaStateChanged event) {
		  raiseEvent<MediaStateChanged> (event, shared_from_this(), signalMediaStateChanged);
	  });

	  connConnectionStateChanged = std::dynamic_pointer_cast<BaseRtpEndpointImpl>(rtp_ep)->signalConnectionStateChanged.connect([ & ] (
			  ConnectionStateChanged event) {
		  raiseEvent<ConnectionStateChanged> (event, shared_from_this(), signalConnectionStateChanged);
	  });

	  connMediaSessionStarted = std::dynamic_pointer_cast<BaseRtpEndpointImpl>(rtp_ep)->signalMediaSessionStarted.connect([ & ] (
			  MediaSessionStarted event) {
		  raiseEvent<MediaSessionStarted> (event, shared_from_this(), signalMediaSessionStarted);
	  });

	  connMediaSessionTerminated = std::dynamic_pointer_cast<BaseRtpEndpointImpl>(rtp_ep)->signalMediaSessionTerminated.connect([ & ] (
			  MediaSessionTerminated event) {
		  raiseEvent<MediaSessionTerminated> (event, shared_from_this(), signalMediaSessionTerminated);
	  });

	  connOnKeySoftLimit = rtp_ep->signalOnKeySoftLimit.connect([ & ] (
			  OnKeySoftLimit event) {
		  raiseEvent<OnKeySoftLimit> (event, shared_from_this(), signalOnKeySoftLimit);
	  });

}

void FacadeRtpEndpointImpl::setProperties (std::shared_ptr<SipRtpEndpointImpl> from)
{
	if (rtp_ep != NULL) {
		rtp_ep->setName (from->getName());
		rtp_ep->setSendTagsInEvents (from->getSendTagsInEvents());
		if (audioCapsSet != NULL)
			rtp_ep->setAudioFormat(audioCapsSet);
		rtp_ep->setMaxOutputBitrate(from->getMaxOutputBitrate());
		rtp_ep->setMinOutputBitrate(from->getMinOutputBitrate());
		if (videoCapsSet != NULL)
			rtp_ep->setVideoFormat(videoCapsSet);
		rtp_ep->setMaxAudioRecvBandwidth (from->getMaxAudioRecvBandwidth ());
		rtp_ep->setMaxVideoRecvBandwidth (from->getMaxVideoRecvBandwidth());
		rtp_ep->setMaxVideoSendBandwidth (from->getMaxVideoSendBandwidth());
		rtp_ep->setMinVideoRecvBandwidth (from->getMinVideoRecvBandwidth ());
		if (rembParamsSet != NULL)
			rtp_ep->setRembParams (rembParamsSet);
	}
}

std::shared_ptr<SipRtpEndpointImpl>
FacadeRtpEndpointImpl::renewInternalEndpoint (std::shared_ptr<SipRtpEndpointImpl> newEndpoint)
{
	std::shared_ptr<SipRtpEndpointImpl> tmp = rtp_ep;

	if (rtp_ep != NULL) {
		disconnectForwardSignals ();
	}

	rtp_ep = newEndpoint;
	linkMediaElement(newEndpoint, newEndpoint);
	setProperties (tmp);

	if (rtp_ep != NULL) {
		connectForwardSignals ();
	}

	return tmp;
}

/*----------------- MEthods from BaseRtpEndpoint ---------------*/
int FacadeRtpEndpointImpl::getMinVideoRecvBandwidth ()
{
	return this->rtp_ep->getMinVideoRecvBandwidth();
}

void FacadeRtpEndpointImpl::setMinVideoRecvBandwidth (int minVideoRecvBandwidth)
{
	this->rtp_ep->setMinVideoRecvBandwidth(minVideoRecvBandwidth);
}

int FacadeRtpEndpointImpl::getMinVideoSendBandwidth () {
	return this->rtp_ep->getMinVideoSendBandwidth ();
}

void FacadeRtpEndpointImpl::setMinVideoSendBandwidth (int minVideoSendBandwidth)
{
	this->rtp_ep->setMinVideoSendBandwidth (minVideoSendBandwidth);
}

int FacadeRtpEndpointImpl::getMaxVideoSendBandwidth ()
{
	return this->rtp_ep->getMaxVideoSendBandwidth();
}

void FacadeRtpEndpointImpl::setMaxVideoSendBandwidth (int maxVideoSendBandwidth)
{
	this->rtp_ep->setMaxVideoSendBandwidth(maxVideoSendBandwidth);
}

std::shared_ptr<MediaState> FacadeRtpEndpointImpl::getMediaState ()
{
	return this->rtp_ep->getMediaState();
}
std::shared_ptr<ConnectionState> FacadeRtpEndpointImpl::getConnectionState ()
{
	return this->rtp_ep->getConnectionState();
}

std::shared_ptr<RembParams> FacadeRtpEndpointImpl::getRembParams ()
{
	return this->rtp_ep->getRembParams();
}
void FacadeRtpEndpointImpl::setRembParams (std::shared_ptr<RembParams> rembParams)
{
	this->rtp_ep->setRembParams (rembParams);
	rembParamsSet = rembParams;
}
sigc::signal<void, MediaStateChanged> FacadeRtpEndpointImpl::getSignalMediaStateChanged ()
{
	return this->rtp_ep->signalMediaStateChanged;
}

sigc::signal<void, ConnectionStateChanged> FacadeRtpEndpointImpl::getSignalConnectionStateChanged ()
{
	return this->rtp_ep->signalConnectionStateChanged;
}




/*---------------- Overloaded methods from SDP Endpoint ---------------*/
int FacadeRtpEndpointImpl::getMaxVideoRecvBandwidth ()
{
	return this->rtp_ep->getMaxVideoRecvBandwidth();
}
void FacadeRtpEndpointImpl::setMaxVideoRecvBandwidth (int maxVideoRecvBandwidth)
{
	this->rtp_ep->setMaxVideoRecvBandwidth(maxVideoRecvBandwidth);
}
int FacadeRtpEndpointImpl::getMaxAudioRecvBandwidth ()
{
	return this->rtp_ep->getMaxAudioRecvBandwidth ();
}
void FacadeRtpEndpointImpl::setMaxAudioRecvBandwidth (int maxAudioRecvBandwidth)
{
	this->rtp_ep->setMaxAudioRecvBandwidth(maxAudioRecvBandwidth);
}

/*----------------------- Overloaded methods from Media Element --------------*/
std::map <std::string, std::shared_ptr<Stats>> FacadeRtpEndpointImpl::getStats ()
{
	return this->rtp_ep->getStats();
}
std::map <std::string, std::shared_ptr<Stats>> FacadeRtpEndpointImpl::getStats (
      std::shared_ptr<MediaType> mediaType)
{
	return this->rtp_ep->getStats(mediaType);
}


std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSourceConnections ()
{
	// TODO Verify this behaviour
	//return this->rtp_ep->getSourceConnections();
	return this->srcPt->getSourceConnections();
}
std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSourceConnections (
      std::shared_ptr<MediaType> mediaType)
{
	// TODO: Verifiy this behaviour
	//return this->rtp_ep->getSourceConnections(mediaType);
	return this->srcPt->getSourceConnections(mediaType);
}
std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSourceConnections (
      std::shared_ptr<MediaType> mediaType, const std::string &description)
{
	// TODO: Verify this behaviour
	//return this->rtp_ep->getSourceConnections(mediaType, description);
	return this->srcPt->getSourceConnections(mediaType, description);
}
std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSinkConnections () {
	// TODO Verify this behaviour
	//return this->rtp_ep->getSinkConnections();
	return this->sinkPt->getSinkConnections();
}
std::vector<std::shared_ptr<ElementConnectionData>> FacadeRtpEndpointImpl::getSinkConnections (
      std::shared_ptr<MediaType> mediaType)
{
	//  TODO: verify this behviour
	//return this->rtp_ep->getSinkConnections(mediaType);
	return this->sinkPt->getSinkConnections(mediaType);
}
std::vector<std::shared_ptr<ElementConnectionData>> FacadeRtpEndpointImpl::getSinkConnections (
      std::shared_ptr<MediaType> mediaType, const std::string &description)
{
	// TODO: Verify this behaviour
	//return this->rtp_ep->getSinkConnections(mediaType, description);
	return this->sinkPt->getSinkConnections(mediaType, description);
}
void FacadeRtpEndpointImpl::setAudioFormat (std::shared_ptr<AudioCaps> caps)
{
	this->rtp_ep->setAudioFormat(caps);
}
void FacadeRtpEndpointImpl::setVideoFormat (std::shared_ptr<VideoCaps> caps)
{
	this->rtp_ep->setVideoFormat(caps);
}

void FacadeRtpEndpointImpl::release ()
{
	this->linkMediaElement(NULL, NULL);
	ComposedObjectImpl::release ();

}

std::string FacadeRtpEndpointImpl::getGstreamerDot ()
{
	return this->rtp_ep->getGstreamerDot();
}
std::string FacadeRtpEndpointImpl::getGstreamerDot (std::shared_ptr<GstreamerDotDetails>
                                     details)
{
	return this->rtp_ep->getGstreamerDot(details);
}

void FacadeRtpEndpointImpl::setOutputBitrate (int bitrate)
{
	this->rtp_ep->setOutputBitrate(bitrate);
}

bool FacadeRtpEndpointImpl::isMediaFlowingIn (std::shared_ptr<MediaType> mediaType)
{
	return this->rtp_ep->isMediaFlowingIn(mediaType);
}
bool FacadeRtpEndpointImpl::isMediaFlowingIn (std::shared_ptr<MediaType> mediaType,
                       const std::string &sinkMediaDescription)
{
	return this->rtp_ep->isMediaFlowingIn(mediaType, sinkMediaDescription);
}
bool FacadeRtpEndpointImpl::isMediaFlowingOut (std::shared_ptr<MediaType> mediaType)
{
	return this->rtp_ep->isMediaFlowingOut(mediaType);
}
bool FacadeRtpEndpointImpl::isMediaFlowingOut (std::shared_ptr<MediaType> mediaType,
                        const std::string &sourceMediaDescription)
{
	return this->rtp_ep->isMediaFlowingOut(mediaType, sourceMediaDescription);
}
bool FacadeRtpEndpointImpl::isMediaTranscoding (std::shared_ptr<MediaType> mediaType)
{
	return this->rtp_ep->isMediaTranscoding(mediaType);
}
bool FacadeRtpEndpointImpl::isMediaTranscoding (std::shared_ptr<MediaType> mediaType,
                         const std::string &binName)
{
	return this->rtp_ep->isMediaTranscoding(mediaType, binName);
}

int FacadeRtpEndpointImpl::getMinOuputBitrate ()
{
	return this->rtp_ep->getMinOuputBitrate();
}
void FacadeRtpEndpointImpl::setMinOuputBitrate (int minOuputBitrate)
{
	this->rtp_ep->setMinOuputBitrate(minOuputBitrate);
}

int FacadeRtpEndpointImpl::getMinOutputBitrate ()
{
	return this->rtp_ep->getMinOutputBitrate();
}
void FacadeRtpEndpointImpl::setMinOutputBitrate (int minOutputBitrate)
{
	this->rtp_ep->setMinOutputBitrate(minOutputBitrate);
}

int FacadeRtpEndpointImpl::getMaxOuputBitrate ()
{
	return this->rtp_ep->getMaxOuputBitrate();
}
void FacadeRtpEndpointImpl::setMaxOuputBitrate (int maxOuputBitrate)
{
	this->rtp_ep->setMaxOuputBitrate(maxOuputBitrate);
}

int FacadeRtpEndpointImpl::getMaxOutputBitrate ()
{
	return this->rtp_ep->getMaxOutputBitrate();
}
void FacadeRtpEndpointImpl::setMaxOutputBitrate (int maxOutputBitrate)
{
	this->rtp_ep->setMaxOutputBitrate(maxOutputBitrate);
}


void
FacadeRtpEndpointImpl::Serialize (JsonSerializer &serializer)
{
  if (serializer.IsWriter) {
    try {
      Json::Value v (getId() );

      serializer.JsonValue = v;
    } catch (std::bad_cast &e) {
    }
  } else {
    throw KurentoException (MARSHALL_ERROR,
                            "'SipRtpEndpointImpl' cannot be deserialized as an object");
  }
}



} /* kurento */
