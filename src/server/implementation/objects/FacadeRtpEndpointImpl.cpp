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
#include <memory>
#include <string>
#include <sstream>
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
                                  std::shared_ptr<SDES> crypto, bool useIpv6)
  : ComposedObjectImpl (conf,
                         std::dynamic_pointer_cast<MediaPipeline> (mediaPipeline)), cryptoCache (crypto), useIpv6Cache (useIpv6)
{
  rtp_ep = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, mediaPipeline, crypto, useIpv6));
  audioCapsSet = NULL;
  videoCapsSet = NULL;
  rembParamsSet = NULL;
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
		GST_DEBUG("GenerateOffer: \n%s", offer.c_str());
		return offer;
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ALREADY_NEGOTIATED) {
			GST_INFO("Consecutive generate Offer on %s, cloning endpoint", this->getId().c_str());
			std::shared_ptr<SipRtpEndpointImpl> newEndpoint = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, getMediaPipeline (), cryptoCache, useIpv6Cache));

			newEndpoint->postConstructor();
			renewInternalEndpoint (newEndpoint);
			offer = newEndpoint->generateOffer();
			GST_DEBUG("2nd try GenerateOffer: \n%s", offer.c_str());
			GST_INFO("Consecutive generate Offer on %s, endpoint cloned and offer processed", this->getId().c_str());
			return offer;
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}
}

std::string FacadeRtpEndpointImpl::processOffer (const std::string &offer)
{
	std::string answer;
	std::shared_ptr<SDES> cryptoToUse = cryptoCache;

	try {
		if (isSDPCompatible (offer)) {
			answer = this->rtp_ep->processOffer(offer);
			GST_DEBUG ("ProcessOffer: \n%s", answer.c_str());
			return answer;
		}
		GST_INFO ("SRTP/RTP not compatible offer received. Adapting");
		if (rtp_ep->isEncrypted ())
			cryptoToUse = std::shared_ptr<SDES>(new SDES ());
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ALREADY_NEGOTIATED) {
			GST_INFO("Consecutive process Offer on %s, cloning endpoint", this->getId().c_str());
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}
	std::shared_ptr<SipRtpEndpointImpl> newEndpoint = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, getMediaPipeline (), cryptoToUse, useIpv6Cache));

	newEndpoint->postConstructor();
	renewInternalEndpoint (newEndpoint);
	answer = newEndpoint->processOffer(offer);
	GST_DEBUG ("2nd try ProcessOffer: \n%s", answer.c_str());
	GST_INFO("Consecutive process Offer on %s, endpoint cloned and offer processed", this->getId().c_str());
	return answer;
}

std::string FacadeRtpEndpointImpl::processAnswer (const std::string &answer)
{
	std::string result;
	std::shared_ptr<SDES> cryptoToUse = cryptoCache;

	try {
		if (isSDPCompatible (answer)) {
			result = this->rtp_ep->processAnswer(answer);
			GST_DEBUG ("ProcessAnswer: \n%s", result.c_str());
			return result;
		}
		GST_INFO ("SRTP/RTP not compatible answer received. Adapting");
		if (rtp_ep->isEncrypted ())
			cryptoToUse = std::shared_ptr<SDES>(new SDES ());
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ANSWER_ALREADY_PROCCESED) {
			GST_INFO("Consecutive process Answer on %s, cloning endpoint", this->getId().c_str());
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}
	std::shared_ptr<SipRtpEndpointImpl> newEndpoint = rtp_ep->getCleanEndpoint (config, getMediaPipeline (), cryptoToUse, useIpv6Cache, answer);
	std::string unusedOffer;
	std::shared_ptr<SipRtpEndpointImpl> oldEndpoint;

	newEndpoint->postConstructor();
	oldEndpoint = renewInternalEndpoint (newEndpoint);
	unusedOffer = newEndpoint->generateOffer();
	GST_DEBUG ("2nd try ProcessAnswer - Unused offer: \n%s", unusedOffer.c_str());
	result = newEndpoint->processAnswer(answer);
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

static bool
isSDPEncryptedProfile (std::string sdp)
{
	// Perhaps we could use GStreamer to parse SDP, but there is no point in decoding the entire SDP
	std::istringstream iss(sdp);

	std::string line;
	while (std::getline(iss, line))
	{
		// Search for an m= line
	    if (line.rfind ("m=", 0) == 0) {
	    	// We assume all media lines use the same protocols
	    	if (line.find ("RTP/SAVP ") != std::string::npos)
	    		return TRUE;
	    	else if (line.find ("RTP/SAVPF ") != std::string::npos)
	    		return TRUE;
	    }
	}
	return FALSE;
}

bool
FacadeRtpEndpointImpl::isSDPCompatible (std::string sdp)
{
	bool encryptedEp = this->rtp_ep->isEncrypted ();
	bool encryptedSDP = isSDPEncryptedProfile (sdp);

	// They are compatible if both values are the same
	return encryptedEp == encryptedSDP;
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

/*virtual void release () override; */

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
