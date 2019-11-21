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
#include <SipRtpEndpointImplFactory.hpp>
#include <jsonrpc/JsonSerializer.hpp>
#include <KurentoException.hpp>
#include <gst/gst.h>
#include <CryptoSuite.hpp>
#include <FacadeRtpEndpointImpl.hpp>
#include <SDES.hpp>
#include <memory>
#include <string>

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
}

FacadeRtpEndpointImpl::~FacadeRtpEndpointImpl()
{
	this->linkMediaElement(NULL, NULL);
}

void
FacadeRtpEndpointImpl::postConstructor ()
{
  ComposedObjectImpl::postConstructor ();

  rtp_ep->postConstructor();
  this->linkMediaElement(rtp_ep, rtp_ep);
}


FacadeRtpEndpointImpl::StaticConstructor FacadeRtpEndpointImpl::staticConstructor;

FacadeRtpEndpointImpl::StaticConstructor::StaticConstructor()
{
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
                           GST_DEFAULT_NAME);
}


/*--------------------- Implementation of SipRtpEndpoint specific features ---------------------------------*/

std::string FacadeRtpEndpointImpl::generateOffer ()
{
	try {
		return this->rtp_ep->generateOffer();
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ALREADY_NEGOTIATED) {
			std::shared_ptr<SipRtpEndpointImpl> newEndpoint = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, getMediaPipeline (), cryptoCache, useIpv6Cache));

			newEndpoint->postConstructor();
			this->linkMediaElement(newEndpoint, newEndpoint);
			rtp_ep = newEndpoint;
			return this->generateOffer();
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
	try {
		return this->rtp_ep->processOffer(offer);
	} catch (kurento::KurentoException& e) {
		if (e.getCode() == SDP_END_POINT_ALREADY_NEGOTIATED) {
			std::shared_ptr<SipRtpEndpointImpl> newEndpoint = std::shared_ptr<SipRtpEndpointImpl>(new SipRtpEndpointImpl (config, getMediaPipeline (), cryptoCache, useIpv6Cache));

			newEndpoint->postConstructor();
			this->linkMediaElement(newEndpoint, newEndpoint);
			rtp_ep = newEndpoint;
			return this->processOffer(offer);
		} else {
			GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s - %s", e.getType().c_str(), e.getMessage().c_str());
			throw e;
		}
	} catch (std::exception& e1) {
		GST_WARNING ("Exception generating offer in SipRtpEndpoint: %s", e1.what());
		throw e1;
	}
}

std::string FacadeRtpEndpointImpl::processAnswer (const std::string &answer)
{
	return this->rtp_ep->processAnswer(answer);
}

std::string FacadeRtpEndpointImpl::getLocalSessionDescriptor ()
{
	return this->rtp_ep->getLocalSessionDescriptor();
}

std::string FacadeRtpEndpointImpl::getRemoteSessionDescriptor ()
{
	return this->rtp_ep->getRemoteSessionDescriptor();
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
	return this->rtp_ep->getSourceConnections();
}
std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSourceConnections (
      std::shared_ptr<MediaType> mediaType)
{
	// TODO: Verifiy this behaviour
	return this->rtp_ep->getSourceConnections(mediaType);
}
std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSourceConnections (
      std::shared_ptr<MediaType> mediaType, const std::string &description)
{
	// TODO: Verify this behaviour
	return this->rtp_ep->getSourceConnections(mediaType, description);
}
std::vector<std::shared_ptr<ElementConnectionData>>
FacadeRtpEndpointImpl::getSinkConnections () {
	// TODO Verify this behaviour
	return this->rtp_ep->getSinkConnections();
}
std::vector<std::shared_ptr<ElementConnectionData>> FacadeRtpEndpointImpl::getSinkConnections (
      std::shared_ptr<MediaType> mediaType)
{
	//  TODO: verify this behviour
	return this->rtp_ep->getSinkConnections(mediaType);
}
std::vector<std::shared_ptr<ElementConnectionData>> FacadeRtpEndpointImpl::getSinkConnections (
      std::shared_ptr<MediaType> mediaType, const std::string &description)
{
	// TODO: Verify this behaviour
	return this->rtp_ep->getSinkConnections(mediaType, description);
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
