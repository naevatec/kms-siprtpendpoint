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
#include "ComposedObjectImpl.hpp"
#include <MediaElementImpl.hpp>
#include <ElementConnectionData.hpp>
#include <MediaPipelineImpl.hpp>
#include <gst/gst.h>
#include <jsonrpc/JsonSerializer.hpp>
#include <KurentoException.hpp>
#include <gst/gst.h>
#include <memory>
#include <string>

#define GST_CAT_DEFAULT kurento_composed_object_impl
GST_DEBUG_CATEGORY_STATIC (GST_CAT_DEFAULT);
#define GST_DEFAULT_NAME "ComposedObjectImpl"

#define FACTORY_NAME "passthrough"

/* In theory the Master key can be shorter than the maximum length, but
 * the GStreamer's SRTP plugin enforces using the maximum length possible
 * for the type of cypher used (in file 'gstsrtpenc.c'). So, KMS also expects
 * that the maximum Master key size is used. */
#define KMS_SRTP_CIPHER_AES_CM_128_SIZE  ((gsize)30)
#define KMS_SRTP_CIPHER_AES_CM_256_SIZE  ((gsize)46)

namespace kurento
{

const static std::string DEFAULT = "default";


ComposedObjectImpl::ComposedObjectImpl (const boost::property_tree::ptree &conf,
                                  std::shared_ptr<MediaPipeline> mediaPipeline)
  : MediaElementImpl (conf,
                         std::dynamic_pointer_cast<MediaObjectImpl> (mediaPipeline), FACTORY_NAME)
{

  sinkPt = std::shared_ptr<PassThroughImpl>(new PassThroughImpl(config, mediaPipeline));
  srcPt = std::shared_ptr<PassThroughImpl>(new PassThroughImpl(config, mediaPipeline));
  linkedSource = NULL;
  linkedSink = NULL;
  origElem = NULL;
}

ComposedObjectImpl::~ComposedObjectImpl()
{
	element = origElem;

	disconnectBridgeSignals ();
}




void
ComposedObjectImpl::disconnectBridgeSignals ()
{
	connElementConnectedSrc.disconnect ();
	connElementConnectedSink.disconnect ();
	//connElementDisconnectedSrc.disconnect ();
	//connElementDisconnectedSink.disconnect ();
	connErrorSrc.disconnect ();
	connErrorSink.disconnect ();
}

void
ComposedObjectImpl::disconnectElementSrcSignals ()
{
	connMediaTranscodingStateChangeSrc.disconnect ();
	connMediaFlowOutStateChange.disconnect ();
	connErrorlinkedSrc.disconnect ();
}

// This method should only be called from linkElement with the mutex held
void
ComposedObjectImpl::connectElementSrcSignals ()
{
	std::weak_ptr<MediaObject> wt = shared_from_this ();

	if (linkedSource == NULL)
		return;

	  connMediaTranscodingStateChangeSrc = std::dynamic_pointer_cast<MediaElementImpl>(linkedSource)->signalMediaTranscodingStateChange.connect([ &, wt ] (
			  MediaTranscodingStateChange event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  raiseEvent<MediaTranscodingStateChange> (event, sth, signalMediaTranscodingStateChange);
	  });

	  connMediaFlowOutStateChange = std::dynamic_pointer_cast<MediaElementImpl>(linkedSource)->signalMediaFlowOutStateChange.connect([ &, wt ] (
			  MediaFlowOutStateChange event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  raiseEvent<MediaFlowOutStateChange> (event, sth, signalMediaFlowOutStateChange);
	  });

	    connErrorlinkedSrc = std::dynamic_pointer_cast<MediaElementImpl>(linkedSource)->signalError.connect([ &, wt ] (
				  Error event) {
			  std::shared_ptr<MediaObject> sth = wt.lock ();
			  if (!sth)
				  return;

			  raiseEvent<Error> (event, sth, signalError);
		});

}

void
ComposedObjectImpl::disconnectElementSinkSignals ()
{
	connMediaTranscodingStateChangeSink.disconnect ();
	connMediaFlowInStateChange.disconnect ();
	if (linkedSink != linkedSource)
		connErrorlinkedSink.disconnect ();
}

void
ComposedObjectImpl::connectElementSinkSignals ()
{
	std::weak_ptr<MediaObject> wt = shared_from_this ();

	if (linkedSink == NULL)
		return;

	  connMediaTranscodingStateChangeSink = std::dynamic_pointer_cast<MediaElementImpl>(linkedSink)->signalMediaTranscodingStateChange.connect([ &, wt ] (
			  MediaTranscodingStateChange event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  raiseEvent<MediaTranscodingStateChange> (event, sth, signalMediaTranscodingStateChange);
	  });

	  connMediaFlowInStateChange = std::dynamic_pointer_cast<MediaElementImpl>(linkedSink)->signalMediaFlowInStateChange.connect([ &, wt ] (
			  MediaFlowInStateChange event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  raiseEvent<MediaFlowInStateChange> (event, sth, signalMediaFlowInStateChange);
	  });

		if (linkedSink != linkedSource) {
		    connErrorlinkedSink = std::dynamic_pointer_cast<MediaElementImpl>(linkedSink)->signalError.connect([ &, wt ] (
					  Error event) {
				  std::shared_ptr<MediaObject> sth = wt.lock ();
				  if (!sth)
					  return;

				  raiseEvent<Error> (event, sth, signalError);
			});
		}

}


void
ComposedObjectImpl::connectBridgeSignals ()
{
	std::weak_ptr<MediaObject> wt = shared_from_this ();

	  connElementConnectedSrc = std::dynamic_pointer_cast<MediaElementImpl>(srcPt)->signalElementConnected.connect([ &, wt ] (
			  ElementConnected event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  //We don't raise internal connection events'
		  if (event.getSource()==srcPt)
			  return;
		  if (event.getSink () == sinkPt)
			  return;
		  raiseEvent<ElementConnected> (event, sth, signalElementConnected);
	  });

	  connElementConnectedSink = std::dynamic_pointer_cast<MediaElementImpl>(sinkPt)->signalElementConnected.connect([ &, wt ] (
			  ElementConnected event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  //We don't raise internal connection events'
		  if (event.getSource()==srcPt)
			  return;
		  if (event.getSink () == sinkPt)
			  return;
		  raiseEvent<ElementConnected> (event, sth, signalElementConnected);
	  });

	/*  connElementDisconnectedSrc = std::dynamic_pointer_cast<MediaElementImpl>(srcPt)->signalElementDisconnected.connect([ &, wt ] (
			  ElementDisconnected event) {
		  try {
			  std::shared_ptr<MediaObject> sth = wt.lock ();
			  if (!sth)
				  return;

			  //We don't raise internal connection events'
			  if (event.getSource()==srcPt)
				  return;
			  if (event.getSink () == sinkPt)
				  return;
			  raiseEvent<ElementDisconnected> (event, sth, signalElementDisconnected);
		  } catch (const std::bad_weak_ptr &e) {
		    // shared_from_this()
		  }
	  });

	  connElementDisconnectedSink = std::dynamic_pointer_cast<MediaElementImpl>(sinkPt)->signalElementDisconnected.connect([ &, wt ] (
			  ElementDisconnected event) {
		  try {
			  std::shared_ptr<MediaObject> sth = wt.lock ();
			  if (!sth)
				  return;

			  //We don't raise internal connection events'
			  if (event.getSource()==srcPt)
				  return;
			  if (event.getSink () == sinkPt)
				  return;
			  raiseEvent<ElementDisconnected> (event, sth, signalElementDisconnected);
		  } catch (const std::bad_weak_ptr &e) {
			    // shared_from_this()
		  }
	  }); */

	  connErrorSrc = std::dynamic_pointer_cast<MediaElementImpl>(srcPt)->signalError.connect([ &, wt ] (
			  Error event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  raiseEvent<Error> (event, sth, signalError);
	  });

	  connErrorSink = std::dynamic_pointer_cast<MediaElementImpl>(sinkPt)->signalError.connect([ &, wt ] (
			  Error event) {
		  std::shared_ptr<MediaObject> sth = wt.lock ();
		  if (!sth)
			  return;

		  raiseEvent<Error> (event, sth, signalError);
	  });
}


bool ComposedObjectImpl::connect (const std::string &eventType, std::shared_ptr<EventHandler> handler)
{
    std::weak_ptr<EventHandler> wh = handler;

    if ("ElementConnected" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<ElementConnected> (signalElementConnected, wh);
	    handler->setConnection (conn);
	    return true;
	}

	if ("ElementDisconnected" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<ElementDisconnected> (signalElementDisconnected, wh);
	    handler->setConnection (conn);
	    return true;
	}

	if ("MediaFlowOutStateChange" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<MediaFlowOutStateChange> (signalMediaFlowOutStateChange, wh);
	    handler->setConnection (conn);
	    return true;
	}

    if ("MediaFlowInStateChange" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<MediaFlowInStateChange> (signalMediaFlowInStateChange, wh);
	    handler->setConnection (conn);
	    return true;
    }

    if ("MediaTranscodingStateChange" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<MediaTranscodingStateChange> (signalMediaTranscodingStateChange, wh);
	    handler->setConnection (conn);
	    return true;
    }

	if ("Error" == eventType) {
    	sigc::connection conn = connectEventToExternalHandler<Error> (signalError, wh);
	    handler->setConnection (conn);
	    return true;
	}

    return false;
}


void
ComposedObjectImpl::postConstructor ()
{
  MediaElementImpl::postConstructor ();

  // FIXME: Consider instead of this "hack" to build a gstreamer bin that contains the passthrough elements and the 
  // dynamically changed SipRtpEndpoint, some kind of "subpipeline"
  origElem = getGstreamerElement ();
  element = srcPt->getGstreamerElement();

  connectBridgeSignals ();
}

ComposedObjectImpl::StaticConstructor ComposedObjectImpl::staticConstructor;

ComposedObjectImpl::StaticConstructor::StaticConstructor()
{
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
                           GST_DEFAULT_NAME);
}


void ComposedObjectImpl::linkMediaElement(std::shared_ptr<MediaElement> linkSrc, std::shared_ptr<MediaElement> linkSink)
{
	GST_DEBUG ("Linking object to facade");
	std::unique_lock<std::recursive_mutex> linkLock (linkMutex);

	// Unlink source and sink from previous composed object
	if (linkedSource != NULL) {
		// Unlink source
		linkedSource->disconnect(sinkPt);
		
		disconnectElementSrcSignals ();
	}
	if (linkedSink != NULL) {
		// Unlink sink
		srcPt->disconnect(linkedSink);

		disconnectElementSinkSignals ();
	}

	linkedSource = linkSrc;
	linkedSink = linkSink;

	// Link source and sink from new composed object
	if (linkedSource != NULL) {
		// Link Source
		linkedSource->connect(sinkPt);

		connectElementSrcSignals ();
	}
	if (linkedSink != NULL) {
		// Link sink
		srcPt->connect(linkedSink);

		connectElementSinkSignals ();
	}
}


void ComposedObjectImpl::connect (std::shared_ptr<MediaElement> sink)
{
	GST_DEBUG ("Connecting (A+V+D) facade to sink");

	// TODO: signals emitted from sinkPt due to connection changes should be
	// elevated to be re-emitted from this Composed Object
  // Until mediaDescriptions are really used, we just connect audio an video
  this->sinkPt->connect(sink, std::make_shared<MediaType>(MediaType::AUDIO), DEFAULT,
          DEFAULT);
  this->sinkPt->connect(sink, std::make_shared<MediaType>(MediaType::VIDEO), DEFAULT,
          DEFAULT);
  this->sinkPt->connect(sink, std::make_shared<MediaType>(MediaType::DATA), DEFAULT, DEFAULT);
}

void ComposedObjectImpl::connect (std::shared_ptr<MediaElement> sink,
                                std::shared_ptr<MediaType> mediaType)
{
	GST_DEBUG ("Connecting (%s) facade to sink", mediaType->getString().c_str());
  this->sinkPt->connect (sink, mediaType, DEFAULT, DEFAULT);
}

void ComposedObjectImpl::connect (std::shared_ptr<MediaElement> sink,
                                std::shared_ptr<MediaType> mediaType,
                                const std::string &sourceMediaDescription)
{
	GST_DEBUG ("Connecting (%s) facade (%s) to sink", mediaType->getString().c_str(), sourceMediaDescription.c_str());

   this->sinkPt->connect (sink, mediaType, sourceMediaDescription, DEFAULT);
}

void ComposedObjectImpl::disconnect (std::shared_ptr<MediaElement> sink)
{
	GST_DEBUG ("Disconnecting (A+V+D) facade from sink");

  // Until mediaDescriptions are really used, we just connect audio an video
  this->sinkPt->disconnect(sink, std::make_shared<MediaType>(MediaType::AUDIO), DEFAULT,
          DEFAULT);
  this->sinkPt->disconnect(sink, std::make_shared<MediaType>(MediaType::VIDEO), DEFAULT,
          DEFAULT);
  this->sinkPt->disconnect(sink, std::make_shared<MediaType>(MediaType::DATA), DEFAULT, DEFAULT);
}

void ComposedObjectImpl::disconnect (std::shared_ptr<MediaElement> sink,
                                std::shared_ptr<MediaType> mediaType)
{
	GST_DEBUG ("Disconnecting (%s) facade to sink", mediaType->getString().c_str());
	this->sinkPt->disconnect (sink, mediaType, DEFAULT, DEFAULT);
}

void ComposedObjectImpl::disconnect (std::shared_ptr<MediaElement> sink,
                                std::shared_ptr<MediaType> mediaType,
                                const std::string &sourceMediaDescription)
{
	GST_DEBUG ("Connecting (%s) facade (%s) to sink", mediaType->getString().c_str(), sourceMediaDescription.c_str());
	this->sinkPt->disconnect (sink, mediaType, sourceMediaDescription, DEFAULT);
}

void ComposedObjectImpl::prepareSinkConnection (std::shared_ptr<MediaElement> src,
                                      std::shared_ptr<MediaType> mediaType,
                                      const std::string &sourceMediaDescription,
                                      const std::string &sinkMediaDescription)
{ 
	// This method shouldn't be needed if it not were to the implementation of MediaElementImpl::disconnectAll that instead 
	// of calling the virtual method disconnect on each sink, it calls the MediaElementImpl::disconnect methods, making it 
	// impossible for the overloading done in this module to work, and causing an infinite loop trying to disconnect
	//
	// Well, in fact the problem is also caused by the fact that as we use intermediate PassThrough objects when connecting
	// a MediaElement to this SipRtpEndpoint where another mediaElement was previously connected to this same SipRtpEndpoint 
	// The connection process leaves a dangling sink connection on previous MediaElmenent. Then, when a disconnectAll is called
	// on that MediaElement, it will try to disconnect that dangling sink connection, but as it calls MediaElementImpl::disconnect
	// instead of this object overloaded method, it causes an inifinite loop
	std::vector<std::shared_ptr<ElementConnectionData>> connections;

	GST_DEBUG ("Preparing Connecting (%s) facade (%s) to sink", mediaType->getString().c_str(), sourceMediaDescription.c_str());

	//Check if connection present for this object (not for the srcPt object)
	connections = MediaElementImpl::getSourceConnections(mediaType, sinkMediaDescription);

	// And if so, disconnect them so that all MediaElements get to a clean state
	if (!connections.empty () ) {
    	std::shared_ptr <ElementConnectionData> connection = connections.at (0);
		GST_DEBUG("Removing Connection source %s, connection sink %s", connection->getSource()->getName().c_str(), connection->getSink()->getName().c_str());
    	connection->getSource()->disconnect (connection->getSink (), mediaType,
                                         sourceMediaDescription,
                                         connection->getSinkDescription () );
  	}


}



} /* kurento */
