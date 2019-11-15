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
}

void
ComposedObjectImpl::postConstructor ()
{
  MediaElementImpl::postConstructor ();

  origElem = getGstreamerElement ();
  element = srcPt->getGstreamerElement();
}

ComposedObjectImpl::StaticConstructor ComposedObjectImpl::staticConstructor;

ComposedObjectImpl::StaticConstructor::StaticConstructor()
{
  GST_DEBUG_CATEGORY_INIT (GST_CAT_DEFAULT, GST_DEFAULT_NAME, 0,
                           GST_DEFAULT_NAME);
}


void ComposedObjectImpl::linkMediaElement(std::shared_ptr<MediaElement> linkSrc, std::shared_ptr<MediaElement> linkSink)
{
	linkMutex.lock();

	// Unlink source and sink from previous composed object
	if (linkedSource != NULL) {
		// Unlink source
		linkedSource->disconnect(sinkPt);
	}
	if (linkedSink != NULL) {
		// Unlink sink
		srcPt->disconnect(linkedSink);
	}

	linkedSource = linkSrc;
	linkedSink = linkSink;

	// Link source and sink from new composed object
	if (linkedSource != NULL) {
		// Link Source
		linkedSource->connect(sinkPt);
	}
	if (linkedSink != NULL) {
		// Link sink
		srcPt->connect(linkedSink);
	}

	linkMutex.unlock();
}


void ComposedObjectImpl::connect (std::shared_ptr<MediaElement> sink)
{
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
  this->sinkPt->connect (sink, mediaType, DEFAULT, DEFAULT);
}

void ComposedObjectImpl::connect (std::shared_ptr<MediaElement> sink,
                                std::shared_ptr<MediaType> mediaType,
                                const std::string &sourceMediaDescription)
{
   this->sinkPt->connect (sink, mediaType, sourceMediaDescription, DEFAULT);
}

void ComposedObjectImpl::disconnect (std::shared_ptr<MediaElement> sink)
{
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
	this->sinkPt->disconnect (sink, mediaType, DEFAULT, DEFAULT);
}

void ComposedObjectImpl::disconnect (std::shared_ptr<MediaElement> sink,
                                std::shared_ptr<MediaType> mediaType,
                                const std::string &sourceMediaDescription)
{
	this->sinkPt->disconnect (sink, mediaType, sourceMediaDescription, DEFAULT);
}




} /* kurento */
