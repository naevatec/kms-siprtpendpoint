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
#ifndef __COMPOSED_OBJECT_IMPL_HPP__
#define __COMPOSED_OBJECT_IMPL_HPP__

#include <MediaElementImpl.hpp>
#include <PassThroughImpl.hpp>
#include <EventHandler.hpp>

namespace kurento
{

class MediaPipeline;

class ComposedObjectImpl;

void Serialize (std::shared_ptr<ComposedObjectImpl> &object,
                JsonSerializer &serializer);

class ComposedObjectImpl : public MediaElementImpl
{

public:

	ComposedObjectImpl (const boost::property_tree::ptree &conf,
                   std::shared_ptr<MediaPipeline> mediaPipeline);

  virtual ~ComposedObjectImpl ();


  void linkMediaElement (std::shared_ptr<MediaElement> linkSrc, std::shared_ptr<MediaElement> linkSink);

  // Connectivity methods needed to override to make the composition of objects

  void connect (std::shared_ptr<MediaElement> sink) override;
  void connect (std::shared_ptr<MediaElement> sink,
                        std::shared_ptr<MediaType> mediaType) override;
  void connect (std::shared_ptr<MediaElement> sink,
                        std::shared_ptr<MediaType> mediaType,
                        const std::string &sourceMediaDescription) override;


  void disconnect (std::shared_ptr<MediaElement> sink) override;
  void disconnect (std::shared_ptr<MediaElement> sink,
                           std::shared_ptr<MediaType> mediaType) override;
  void disconnect (std::shared_ptr<MediaElement> sink,
                           std::shared_ptr<MediaType> mediaType,
                           const std::string &sourceMediaDescription) override;


protected:
  virtual void postConstructor () override;
  std::shared_ptr<PassThroughImpl> sinkPt;
  std::shared_ptr<PassThroughImpl> srcPt;

private:

  GstElement* origElem;
  std::shared_ptr<MediaElement> linkedSource;
  std::shared_ptr<MediaElement> linkedSink;

  std::recursive_mutex linkMutex;

  class StaticConstructor
  {
  public:
    StaticConstructor();
  };

  static StaticConstructor staticConstructor;

};

} /* kurento */

#endif /*  __COMPOSED_OBJECT_IMPL_HPP__ */
