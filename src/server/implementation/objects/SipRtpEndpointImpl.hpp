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
#ifndef __SIP_RTP_ENDPOINT_IMPL_HPP__
#define __SIP_RTP_ENDPOINT_IMPL_HPP__

#include "BaseRtpEndpointImpl.hpp"
#include "SipRtpEndpoint.hpp"
#include <EventHandler.hpp>

namespace kurento
{

class MediaPipeline;

class SipRtpEndpointImpl;

void Serialize (std::shared_ptr<SipRtpEndpointImpl> &object,
                JsonSerializer &serializer);

class SipRtpEndpointImpl : public BaseRtpEndpointImpl, public virtual SipRtpEndpoint
{

public:

  SipRtpEndpointImpl (const boost::property_tree::ptree &conf,
                   std::shared_ptr<MediaPipeline> mediaPipeline,
                   std::shared_ptr<SDES> crypto, bool useIpv6);

  virtual ~SipRtpEndpointImpl ();

  sigc::signal<void, OnKeySoftLimit> signalOnKeySoftLimit;

  std::string generateOffer () override;
  std::string processOffer (const std::string &offer) override;
  std::string processAnswer (const std::string &answer) override;
  std::string getLocalSessionDescriptor () override;
  std::string getRemoteSessionDescriptor () override;


  /* Next methods are automatically implemented by code generator */
  using BaseRtpEndpointImpl::connect;
  virtual bool connect (const std::string &eventType,
                        std::shared_ptr<EventHandler> handler) override;

  virtual void invoke (std::shared_ptr<MediaObjectImpl> obj,
                       const std::string &methodName, const Json::Value &params,
                       Json::Value &response) override;

  virtual void Serialize (JsonSerializer &serializer) override;

protected:
  virtual void postConstructor () override;

private:

  gulong handlerOnKeySoftLimit = 0;
  void onKeySoftLimit (gchar *media);

  class StaticConstructor
  {
  public:
    StaticConstructor();
  };

  static StaticConstructor staticConstructor;

};

} /* kurento */

#endif /*  __SIP_RTP_ENDPOINT_IMPL_HPP__ */
