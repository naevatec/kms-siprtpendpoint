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

#define BOOST_TEST_STATIC_LINK
#define BOOST_TEST_PROTECTED_VIRTUAL

#include <boost/test/included/unit_test.hpp>
#include <MediaPipelineImpl.hpp>
#include <objects/FacadeRtpEndpointImpl.hpp>
//#include <IceCandidate.hpp>
#include <mutex>
#include <condition_variable>
#include <ModuleManager.hpp>
#include <KurentoException.hpp>
#include <MediaSet.hpp>
#include <MediaElementImpl.hpp>
#include <ConnectionState.hpp>
#include <MediaState.hpp>
//#include <SDES.hpp>
//#include <CryptoSuite.hpp>

#include <sigc++/connection.h>

#include <RegisterParent.hpp>

using namespace kurento;
using namespace boost::unit_test;

boost::property_tree::ptree config;
std::string mediaPipelineId;
ModuleManager moduleManager;

struct GF {
  GF();
  ~GF();
};

BOOST_GLOBAL_FIXTURE (GF);

GF::GF()
{
  boost::property_tree::ptree ac, audioCodecs, vc, videoCodecs;
  gst_init(nullptr, nullptr);

//  moduleManager.loadModulesFromDirectories ("./src/server:../../kms-omni-build:../../src/server:../../../../kms-omni-build");
  moduleManager.loadModulesFromDirectories ("../../src/server:./");

  config.add ("configPath", "../../../tests" );
  config.add ("modules.kurento.SdpEndpoint.numAudioMedias", 1);
  config.add ("modules.kurento.SdpEndpoint.numVideoMedias", 1);

  ac.put ("name", "opus/48000/2");
  audioCodecs.push_back (std::make_pair ("", ac) );
  config.add_child ("modules.kurento.SdpEndpoint.audioCodecs", audioCodecs);

  vc.put ("name", "VP8/90000");
  videoCodecs.push_back (std::make_pair ("", vc) );
  config.add_child ("modules.kurento.SdpEndpoint.videoCodecs", videoCodecs);

  mediaPipelineId = moduleManager.getFactory ("MediaPipeline")->createObject (
                      config, "",
                      Json::Value() )->getId();
}

GF::~GF()
{
  MediaSet::deleteMediaSet();
}

#define CRYPTOKEY "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7"

//static std::shared_ptr<SDES> getCrypto ()
//{
//	std::shared_ptr<kurento::SDES> crypto = std::make_shared<kurento::SDES>(new kurento::SDES());
//	std::shared_ptr<kurento::CryptoSuite> cryptoSuite = std::make_shared<kurento::CryptoSuite> (new kurento::CryptoSuite (kurento::CryptoSuite::AES_128_CM_HMAC_SHA1_80));
//
//	crypto->setCrypto(cryptoSuite);
//	crypto->setKey(CRYPTOKEY);
//	return crypto;
//}

static std::shared_ptr <MediaElementImpl>
createRtpEndpoint (bool useIpv6, bool useCrypto)
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;
  constructorParams ["useIpv6"] = useIpv6;
//  if (useCrypto) {
//	  constructorParams ["crypto"] = getCrypto ()->;
//  }

  rtpEndpoint = moduleManager.getFactory ("RtpEndpoint")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <MediaElementImpl> (rtpEndpoint);
}


static std::shared_ptr <FacadeRtpEndpointImpl>
createSipRtpEndpoint (bool useIpv6, bool useCrypto)
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;
  constructorParams ["useIpv6"] = useIpv6;
//  if (useCrypto) {
//	  constructorParams ["crypto"] = getCrypto ()->;
//  }

  rtpEndpoint = moduleManager.getFactory ("SipRtpEndpoint")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <FacadeRtpEndpointImpl> (rtpEndpoint);
}

static void
releaseSipRtpEndpoint (std::shared_ptr<FacadeRtpEndpointImpl> &ep)
{
  ep->release();
//  std::string id = ep->getId();
//
//  ep.reset();
//  MediaSet::getMediaSet ()->release (id);
}

static void
releaseRtpEndpoint (std::shared_ptr<MediaElementImpl> &ep)
{
  ep->release();
//  std::string id = ep->getId();
//
//  ep.reset();
//  MediaSet::getMediaSet ()->release (id);
}


static void
source_connections_impl ()
{
  bool useIpv6 = FALSE;
  bool useCrypto = FALSE;
  std::shared_ptr <MediaElementImpl> rtpEp1 = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> rtpEp2 = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> rtpEp3 = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> sipRtp = createSipRtpEndpoint (useIpv6, useCrypto);

  sipRtp->connect (rtpEp1);
  sipRtp->connect (rtpEp3);
  sipRtp->connect (rtpEp3);

  rtpEp1->connect (sipRtp);
  rtpEp2->connect (sipRtp);
  rtpEp3->connect (sipRtp);

  releaseRtpEndpoint (rtpEp1);
  releaseRtpEndpoint (rtpEp2);
  releaseRtpEndpoint (rtpEp3);
  releaseSipRtpEndpoint (sipRtp);
}


static void
source_connections()
{
	  BOOST_TEST_MESSAGE ("Start test: test source connections on several sources");
	  source_connections_impl ();
}


test_suite *
init_unit_test_suite ( int , char *[] )
{
  test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpoint" );

  test->add (BOOST_TEST_CASE ( source_connections ), 0, /* timeout */ 5);
  return test;
}
