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
  config.add ("modules.siprtp.SipRtpEndpoint.audioCodecs", "PCMU/8000,G729/8000,DVI4/22050");
  config.add ("modules.siprtp.SipRtpEndpoint.videoCodecs", "VP8/90000");
  config.add ("modules.kurento.SdpEndpoint.numAudioMedias", 1);
  config.add ("modules.kurento.SdpEndpoint.numVideoMedias", 1);

  mediaPipelineId = moduleManager.getFactory ("MediaPipeline")->createObject (
                      config, "",
                      Json::Value() )->getId();
}

GF::~GF()
{
  MediaSet::deleteMediaSet();
}

static std::shared_ptr <FacadeRtpEndpointImpl>
createRtpEndpoint (bool useIpv6, bool useCrypto)
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
releaseRtpEndpoint (std::shared_ptr<FacadeRtpEndpointImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}


static bool
check_audio_codecs (std::string sdp)
{
  std::stringstream ss(sdp);
  std::string to;

  while (std::getline(ss,to,'\n')) {
    if (to.rfind("m=audio ", 0) == 0) {
      if (to.find ("RTP/AVPF 0 18 17") != std::string::npos) {
        return true;
      } else {
        return false;
      }
    }
  }
  return false;
}

static bool
check_video_codecs (std::string sdp)
{
  return sdp.find("VP8/90000") != std::string::npos ;
}


static void
codecs_config ()
{
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (false, false);

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();

    if (!check_video_codecs (offer) || !check_audio_codecs (offer)) {
  	 BOOST_ERROR("Expected codec not found in SDP offer");
    }
  } catch (kurento::KurentoException& e) {
	 BOOST_ERROR("Unwanted Kurento Exception managing offer/answer");
  }
  releaseRtpEndpoint (rtpEpOfferer);
}



test_suite *
init_unit_test_suite ( int , char *[] )
{
  test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpoint" );

  test->add (BOOST_TEST_CASE ( &codecs_config ), 0, /* timeout */ 20);
  
  return test;
}
