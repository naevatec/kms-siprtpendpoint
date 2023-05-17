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

#define PUBLICIPV4 "127.1.1.1"
#define CFGPUBLICIPV4 "127.1.1.2"
#define PUBLICIPV6 "2001:0db8:0000:0000:0000:ff00:0042:8329"
#define CFGPUBLICIPV6 "2001:0db8:0000:0000:0000:ff00:0042:7238"

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
createRtpEndpointPublicIPv4 ()
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;
  constructorParams ["useIpv6"] = false;
  constructorParams ["publicIPv4"] = PUBLICIPV4;
//  if (useCrypto) {
//	  constructorParams ["crypto"] = getCrypto ()->;
//  }

  rtpEndpoint = moduleManager.getFactory ("SipRtpEndpoint")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <FacadeRtpEndpointImpl> (rtpEndpoint);
}

static std::shared_ptr <FacadeRtpEndpointImpl>
createRtpEndpointPublicIPv6 ()
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;
  constructorParams ["useIpv6"] = true;
  constructorParams ["publicIPv6"] = PUBLICIPV6;
//  if (useCrypto) {
//	  constructorParams ["crypto"] = getCrypto ()->;
//  }

  rtpEndpoint = moduleManager.getFactory ("SipRtpEndpoint")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <FacadeRtpEndpointImpl> (rtpEndpoint);
}

static std::shared_ptr <FacadeRtpEndpointImpl>
createRtpEndpoint (bool useIpv6)
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


static gboolean
check_public_ip (const std::string sdp, const std::string public_ip)
{
  return (sdp.find (public_ip) != std::string::npos);
}

static void
no_public_ip ()
{
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (false);

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();

    if (check_public_ip (offer, PUBLICIPV4) || check_public_ip (offer, PUBLICIPV6)) {
  	 BOOST_ERROR("Public IP not expected in offer");
    }
  } catch (kurento::KurentoException& e) {
	 BOOST_ERROR("Unwanted Kurento Exception managing offer/answer");
  }
  releaseRtpEndpoint (rtpEpOfferer);
}

static void
public_ipv4 ()
{
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpointPublicIPv4 ();

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();

    if (!check_public_ip (offer, PUBLICIPV4) || check_public_ip (offer, PUBLICIPV6)) {
  	 BOOST_ERROR("Public IP not expected in offer");
    }
  } catch (kurento::KurentoException& e) {
	 BOOST_ERROR("Unwanted Kurento Exception managing offer/answer");
  }
  releaseRtpEndpoint (rtpEpOfferer);
}

static void
public_ipv6 ()
{
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpointPublicIPv6 ();

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();

    if (check_public_ip (offer, PUBLICIPV4) || !check_public_ip (offer, PUBLICIPV6)) {
  	 BOOST_ERROR("Public IP not expected in offer");
    }
  } catch (kurento::KurentoException& e) {
	 BOOST_ERROR("Unwanted Kurento Exception managing offer/answer");
  }
  releaseRtpEndpoint (rtpEpOfferer);
}


static void
public_ipv4_cfg ()
{
  config.add ("modules.siprtp.SipRtpEndpoint.publicIPv4", CFGPUBLICIPV4);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (false);

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();

    if (!check_public_ip (offer, CFGPUBLICIPV4)) {
  	 BOOST_ERROR("Public IP not expected in offer");
    }
  } catch (kurento::KurentoException& e) {
	 BOOST_ERROR("Unwanted Kurento Exception managing offer/answer");
  }
  releaseRtpEndpoint (rtpEpOfferer);
}

static void
public_ipv6_cfg ()
{
  config.add ("modules.siprtp.SipRtpEndpoint.publicIPv6", CFGPUBLICIPV6);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (true);

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();

    if (!check_public_ip (offer, CFGPUBLICIPV6)) {
  	 BOOST_ERROR("Public IP not expected in offer");
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

  test->add (BOOST_TEST_CASE ( &no_public_ip ), 0, /* timeout */ 15000);
  test->add (BOOST_TEST_CASE ( &public_ipv4 ), 0, /* timeout */ 15000);
  test->add (BOOST_TEST_CASE ( &public_ipv6 ), 0, /* timeout */ 15000);
  test->add (BOOST_TEST_CASE ( &public_ipv4_cfg ), 0, /* timeout */ 15000);
  test->add (BOOST_TEST_CASE ( &public_ipv6_cfg ), 0, /* timeout */ 15000);
  
  return test;
}
