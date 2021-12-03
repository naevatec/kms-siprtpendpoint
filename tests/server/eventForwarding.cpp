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
#include <MediaElementImpl.hpp>
#include <PassThroughImpl.hpp>
//#include <IceCandidate.hpp>
#include <mutex>
#include <condition_variable>
#include <ModuleManager.hpp>
#include <KurentoException.hpp>
#include <MediaSet.hpp>
#include <MediaElementImpl.hpp>
#include <ConnectionState.hpp>
#include <MediaState.hpp>
#include <MediaFlowInStateChange.hpp>
#include <MediaFlowState.hpp>
#include <chrono>
//#include <SDES.hpp>
//#include <CryptoSuite.hpp>

#include <sigc++/connection.h>

#include <RegisterParent.hpp>


#define PLAYER_MEDIA_1 ""
#define PLAYER_MEDIA_2 ""
#define PLAYER_MEDIA_3 ""


using namespace kurento;
using namespace boost::unit_test;
using namespace std::chrono_literals;

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

//  moduleManager.loadModulesFromDirectories ("../../src/server:./src/server:../../kms-omni-build:../../src/server:../../../../kms-omni-build");
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

static std::shared_ptr <PassThroughImpl>
createPassThrough ()
{
  std::shared_ptr <kurento::MediaObjectImpl> pt;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;

  pt = moduleManager.getFactory ("PassThrough")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <PassThroughImpl> (pt);
}

static void
releasePassTrhough (std::shared_ptr<PassThroughImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
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

static std::shared_ptr<MediaElementImpl> createTestSrc() {
  std::shared_ptr <MediaElementImpl> src = std::dynamic_pointer_cast
      <MediaElementImpl> (MediaSet::getMediaSet()->ref (new  MediaElementImpl (
                            boost::property_tree::ptree(),
                            MediaSet::getMediaSet()->getMediaObject (mediaPipelineId),
                            "dummysrc") ) );

  g_object_set (src->getGstreamerElement(), "audio", TRUE, "video", TRUE, NULL);

  return std::dynamic_pointer_cast <MediaElementImpl> (src);
}

static void
releaseTestSrc (std::shared_ptr<MediaElementImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}

class TestEventHandler: public kurento::EventHandler
{
private:
	std::condition_variable *testCV;
	std::string lastEvent;

public:
	TestEventHandler (std::condition_variable *cv, std::shared_ptr<MediaObjectImpl> object): kurento::EventHandler(object), testCV(cv)
	{ }

	virtual void sendEvent (Json::Value &value)
	{
        BOOST_TEST_MESSAGE ("EventHandledr: " + value.toStyledString());
        lastEvent = value.toStyledString();
        if (testCV)
        	testCV->notify_one();
	}

	std::string getLastEvent ()
	{
		return lastEvent;
	}
};

static void
media_flow_out_forward_impl (bool useIpv6, bool useCrypto)
{
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

  std::shared_ptr<TestEventHandler> testEH (new TestEventHandler (&cv,std::dynamic_pointer_cast <MediaObjectImpl> (rtpEpAnswerer)));

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->connect(pt);

  rtpEpAnswerer->connect (std::string("MediaFlowOutStateChange"), std::dynamic_pointer_cast <EventHandler>(testEH));


  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  cv.wait_for (lck, 5000ms, [&] () {
    return !(testEH->getLastEvent().empty());
  });

  if (testEH->getLastEvent().empty()) {
    BOOST_ERROR ("No event received");
  }

  releaseTestSrc (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);

}

static void
media_flow_out_forward ()
{
  BOOST_TEST_MESSAGE ("Start test: media_flow_out_forward");
  media_flow_out_forward_impl (false, false);
}

static void
media_flow_out_forward_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: media_flow_out_forward_ipv6");
  media_flow_out_forward_impl (true, false);
}

static void
media_flow_in_forward_impl (bool useIpv6, bool useCrypto)
{
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

  std::shared_ptr<TestEventHandler> testEH (new TestEventHandler (&cv,std::dynamic_pointer_cast <MediaObjectImpl> (rtpEpOfferer)));

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->connect(pt);

  rtpEpOfferer->connect (std::string("MediaFlowInStateChange"), std::dynamic_pointer_cast <EventHandler>(testEH));


  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  cv.wait_for (lck, 5000ms, [&] () {
    return !(testEH->getLastEvent().empty());
  });

  if (testEH->getLastEvent().empty()) {
    BOOST_ERROR ("NoEvent received");
  }
  releaseTestSrc (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);

}

static void
media_flow_in_forward ()
{
  BOOST_TEST_MESSAGE ("Start test: media_flow_in_forward");
  media_flow_in_forward_impl (false, false);
}

static void
media_flow_in_forward_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: media_flow_in_forward_ipv6");
  media_flow_in_forward_impl (true, false);
}

static void
element_connected_forward_impl (bool useIpv6, bool useCrypto)
{
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

  std::shared_ptr<TestEventHandler> testEH (new TestEventHandler (&cv,std::dynamic_pointer_cast <MediaObjectImpl> (rtpEpAnswerer)));

  rtpEpAnswerer->connect (std::string("ElementConnected"), std::dynamic_pointer_cast <EventHandler>(testEH));

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->connect(pt);


  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  cv.wait_for (lck, 5000ms, [&] () {
    return !(testEH->getLastEvent().empty());
  });

  if (testEH->getLastEvent().empty()) {
    BOOST_ERROR ("NoEvent received");
  }

  releaseTestSrc (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);

}

static void
element_connected_forward ()
{
  BOOST_TEST_MESSAGE ("Start test: element_connected_forward");
  element_connected_forward_impl (false, false);
}

static void
element_connected_forward_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: element_connected_forward_ipv6");
  element_connected_forward_impl (true, false);
}

static void
element_disconnected_forward_impl (bool useIpv6, bool useCrypto)
{
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

  std::shared_ptr<TestEventHandler> testEH (new TestEventHandler (&cv,std::dynamic_pointer_cast <MediaObjectImpl> (rtpEpAnswerer)));

  rtpEpAnswerer->connect (std::string("ElementDisconnected"), std::dynamic_pointer_cast <EventHandler>(testEH));

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->connect(pt);


  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  src->disconnect (rtpEpOfferer);
  rtpEpAnswerer->disconnect (pt);

  cv.wait_for (lck, 5000ms, [&] () {
    return !(testEH->getLastEvent().empty());
  });

  if (testEH->getLastEvent().empty()) {
    BOOST_ERROR ("NoEvent received");
  }

  releaseTestSrc (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);

}

static void
element_release_impl ()
{
	std::shared_ptr<TestEventHandler> testEH;
	std::shared_ptr<TestEventHandler> testEH2;

	{
		  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (false, false);
		  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (false, false);
		  std::shared_ptr <MediaElementImpl> src = createTestSrc();
		  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

		  testEH =std::shared_ptr<TestEventHandler> (new TestEventHandler (NULL,std::dynamic_pointer_cast <MediaObjectImpl> (rtpEpOfferer)));
		  testEH2 =std::shared_ptr<TestEventHandler> (new TestEventHandler (NULL,std::dynamic_pointer_cast <MediaObjectImpl> (rtpEpAnswerer)));

		  rtpEpOfferer->connect (std::string("ElementDisconnected"), std::dynamic_pointer_cast <EventHandler>(testEH));
		  rtpEpAnswerer->connect (std::string("ElementDisconnected"), std::dynamic_pointer_cast <EventHandler>(testEH2));

		  src->connect (rtpEpOfferer);

		  rtpEpAnswerer->connect(pt);


		  std::string offer = rtpEpOfferer->generateOffer ();
		  BOOST_TEST_MESSAGE ("offer: " + offer);

		  std::string answer = rtpEpAnswerer->processOffer (offer);
		  BOOST_TEST_MESSAGE ("answer: " + answer);

		  rtpEpOfferer->processAnswer (answer);

		  src->disconnect (rtpEpOfferer);
		  rtpEpAnswerer->disconnect (pt);

		  sleep (1);

		  releaseTestSrc (src);
		  releaseRtpEndpoint (rtpEpOfferer);
		  releaseRtpEndpoint (rtpEpAnswerer);
		  releasePassTrhough (pt);
	}
	sleep (1);
}


static void
element_disconnected_forward ()
{
  BOOST_TEST_MESSAGE ("Start test: element_disconnected_forward");
  element_disconnected_forward_impl (false, false);
}

static void
element_disconnected_forward_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: element_disconnected_forward_ipv6");
  element_disconnected_forward_impl (true, false);
}

static void
element_release ()
{
  BOOST_TEST_MESSAGE ("Start test: element_disconnected_forward");
  element_release_impl ();
}





test_suite *
init_unit_test_suite ( int , char *[] )
{
  test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpoint" );
  if (true)
	  test->add (BOOST_TEST_CASE ( &media_flow_out_forward ), 0, /* timeout */ 1000);
  if (true)
	  test->add (BOOST_TEST_CASE ( &media_flow_in_forward ), 0, /* timeout */ 1000);
  if (true)
	  test->add (BOOST_TEST_CASE ( &element_connected_forward ), 0, /* timeout */ 1000);
  if (false)
	  test->add (BOOST_TEST_CASE ( &element_disconnected_forward ), 0, /* timeout */ 1000);
  if (true)
	  test->add (BOOST_TEST_CASE ( &element_release ), 0, /* timeout */ 1000);

  if (false) {
	  test->add (BOOST_TEST_CASE ( &media_flow_out_forward_ipv6 ), 0, /* timeout */ 5);
	  test->add (BOOST_TEST_CASE ( &media_flow_in_forward_ipv6 ), 0, /* timeout */ 5);
	  test->add (BOOST_TEST_CASE ( &element_connected_forward_ipv6 ), 0, /* timeout */ 5);
	  test->add (BOOST_TEST_CASE ( &element_disconnected_forward_ipv6 ), 0, /* timeout */ 5);
  }
  return test;
}
