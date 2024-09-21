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
#include "SDES.hpp"
#include "CryptoSuite.hpp"

#include <sigc++/connection.h>

#include <RegisterParent.hpp>

using namespace kurento;
using namespace boost::unit_test;

boost::property_tree::ptree config;
std::shared_ptr<MediaPipelineImpl> thePipeline;
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

  thePipeline = std::dynamic_pointer_cast <MediaPipelineImpl> (moduleManager.getFactory ("MediaPipeline")->createObject (
                      config, "",
                      Json::Value() ));
                      
  
  mediaPipelineId = thePipeline->getId();
}

GF::~GF()
{
  MediaSet::deleteMediaSet();
}


#define CRYPTOKEY "00108310518720928b30d38f411493"

static std::shared_ptr<SDES> getCrypto ()
{
	std::shared_ptr<SDES> crypto (new SDES());
	std::shared_ptr<CryptoSuite> cryptoSuite (new kurento::CryptoSuite (kurento::CryptoSuite::AES_128_CM_HMAC_SHA1_80));

	crypto->setCrypto(cryptoSuite);
	crypto->setKey(CRYPTOKEY);
	return crypto;
}

static Json::Value
createSdesJson (std::shared_ptr<SDES> sdes)
{
	Json::Value sdesParams;

	sdesParams ["key"] = sdes->getKey();
	sdesParams ["crypto"] = sdes->getCrypto()->getString();

	return sdesParams;
}


static std::shared_ptr <FacadeRtpEndpointImpl>
createRtpEndpoint (bool useIpv6, bool useCrypto)
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;
  constructorParams ["useIpv6"] = useIpv6;
  constructorParams ["cryptoAgnostic"] = true;
  if (useCrypto) {
	  constructorParams ["crypto"] = createSdesJson (getCrypto ());
  }

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

static std::shared_ptr<MediaElementImpl> createTestSink() {
  std::shared_ptr <MediaElementImpl> src = std::dynamic_pointer_cast
      <MediaElementImpl> (MediaSet::getMediaSet()->ref (new  MediaElementImpl (
                            boost::property_tree::ptree(),
                            MediaSet::getMediaSet()->getMediaObject (mediaPipelineId),
                            "dummysink") ) );

  g_object_set (src->getGstreamerElement(), "audio", TRUE, "video", TRUE, NULL);

  return std::dynamic_pointer_cast <MediaElementImpl> (src);
}



static void
releaseTestElement (std::shared_ptr<MediaElementImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}

/*static std::shared_ptr <PassThroughImpl>
createPassThrough ()
{
  std::shared_ptr <kurento::MediaObjectImpl> pt;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;

  pt = moduleManager.getFactory ("PassThrough")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <PassThroughImpl> (pt);
}*/

static std::shared_ptr<MediaElementImpl> getMediaElement (std::shared_ptr<MediaElementImpl> element)
{
	return std::dynamic_pointer_cast<MediaElementImpl> (element);
}

/*static void
releasePassTrhough (std::shared_ptr<PassThroughImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}*/

static void
dump_gstreamer_dot (std::string filename)
{
  std::string gstreamerDot = thePipeline->getGstreamerDot ();
  std::ofstream out(filename);
  out << gstreamerDot;
  out.close();
}


static void
show_media_flow_in (const std::shared_ptr<MediaElementImpl> &element, MediaFlowInStateChanged event, std::atomic<bool> &media_state_change, std::condition_variable &cv)
{
  std::shared_ptr<MediaFlowState> state = event.getState();
  if (event.getMediaType ()->getValue() == MediaType::VIDEO) {
    if (state->getValue() == MediaFlowState::FLOWING) {
      std::string message = "Video Flowing in element ";

      message.append (element->getId()).append(" (").append (((GstObject*)element->getGstreamerElement())->name).append(")");

      BOOST_TEST_MESSAGE(message.c_str());
      media_state_change = true;
      cv.notify_one ();
    } else {
      std::string message = "Video Not Flowing in element ";

      message.append (element->getId()).append(" (").append (((GstObject*)element->getGstreamerElement())->name).append(")");

      BOOST_TEST_MESSAGE(message.c_str());
      media_state_change = true;
      cv.notify_one ();
    }
  }
}

static void
show_media_flow_out (const std::shared_ptr<MediaElementImpl> &element, MediaFlowOutStateChanged event, std::atomic<bool> &media_state_change, std::condition_variable &cv)
{
  std::shared_ptr<MediaFlowState> state = event.getState();
  if (event.getMediaType ()->getValue() == MediaType::VIDEO) {
    if (state->getValue() == MediaFlowState::FLOWING) {
      std::string message = "Video Flowing out from element ";

      message.append (element->getId()).append(" (").append (((GstObject*)element->getGstreamerElement())->name).append(")");

      BOOST_TEST_MESSAGE(message.c_str());
      media_state_change = true;
      cv.notify_one ();
    } else {
      std::string message = "Video Not Flowing Out from element ";

      message.append (element->getId()).append(" (").append (((GstObject*)element->getGstreamerElement())->name).append(")");

      BOOST_TEST_MESSAGE(message.c_str());
      media_state_change = true;
      cv.notify_one ();
    }
  }
}

static sigc::connection
log_flowing_in_on_element (const std::shared_ptr<MediaElementImpl> &element, std::atomic<bool> &media_state_changed, std::condition_variable &cv)
{
  sigc::connection conn = getMediaElement(element)->signalMediaFlowInStateChanged.connect([&] (
		  MediaFlowInStateChanged event) {
        show_media_flow_in (element, event, media_state_changed, cv);
    }
  );
  return conn;
}

static sigc::connection
log_flowing_out_from_element (const std::shared_ptr<MediaElementImpl> &element, std::atomic<bool> &media_state_changed, std::condition_variable &cv)
{
  sigc::connection conn = getMediaElement(element)->signalMediaFlowOutStateChanged.connect([&] (
		  MediaFlowOutStateChanged event) {
        show_media_flow_out (element, event, media_state_changed, cv);
    }
  );
  return conn;
}


static void
reconnection_generate_offer_state_changes_impl (bool useIpv6, bool useCrypto)
{
  std::atomic<bool> media_state_changed (false);
  std::atomic<bool> media_state_changed2 (false);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, false);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer2 = createRtpEndpoint (useIpv6, false);
  std::shared_ptr <MediaElementImpl> src1 = createTestSrc();
  std::shared_ptr <MediaElementImpl> src2 = createTestSrc();
  std::shared_ptr <MediaElementImpl> src3 = createTestSrc();
  std::shared_ptr <MediaElementImpl> sink1 = createTestSink();
  std::shared_ptr <MediaElementImpl> sink2 = createTestSink();
  std::shared_ptr <MediaElementImpl> sink3 = createTestSink();
  std::condition_variable cv;
  std::condition_variable cv2;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  src1->connect (rtpEpAnswerer);
  src2->connect (rtpEpAnswerer2);
  src3->connect (rtpEpOfferer);
  rtpEpAnswerer->connect (sink1);
  rtpEpAnswerer2->connect (sink2);
  rtpEpOfferer->connect (sink3);



  sigc::connection c_offerer_out = log_flowing_out_from_element (rtpEpOfferer, media_state_changed, cv);
  sigc::connection c_sink_in = log_flowing_in_on_element (sink3, media_state_changed, cv);
//  log_flowing_on_element (rtpEpAnswerer, media_state_changed, cv);
//  log_flowing_on_element (rtpEpAnswerer2, media_state_changed, cv);
//  log_flowing_on_element (sink1, media_state_changed, cv);
//  log_flowing_on_element (sink2, media_state_changed, cv);
  sigc::connection c_sink_out = log_flowing_out_from_element (rtpEpOfferer, media_state_changed2, cv2);
  sigc::connection c_offerer_in = log_flowing_in_on_element (sink3, media_state_changed, cv);


  try {
	  std::string offer1 = rtpEpAnswerer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer1: " + offer1);

	  std::string answer1 = rtpEpOfferer->processOffer(offer1);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpAnswerer->processAnswer(answer1);

	  // First stream
    cv.wait_until (lck, std::chrono::steady_clock::now() + std::chrono::seconds(10), [&] () {
	    return media_state_changed.load();
	  });

	  if (!media_state_changed) {
	    BOOST_ERROR ("Media not Flowing");
	  }

    media_state_changed = false;
    lck.unlock ();

    std::mutex mtx2;
    std::unique_lock<std::mutex> lck2 (mtx2);

	  std::string offer2 = rtpEpAnswerer2->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer2: " + offer2);

	  std::string answer2 = rtpEpOfferer->processOffer(offer2);
	  BOOST_TEST_MESSAGE ("answer2: " + answer2);

	  rtpEpAnswerer2->processAnswer(answer2);
	  BOOST_TEST_MESSAGE ("answer2 processed");
    

    dump_gstreamer_dot ("gstreamer_2nd_newly_connected.dot");    
	  BOOST_TEST_MESSAGE ("Generated Gstreamer dump");


	  // Second stream
    cv2.wait_until (lck2, std::chrono::steady_clock::now() + std::chrono::seconds(10), [&] () {
	    return !media_state_changed2.load();
	  });

    dump_gstreamer_dot ("gstreamer_2nd_old_connected.dot");    

	  if (!media_state_changed2) {
	    BOOST_ERROR ("2nd negotiation. Media not Flowing");
	  }

  } catch (kurento::KurentoException& e) {
	 BOOST_ERROR("Unwanted Kurento Exception managing offer/answer");
  }

  if (rtpEpAnswerer->getConnectionState ()->getValue () !=
      ConnectionState::CONNECTED) {
    BOOST_ERROR ("Connection must be connected");
  }

  if (rtpEpOfferer->getConnectionState ()->getValue () !=
      ConnectionState::CONNECTED) {
    BOOST_ERROR ("Connection must be connected");
  }

  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releaseRtpEndpoint (rtpEpAnswerer2);
  releaseTestElement (sink1);
  releaseTestElement (sink2);
  releaseTestElement (sink3);
  releaseTestElement (src1);
  releaseTestElement (src2);
  releaseTestElement (src3);
}


static void
reconnection_generate_offer_state_changes()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_generate_offer_state_changes");
	  reconnection_generate_offer_state_changes_impl (false, true);
}

static void
reconnection_generate_offer_state_changes_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_generate_offer_state_changes_ipv6");
	  reconnection_generate_offer_state_changes_impl (true, true);
}


test_suite *
init_unit_test_suite ( int , char *[] )
{
  test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpoint" );

  test->add (BOOST_TEST_CASE ( &reconnection_generate_offer_state_changes ), 0, /* timeout */ 1000);

  if (false) {
	  test->add (BOOST_TEST_CASE ( &reconnection_generate_offer_state_changes_ipv6 ), 0, /* timeout */ 1000);
  }
  return test;
}
