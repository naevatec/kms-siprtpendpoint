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
#include <MediaFlowInStateChanged.hpp>
#include <MediaFlowState.hpp>
#include <GstreamerDotDetails.hpp>
//#include <SDES.hpp>
//#include <CryptoSuite.hpp>

#include <sigc++/connection.h>

#include <RegisterParent.hpp>


#define PLAYER_MEDIA_1 ""
#define PLAYER_MEDIA_2 ""
#define PLAYER_MEDIA_3 ""


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


std::string
createMediaPipeline (boost::property_tree::ptree& cfg)
{
	std::string pipeId;
	
	pipeId = moduleManager.getFactory ("MediaPipeline")->createObject (
                      cfg, "",
                      Json::Value() )->getId();
	return pipeId;
}

void
initKurentoConfig (boost::property_tree::ptree& cfg)
{
  boost::property_tree::ptree ac, audioCodecs, vc, videoCodecs;

  cfg.add ("configPath", "../../../tests" );
  cfg.add ("modules.kurento.SdpEndpoint.numAudioMedias", 1);
  cfg.add ("modules.kurento.SdpEndpoint.numVideoMedias", 1);

  ac.put ("name", "opus/48000/2");
  audioCodecs.push_back (std::make_pair ("", ac) );
  cfg.add_child ("modules.kurento.SdpEndpoint.audioCodecs", audioCodecs);

  vc.put ("name", "VP8/90000");
  videoCodecs.push_back (std::make_pair ("", vc) );
  cfg.add_child ("modules.kurento.SdpEndpoint.videoCodecs", videoCodecs);
}

GF::GF()
{
  gst_init(nullptr, nullptr);

//  moduleManager.loadModulesFromDirectories ("../../src/server:./src/server:../../kms-omni-build:../../src/server:../../../../kms-omni-build");
  moduleManager.loadModulesFromDirectories ("../../src/server:./");

  initKurentoConfig(config);
  
  mediaPipelineId = createMediaPipeline (config);
}

GF::~GF()
{
  MediaSet::deleteMediaSet();
}

#define CRYPTOKEY "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7"


static void
dumpPipeline (std::shared_ptr<MediaPipeline> pipeline, std::string fileName)
{
  std::string pipelineDot;
  std::shared_ptr<GstreamerDotDetails> details (new GstreamerDotDetails ("SHOW_ALL"));

  pipelineDot = pipeline->getGstreamerDot (details);
  std::ofstream out(fileName);

  out << pipelineDot;
  out.close ();

}

static void
dumpPipeline (std::string pipelineId, std::string fileName)
{
  std::shared_ptr<MediaPipeline> pipeline = std::dynamic_pointer_cast<MediaPipeline> (MediaSet::getMediaSet ()->getMediaObject (pipelineId));
  dumpPipeline (pipeline, fileName);

//  MediaSet::getMediaSet ()->release (pipelineId);
}

static void
dumpPipeline(std::string filename)
{
	dumpPipeline (mediaPipelineId, filename);
}

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
createPassThrough (std::string pipeId)
{
  std::shared_ptr <kurento::MediaObjectImpl> pt;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = pipeId;

  pt = moduleManager.getFactory ("PassThrough")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <PassThroughImpl> (pt);
}

static std::shared_ptr <PassThroughImpl>
createPassThrough ()
{
	return createPassThrough(mediaPipelineId);
}

static void
releasePassTrhough (std::shared_ptr<PassThroughImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}


static std::shared_ptr <FacadeRtpEndpointImpl>
createRtpEndpoint (std::string pipeId, bool useIpv6, bool useCrypto)
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = pipeId;
  constructorParams ["useIpv6"] = useIpv6;
//  if (useCrypto) {
//	  constructorParams ["crypto"] = getCrypto ()->;
//  }

  rtpEndpoint = moduleManager.getFactory ("SipRtpEndpoint")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <FacadeRtpEndpointImpl> (rtpEndpoint);
}

static std::shared_ptr <FacadeRtpEndpointImpl>
createRtpEndpoint (bool useIpv6, bool useCrypto)
{
	return createRtpEndpoint (mediaPipelineId, useIpv6, useCrypto);
}

static void
releaseRtpEndpoint (std::shared_ptr<FacadeRtpEndpointImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}

static std::shared_ptr<MediaElementImpl> createTestSrc(std::string pipeId) {
  std::shared_ptr <MediaElementImpl> src = std::dynamic_pointer_cast
      <MediaElementImpl> (MediaSet::getMediaSet()->ref (new  MediaElementImpl (
                            boost::property_tree::ptree(),
                            MediaSet::getMediaSet()->getMediaObject (pipeId),
                            "dummysrc") ) );

  g_object_set (src->getGstreamerElement(), "audio", TRUE, "video", TRUE, NULL);

  return std::dynamic_pointer_cast <MediaElementImpl> (src);
}

static std::shared_ptr<MediaElementImpl> createTestSrc()
{
	return createTestSrc (mediaPipelineId);
}

static std::shared_ptr<MediaElementImpl> createTestAudioSrc() {
  std::shared_ptr <MediaElementImpl> src = std::dynamic_pointer_cast
      <MediaElementImpl> (MediaSet::getMediaSet()->ref (new  MediaElementImpl (
                            boost::property_tree::ptree(),
                            MediaSet::getMediaSet()->getMediaObject (mediaPipelineId),
                            "dummysrc") ) );

  g_object_set (src->getGstreamerElement(), "audio", TRUE, "video", FALSE, NULL);

  return std::dynamic_pointer_cast <MediaElementImpl> (src);
}

static void
releaseTestElement (std::shared_ptr<MediaElementImpl> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}

static std::shared_ptr<MediaElementImpl> getMediaElement (std::shared_ptr<PassThroughImpl> element)
{
	return std::dynamic_pointer_cast<MediaElementImpl> (element);
}


static void
media_state_changes_impl (bool useIpv6, bool useCrypto)
{
  std::atomic<bool> media_state_changed (false);
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->connect(pt);

  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
		  MediaFlowInStateChanged event) {
	  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
	  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
		  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
		  	  	  media_state_changed = true;
		  	  	  cv.notify_one();
	  	  	  }
  	  	  }
  );

  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  sleep(2);
  dumpPipeline ("media_state_changes_impl_1.dot");

  cv.wait (lck, [&] () {
    return media_state_changed.load();
  });

  if (!media_state_changed) {
    BOOST_ERROR ("Not media Flowing");
  }

  conn.disconnect ();

  src->disconnect(rtpEpOfferer);
  rtpEpAnswerer->disconnect(pt);
  releaseTestElement (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);

}

static std::string remove_ssrc_from_sdp (std::string sdp) 
{
	size_t ssrcPos = sdp.find("a=ssrc:");

	while (ssrcPos != std::string::npos) {
		size_t newLinePos = sdp.find('\n', ssrcPos);
		if (newLinePos != std::string::npos) {
			sdp.erase(ssrcPos, newLinePos - ssrcPos);
		}

		ssrcPos = sdp.find("a=ssrc:", newLinePos);
	}
	return sdp;
}


static void
media_state_changes_no_ssrc_in_sdp_impl (bool useIpv6, bool useCrypto)
{
  std::atomic<bool> media_state_changed (false);
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();

  src->connect (rtpEpOfferer);
  rtpEpAnswerer->connect(pt);

  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
		  MediaFlowInStateChanged event) {
	  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
	  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
		  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
		  	  	  media_state_changed = true;
		  	  	  cv.notify_one();
	  	  	  }
  	  	  }
  );

  std::string offer = rtpEpOfferer->generateOffer ();
  offer = remove_ssrc_from_sdp(offer);
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  answer = remove_ssrc_from_sdp(answer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  sleep(2);
  dumpPipeline ("media_state_changes_no_ssrc_in_sdp_impl_1.dot");

  cv.wait (lck, [&] () {
    return media_state_changed.load();
  });

  if (!media_state_changed) {
    BOOST_ERROR ("Not media Flowing");
  }

  conn.disconnect ();

  src->disconnect (rtpEpOfferer);
  rtpEpAnswerer->disconnect(pt);

  releaseTestElement (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);

}

static void
media_state_changes ()
{
  BOOST_TEST_MESSAGE ("Start test: media_state_changes");
  media_state_changes_impl (false, false);
}

static void
media_state_changes_no_ssrc_in_sdp () 
{
  BOOST_TEST_MESSAGE ("Start test: media_state_changes_no_ssrc_in_sdp");
  media_state_changes_no_ssrc_in_sdp_impl (false, false);
}

static void
media_state_changes_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: media_state_changes_ipv6");
  media_state_changes_impl (true, false);
}

static void
reconnection_generate_offer_state_changes_impl (bool useIpv6, bool useCrypto)
{
  std::atomic<bool> media_state_changed (false);
  std::atomic<bool> media_state_changed2 (false);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer2 = createRtpEndpoint (useIpv6, useCrypto);
  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();
  std::shared_ptr <PassThroughImpl> pt2 = createPassThrough ();
  std::shared_ptr <MediaElementImpl> src = createTestSrc();
  std::condition_variable cv;
  std::condition_variable cv2;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);
  std::mutex mtx2;
  std::unique_lock<std::mutex> lck2 (mtx2);

  src->connect(rtpEpOfferer);
  rtpEpAnswerer->connect(pt);
  rtpEpAnswerer2->connect(pt2);

  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
		  MediaFlowInStateChanged event) {
	  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
	  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
		  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
		  	  	  media_state_changed = true;
		  	  	  cv.notify_one();
	  	  	  }
  	  	  }
  );

  sigc::connection conn2 = getMediaElement(pt2)->signalMediaFlowInStateChanged.connect([&] (
		  MediaFlowInStateChanged event) {
	  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
	  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
		  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
		  	  	  media_state_changed2 = true;
		  	  	  cv2.notify_one();
	  	  	  }
  	  	  }
  );

  try {
	  std::string offer1 = rtpEpOfferer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer1: " + offer1);

	  std::string answer1 = rtpEpAnswerer->processOffer(offer1);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpOfferer->processAnswer(answer1);

	  sleep(2);
  	  dumpPipeline ("reconnection_generate_offer_state_changes_impl_1.dot");

	  // First stream
	  cv.wait (lck, [&] () {
	    return media_state_changed.load();
	  });
	  conn.disconnect ();

	  if (!media_state_changed) {
	    BOOST_ERROR ("Not media Flowing");
	  }

	  std::string offer2 = rtpEpOfferer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer2: " + offer2);

	  std::string answer2 = rtpEpAnswerer2->processOffer(offer2);
	  BOOST_TEST_MESSAGE ("answer2: " + answer2);

	  rtpEpOfferer->processAnswer(answer2);

	  // Second stream
	  cv2.wait (lck2, [&] () {
	    return media_state_changed2.load();
	  });
	  conn2.disconnect ();


	  if (!media_state_changed2) {
	    BOOST_ERROR ("Not media Flowing");
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

  src->disconnect(rtpEpOfferer);
  rtpEpAnswerer->disconnect(pt);
  rtpEpAnswerer2->disconnect(pt2);

  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releaseRtpEndpoint (rtpEpAnswerer2);
  releasePassTrhough (pt);
  releasePassTrhough (pt2);
}


static void
reconnection_process_offer_state_changes_impl (bool useIpv6, bool useCrypto)
{
	  std::atomic<bool> media_state_changed (false);
	  std::atomic<bool> media_state_changed2 (false);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer2 = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();
	  std::shared_ptr <PassThroughImpl> pt2 = createPassThrough ();
	  std::shared_ptr <MediaElementImpl> src = createTestSrc();
	  std::condition_variable cv;
	  std::condition_variable cv2;
	  std::mutex mtx;
	  std::unique_lock<std::mutex> lck (mtx);
	  std::mutex mtx2;
	  std::unique_lock<std::mutex> lck2 (mtx2);

	  src->connect(rtpEpAnswerer);
	  rtpEpOfferer->connect(pt);
	  rtpEpOfferer2->connect(pt2);

	  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed = true;
			  	  	  cv.notify_one();
		  	  	  }
	  	  	  }
	  );

	  sigc::connection conn2 = getMediaElement(pt2)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed2 = true;
			  	  	  cv2.notify_one();
		  	  	  }
	  	  	  }
	  );

  try {
	  std::string offer1 = rtpEpOfferer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer1: " + offer1);

	  std::string answer1 = rtpEpAnswerer->processOffer (offer1);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpOfferer->processAnswer(answer1);

	  sleep(2);
	  dumpPipeline ("reconnection_process_offer_state_changes_impl_1.dot");

	  // First stream
	  cv.wait (lck, [&] () {
	    return media_state_changed.load();
	  });
	  conn.disconnect ();

	  if (!media_state_changed) {
	    BOOST_ERROR ("Not media Flowing");
	  }

	  std::string offer2 = rtpEpOfferer2->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer2: " + offer2);

	  std::string answer2 = rtpEpAnswerer->processOffer (offer2);
	  BOOST_TEST_MESSAGE ("answer2: " + answer2);

	  rtpEpOfferer2->processAnswer(answer2);

	  // Second stream
	  cv2.wait (lck2, [&] () {
	    return media_state_changed2.load();
	  });
	  conn2.disconnect ();

	  if (!media_state_changed2) {
	    BOOST_ERROR ("Not media Flowing");
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

src->disconnect(rtpEpAnswerer);
rtpEpOfferer->disconnect(pt);
rtpEpOfferer2->disconnect(pt2);

  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpOfferer2);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);
  releasePassTrhough (pt2);
}

static void
reconnection_process_answer_state_changes_impl (bool useIpv6, bool useCrypto)
{
	  std::atomic<bool> media_state_changed (false);
	  std::atomic<bool> media_state_changed2 (false);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer2 = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();
	  std::shared_ptr <PassThroughImpl> pt2 = createPassThrough ();
	  std::shared_ptr <MediaElementImpl> src = createTestSrc();
	  std::condition_variable cv;
	  std::condition_variable cv2;
	  std::mutex mtx;
	  std::unique_lock<std::mutex> lck (mtx);
	  std::mutex mtx2;
	  std::unique_lock<std::mutex> lck2 (mtx2);

	  src->connect(rtpEpOfferer);
	  rtpEpAnswerer->connect(pt);
	  rtpEpAnswerer2->connect(pt2);

	  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed = true;
			  	  	  cv.notify_one();
		  	  	  }
	  	  	  }
	  );

	  sigc::connection conn2 = getMediaElement(pt2)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  if (state->getValue() == MediaFlowState::FLOWING) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed2 = true;
			  	  	  cv2.notify_one();
		  	  	  }
	  	  	  }
	  );

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer: " + offer);

	  std::string answer1 = rtpEpAnswerer->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpOfferer->processAnswer(answer1);

	  // First stream
	  cv.wait (lck, [&] () {
	    return media_state_changed.load();
	  });
	  conn.disconnect ();

	  if (!media_state_changed) {
	    BOOST_ERROR ("Not media Flowing");
	  }

	  std::string answer2 = rtpEpAnswerer2->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer2: " + answer2);

	  rtpEpOfferer->processAnswer (answer2);

	  // Second stream
	  cv2.wait (lck2, [&] () {
	    return media_state_changed2.load();
	  });
	  conn2.disconnect ();

	  if (!media_state_changed2) {
	    BOOST_ERROR ("Not media Flowing");
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

	src->disconnect(rtpEpOfferer);
	rtpEpAnswerer->disconnect(pt);
	rtpEpAnswerer2->disconnect(pt2);

  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releaseRtpEndpoint (rtpEpAnswerer2);
  releasePassTrhough (pt);
  releasePassTrhough (pt2);
  releaseTestElement (src);
}

static void
reconnection_process_answer_back_state_changes_impl (bool useIpv6, bool useCrypto)
{
	  std::atomic<bool> media_state_changed (false);
	  std::atomic<bool> media_state_changed2 (false);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer2 = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();
	  std::shared_ptr <MediaElementImpl> src = createTestAudioSrc();
	  std::shared_ptr <MediaElementImpl> src2 = createTestSrc();
	  std::condition_variable cv;
	  std::condition_variable cv2;
	  std::mutex mtx;
	  std::unique_lock<std::mutex> lck (mtx);
	  std::mutex mtx2;
	  std::unique_lock<std::mutex> lck2 (mtx2);

	  rtpEpOfferer->connect(pt);
	  src->connect(rtpEpAnswerer);
	  src2->connect(rtpEpAnswerer2);

	  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  std::shared_ptr<MediaType> media = event.getMediaType();

		  	  	  if ((state->getValue() == MediaFlowState::FLOWING) && (media->getValue() == MediaType::AUDIO)) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed = true;
			  	  	  cv.notify_one();
		  	  	  }
	  	  	  }
	  );

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer: " + offer);

	  std::string answer1 = rtpEpAnswerer->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpOfferer->processAnswer(answer1);

	  // First stream
	  cv.wait (lck, [&] () {
	    return media_state_changed.load();
	  });
	  conn.disconnect ();

	  conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  std::shared_ptr<MediaType> media = event.getMediaType();

		  	  	  if ((state->getValue() == MediaFlowState::FLOWING) && (media->getValue() == MediaType::VIDEO)) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed2 = true;
			  	  	  cv2.notify_one();
		  	  	  }
	  	  	  }
	  );

	  if (!media_state_changed) {
	    BOOST_ERROR ("Not media Flowing");
	  }

	  std::string answer2 = rtpEpAnswerer2->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer2: " + answer2);

	  rtpEpOfferer->processAnswer (answer2);

	  // First stream
	  cv2.wait (lck2, [&] () {
	    return media_state_changed2.load();
	  });
	  conn.disconnect ();

	  if (!media_state_changed2) {
	    BOOST_ERROR ("Not media Flowing");
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

	  rtpEpOfferer->disconnect(pt);
	  src->disconnect(rtpEpAnswerer);
	  src2->disconnect(rtpEpAnswerer2);

  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releaseRtpEndpoint (rtpEpAnswerer2);
  releasePassTrhough (pt);
  releaseTestElement (src);
  releaseTestElement (src2);
}

static void
filter_out_from_source_addr_impl (bool useIpv6, bool useCrypto)
{
	  std::atomic<bool> media_state_changed (false);
	  std::atomic<bool> media_state_changed2 (false);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer2 = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();
	  std::shared_ptr <MediaElementImpl> src = createTestAudioSrc();
	  std::shared_ptr <MediaElementImpl> src2 = createTestSrc();
	  std::condition_variable cv;
	  std::condition_variable cv2;
	  std::mutex mtx;
	  std::unique_lock<std::mutex> lck (mtx);
	  std::mutex mtx2;
	  std::unique_lock<std::mutex> lck2 (mtx2);

	  rtpEpOfferer->connect(pt);
	  src->connect(rtpEpAnswerer);
	  src2->connect(rtpEpAnswerer2);

	  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  std::shared_ptr<MediaType> media = event.getMediaType();

		  	  	  if ((state->getValue() == MediaFlowState::FLOWING) && (media->getValue() == MediaType::AUDIO)) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed = true;
			  	  	  cv.notify_one();
		  	  	  }
	  	  	  }
	  );

  try {
	  std::string offer = rtpEpOfferer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer: " + offer);

	  std::string answer1 = rtpEpAnswerer->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpOfferer->processAnswer(answer1);

	  // First stream
	  cv.wait (lck, [&] () {
	    return media_state_changed.load();
	  });
	  conn.disconnect ();

	  conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  std::shared_ptr<MediaType> media = event.getMediaType();

		  	  	  if ((state->getValue() == MediaFlowState::FLOWING) && (media->getValue() == MediaType::VIDEO)) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed2 = true;
			  	  	  cv2.notify_one();
		  	  	  }
	  	  	  }
	  );

	  if (!media_state_changed) {
	    BOOST_ERROR ("Not media Flowing");
	  }
	  sleep(2);
	  dumpPipeline ("firstNegotiation.dot");
	  std::string answer2 = rtpEpAnswerer2->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer2: " + answer2);

	  rtpEpOfferer->processAnswer (answer2);

	  // First stream
	  cv2.wait (lck2, [&] () {
	    return media_state_changed2.load();
	  });
	  conn.disconnect ();

	  if (!media_state_changed2) {
	    BOOST_ERROR ("Not media Flowing");
	  }

	  sleep(2);
	  dumpPipeline ("secondNegotiation.dot");

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

	  rtpEpOfferer->disconnect(pt);
	  src->disconnect(rtpEpAnswerer);
	  src2->disconnect(rtpEpAnswerer2);

  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releaseRtpEndpoint (rtpEpAnswerer2);
  releasePassTrhough (pt);
  releaseTestElement (src);
  releaseTestElement (src2);
}


static void
check_ssrc_switch_impl (bool useIpv6, bool useCrypto)
{
	  std::atomic<bool> media_state_changed (false);
	  std::atomic<bool> media_state_changed2 (false);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, useCrypto);
	  std::shared_ptr <PassThroughImpl> pt = createPassThrough ();
	  std::shared_ptr <MediaElementImpl> src = createTestSrc();
	  std::condition_variable cv;
	  std::condition_variable cv2;
	  std::mutex mtx;
	  std::unique_lock<std::mutex> lck (mtx);
	  std::mutex mtx2;
	  std::unique_lock<std::mutex> lck2 (mtx2);

	  rtpEpOfferer->connect(pt);
	  src->connect(rtpEpAnswerer);

	  sigc::connection conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  std::shared_ptr<MediaType> media = event.getMediaType();

		  	  	  if ((state->getValue() == MediaFlowState::FLOWING) && (media->getValue() == MediaType::AUDIO)) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed = true;
			  	  	  cv.notify_one();
		  	  	  }
	  	  	  }
	  );

  try {
	  std::string offer = rtpEpAnswerer->generateOffer ();
	  BOOST_TEST_MESSAGE ("offer: " + offer);

	  std::string answer1 = rtpEpOfferer->processOffer (offer);
	  BOOST_TEST_MESSAGE ("answer1: " + answer1);

	  rtpEpAnswerer->processAnswer(answer1);

	  // First stream
	  cv.wait (lck, [&] () {
	    return media_state_changed.load();
	  });
	  conn.disconnect ();

	  /*conn = getMediaElement(pt)->signalMediaFlowInStateChanged.connect([&] (
			  MediaFlowInStateChanged event) {
		  	  	  std::shared_ptr<MediaFlowState> state = event.getState();
		  	  	  std::shared_ptr<MediaType> media = event.getMediaType();

		  	  	  if ((state->getValue() == MediaFlowState::FLOWING) && (media->getValue() == MediaType::VIDEO)) {
			  	  	  BOOST_CHECK (state->getValue() == MediaFlowState::FLOWING);
			  	  	  media_state_changed2 = true;
			  	  	  cv2.notify_one();
		  	  	  }
	  	  	  }
	  );*/

	  if (!media_state_changed) {
	    BOOST_ERROR ("Not media Flowing");
	  }
	  sleep(2);
	  dumpPipeline ("firstNegotiation.dot");
	  std::string sdp2 = rtpEpAnswerer->processAnswer(answer1);
	  //std::string sdp3 = rtpEpOfferer->processAnswer(answer1);

	  sleep(2);
	  dumpPipeline ("secondNegotiation.dot");
	  /*cv2.wait (lck2, [&] () {
	    return media_state_changed2.load();
	  });
	  conn.disconnect ();

	  if (!media_state_changed2) {
	    BOOST_ERROR ("Not media Flowing");
	  }*/

	  if (!getMediaElement(pt)->isMediaFlowingIn(std::shared_ptr<MediaType> (new MediaType (MediaType::VIDEO)))) {
		BOOST_ERROR("Media not flowing");
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

	  rtpEpOfferer->disconnect(pt);
	  src->disconnect(rtpEpAnswerer);
	  
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
  releasePassTrhough (pt);
  releaseTestElement (src);
}

static void
reconnection_generate_offer_state_changes()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_generate_offer_state_changes");
	  reconnection_generate_offer_state_changes_impl (false, false);
}

static void
reconnection_generate_offer_state_changes_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_generate_offer_state_changes_ipv6");
	  reconnection_generate_offer_state_changes_impl (true, false);
}

static void
reconnection_process_offer_state_changes()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_process_offer_state_changes");
	  reconnection_process_offer_state_changes_impl (false, false);
}

static void
reconnection_process_offer_state_changes_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_process_offer_state_changes_ipv6");
	  reconnection_process_offer_state_changes_impl (true, false);
}

static void
reconnection_process_answer_state_changes()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_process_offer_state_changes");
	  reconnection_process_answer_state_changes_impl (false, false);
}

static void
reconnection_process_answer_state_changes_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_process_offer_state_changes_ipv6");
	  reconnection_process_answer_state_changes_impl (true, false);
}

static void
reconnection_process_answer_back_state_changes()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_process_answer_back_state_changes");
	  reconnection_process_answer_back_state_changes_impl (false, false);
}

static void
reconnection_process_answer_back_state_changes_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: reconnection_process_answer_back_state_changes_ipv6");
	  reconnection_process_answer_back_state_changes_impl (true, false);
}

static void
filter_out_from_source_addr()
{
	  BOOST_TEST_MESSAGE ("Start test: filter_out_from_source_addr");
	  filter_out_from_source_addr_impl (false, false);
}

static void
filter_out_from_source_addr_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: filter_out_from_source_addr_ipv6");
	  filter_out_from_source_addr_impl (true, false);
}

static void 
check_ssrc_switch()
{
	  BOOST_TEST_MESSAGE ("Start test: check_ssrc_switch");
	  check_ssrc_switch_impl (false, false);
}

static void 
check_ssrc_switch_ipv6()
{
	  BOOST_TEST_MESSAGE ("Start test: check_ssrc_switch_ipv6");
	  check_ssrc_switch_impl (true, false);
}


static void
bitrate_limiter_impl (bool useIpv6)
{
  std::string pipeId;

  config.add ("modules.siprtp.SipRtpEndpoint.max-kbps", 450);
  config.add ("modules.siprtp.SipRtpEndpoint.max-bucket-size", 4500);
  config.add ("modules.siprtp.SipRtpEndpoint.max-bucket-storage", 1000000);

  pipeId = mediaPipelineId;

  std::atomic<bool> media_state_changed (false);
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (pipeId, useIpv6, false);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (pipeId, useIpv6, false);
  std::shared_ptr <MediaElementImpl> src = createTestSrc(pipeId);

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->getSignalMediaStateChanged().connect ([&] (
  MediaStateChanged event) {
    std::shared_ptr <MediaState> state = event.getNewState();
    BOOST_CHECK (state->getValue() == MediaState::CONNECTED);
    media_state_changed = true;
    cv.notify_one();
  });

  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  dumpPipeline ("bitrate_limiter_1.dot");
  cv.wait (lck, [&] () {
    return media_state_changed.load();
  });

  if (!media_state_changed) {
    BOOST_ERROR ("Not media state changed");
  }

  sleep(10);
  dumpPipeline ("bitrate_limiter_2.dot");

  releaseTestElement (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
}


static void
bitrate_overloadded_impl (bool useIpv6)
{
  config.add ("modules.siprtp.SipRtpEndpoint.max-kbps", 250);
  config.add ("modules.siprtp.SipRtpEndpoint.max-bucket-size", 3000);

  std::atomic<bool> media_state_changed (false);
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);

  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpOfferer = createRtpEndpoint (useIpv6, false);
  std::shared_ptr <FacadeRtpEndpointImpl> rtpEpAnswerer = createRtpEndpoint (useIpv6, false);
  std::shared_ptr <MediaElementImpl> src = createTestSrc();

  src->connect (rtpEpOfferer);

  rtpEpAnswerer->getSignalMediaStateChanged().connect ([&] (
  MediaStateChanged event) {
    std::shared_ptr <MediaState> state = event.getNewState();
    BOOST_CHECK (state->getValue() == MediaState::CONNECTED);
    media_state_changed = true;
    cv.notify_one();
  });

  std::string offer = rtpEpOfferer->generateOffer ();
  BOOST_TEST_MESSAGE ("offer: " + offer);

  std::string answer = rtpEpAnswerer->processOffer (offer);
  BOOST_TEST_MESSAGE ("answer: " + answer);

  rtpEpOfferer->processAnswer (answer);

  cv.wait (lck, [&] () {
    return media_state_changed.load();
  });

  if (!media_state_changed) {
    BOOST_ERROR ("Not media state chagned");
  }

  sleep(10);

  releaseTestElement (src);
  releaseRtpEndpoint (rtpEpOfferer);
  releaseRtpEndpoint (rtpEpAnswerer);
}

static void
bitrate_limiter ()
{
  BOOST_TEST_MESSAGE ("Start test: bitrate limiter");
  bitrate_limiter_impl (false);
}

static void
bitrate_limiter_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: bitrate limiter");
  bitrate_limiter_impl (true);
}

static void
bitrate_overloadded ()
{
  BOOST_TEST_MESSAGE ("Start test: bitrate limiter");
  bitrate_overloadded_impl (false);
}

static void
bitrate_overloadded_ipv6 ()
{
  BOOST_TEST_MESSAGE ("Start test: bitrate limiter");
  bitrate_overloadded_impl (true);
}



test_suite *
init_unit_test_suite ( int , char *[] )
{
	test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpointPlay" );

  test->add (BOOST_TEST_CASE ( &media_state_changes ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &media_state_changes_no_ssrc_in_sdp), 0 , /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &reconnection_generate_offer_state_changes ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &reconnection_process_offer_state_changes ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &reconnection_process_answer_state_changes ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &reconnection_process_answer_back_state_changes ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &bitrate_limiter ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &bitrate_overloadded ), 0, /* timeout */ 15);
  test->add (BOOST_TEST_CASE ( &check_ssrc_switch ), 0, /* timeout */ 20);
  test->add (BOOST_TEST_CASE ( &filter_out_from_source_addr ), 0, /* timeout */ 20);

  if (false) {
	  test->add (BOOST_TEST_CASE ( &media_state_changes_ipv6 ), 0, /* timeout */ 15000);
	  test->add (BOOST_TEST_CASE ( &reconnection_generate_offer_state_changes_ipv6 ), 0, /* timeout */ 15);
	  test->add (BOOST_TEST_CASE ( &reconnection_process_offer_state_changes_ipv6 ), 0, /* timeout */ 15);
	  test->add (BOOST_TEST_CASE ( &reconnection_process_answer_state_changes_ipv6 ), 0, /* timeout */ 15);
	  test->add (BOOST_TEST_CASE ( &reconnection_process_answer_back_state_changes_ipv6 ), 0, /* timeout */ 15);
      test->add (BOOST_TEST_CASE ( &bitrate_limiter_ipv6 ), 0, /* timeout */ 15);
	  test->add (BOOST_TEST_CASE ( &bitrate_overloadded_ipv6 ), 0, /* timeout */ 15);
	  test->add (BOOST_TEST_CASE ( &check_ssrc_switch_ipv6 ), 0, /* timeout */ 20);
	  test->add (BOOST_TEST_CASE ( &filter_out_from_source_addr_ipv6 ), 0, /* timeout */ 20);
  }
  return test;
}
