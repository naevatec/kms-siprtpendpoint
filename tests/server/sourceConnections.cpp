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
#include <chrono>

#include <sigc++/connection.h>

#include <RegisterParent.hpp>

using namespace kurento;
using namespace boost::unit_test;
using namespace std::chrono_literals;


boost::property_tree::ptree config;
std::string mediaPipelineId;
ModuleManager moduleManager;

std::string sdpOffer1 = "v=0\n"
"o=Test 4518353 4518353 IN IP4 127.0.0.1\n"
"s=TEST\n"
"t=0 0\n"
"m=audio 0 RTP/SAVP 0\n"
"c=IN IP4 127.0.0.1\n"
"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YzM2ZmU2MTEzNjM2N2FiZDZhZWU3MTZhNTg2NDgz\n"
"a=inactive\n"
"m=video 0 RTP/SAVP 98\n"
"c=IN IP4 127.0.0.1\n"
"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YzBlNGQ4ZjBmMWZkY2RhNzg2NGI0NTcwNDQyYWQ0\n"
"a=inactive\n"
"m=audio 60684 RTP/AVP 8 0 96\n"
"c=IN IP4 127.0.0.1\n"
"a=rtpmap:8 PCMA/8000\n"
"a=rtpmap:0 PCMU/8000\n"
"a=rtpmap:96 opus/48000/2\n"
"a=rtcp:60685\n"
"a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\n"
"a=setup:actpass\n"
"a=mid:audio0\n"
"a=ptime:20\n"
"a=sendrecv\n"
"a=ssrc:3101238828 cname:user4234385188@host-496f29bd\n"
"m=video 0 RTP/AVP 98\n"
"c=IN IP4 127.0.0.1\n"
"a=inactive\n";

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
        if (value["data"]["state"].asString().compare(std::string{"FLOWING"}) == 0) {
        lastEvent = value.toStyledString();
        if (testCV)
        	testCV->notify_one();
        }
	}

	std::string getLastEvent ()
	{
		return lastEvent;
	}
};


#define CRYPTOKEY "00108310518720928b30d38f411493"

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
releasePassThrough (std::shared_ptr<PassThroughImpl> &ep)
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
createSipRtpEndpoint (bool useIpv6, bool useCrypto)
{
  std::shared_ptr <kurento::MediaObjectImpl> rtpEndpoint;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = mediaPipelineId;
  constructorParams ["cryptoAgnostic"] = TRUE;
  if (useCrypto) {
	  constructorParams ["crypto"] = createSdesJson (getCrypto ());
  }
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
source_connections_regenerate_impl ()
{
  bool useIpv6 = FALSE;
  //bool useCrypto = TRUE;
  std::shared_ptr <PassThroughImpl> pt1 = createPassThrough ();
  std::shared_ptr <PassThroughImpl> pt2 = createPassThrough ();
  std::shared_ptr <PassThroughImpl> pt3 = createPassThrough ();
  std::shared_ptr <MediaElementImpl> src = createTestSrc();

  std::shared_ptr <FacadeRtpEndpointImpl> sipRtp = createSipRtpEndpoint (useIpv6, TRUE);
  std::shared_ptr <FacadeRtpEndpointImpl> sipRtp2 = createSipRtpEndpoint (useIpv6, FALSE);
  std::condition_variable cv;
  std::mutex mtx;
  std::unique_lock<std::mutex> lck (mtx);
  std::shared_ptr<TestEventHandler> testEH (new TestEventHandler (&cv,std::dynamic_pointer_cast <MediaObjectImpl> (pt3)));


  sipRtp2->connect(sipRtp2);
  sipRtp->connect (pt1);
  sipRtp->connect (pt2);
  sipRtp->connect (pt3);

  pt3->connect (std::string("MediaFlowInStateChange"), std::dynamic_pointer_cast <EventHandler>(testEH));


  pt1->connect (sipRtp);
  pt2->connect (sipRtp);
  src->connect (sipRtp);

  std::string offer = sipRtp2->generateOffer();
  std::string answer = sipRtp->processOffer(offer);
  sipRtp2->processAnswer(answer);


	  // First stream
	bool result = cv.wait_for (lck, 5000ms, [&] () {
	    return !(testEH->getLastEvent().empty());
	  });

	  if (!result) {
	    BOOST_ERROR ("Not media Flowing");
	  }


  releaseSipRtpEndpoint (sipRtp);
  releasePassThrough(pt1);
  releasePassThrough(pt2);
  releasePassThrough(pt3);
  releaseTestSrc (src);
}


static void
source_connections()
{
	  BOOST_TEST_MESSAGE ("Start test: test source connections on several sources");
	  source_connections_impl ();
}

static void
source_connections_regenerate()
{
	  BOOST_TEST_MESSAGE ("Start test: test source connections on several sources");
	  source_connections_regenerate_impl ();
}

test_suite *
init_unit_test_suite ( int , char *[] )
{
  test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpoint" );

  test->add (BOOST_TEST_CASE ( source_connections ), 0, /* timeout */ 10);
  test->add (BOOST_TEST_CASE ( source_connections_regenerate ), 0, /* timeout */ 10);
  return test;
}
