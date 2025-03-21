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

#include <gst/gst.h>

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

#include <list>


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

static void
bus_msg (GstBus * bus, GstMessage * msg, gpointer pipe)
{
  switch (GST_MESSAGE_TYPE (msg)) {
    case GST_MESSAGE_ERROR:{
      gchar *error_file = g_strdup_printf ("error-%s", GST_OBJECT_NAME (pipe));

      GST_ERROR ("Error: %" GST_PTR_FORMAT, msg);
      GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (pipe),
          GST_DEBUG_GRAPH_SHOW_ALL, error_file);
      g_free (error_file);
      break;
    }
    case GST_MESSAGE_WARNING:{
      gchar *warn_file = g_strdup_printf ("warning-%s", GST_OBJECT_NAME (pipe));

      GST_WARNING ("Warning: %" GST_PTR_FORMAT, msg);
      GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS (GST_BIN (pipe),
          GST_DEBUG_GRAPH_SHOW_ALL, warn_file);
      g_free (warn_file);
      break;
    }
    case GST_MESSAGE_EOS:{
      break;
    }
    default:
      break;
  }
}


std::string
createMediaPipeline (boost::property_tree::ptree& cfg)
{
	std::string pipeId;
  std::shared_ptr<kurento::MediaPipelineImpl> pipeline;
  std::shared_ptr<kurento::MediaObject> element;
	
	element = moduleManager.getFactory ("MediaPipeline")->createObject (
                      cfg, "",
                      Json::Value() );
  pipeId = element->getId();
  pipeline = std::dynamic_pointer_cast<kurento::MediaPipelineImpl> (element);

  GstBus *bus = gst_pipeline_get_bus (GST_PIPELINE (pipeline->getPipeline()));

  gst_bus_add_signal_watch (bus);
  g_signal_connect (bus, "message", G_CALLBACK (bus_msg), pipeline->getPipeline());

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

static std::shared_ptr <PassThrough>
createPassThrough (std::string pipeId)
{
  std::shared_ptr <kurento::MediaObjectImpl> pt;
  Json::Value constructorParams;

  constructorParams ["mediaPipeline"] = pipeId;

  pt = moduleManager.getFactory ("PassThrough")->createObject (
                  config, "",
                  constructorParams );

  return std::dynamic_pointer_cast <PassThrough> (pt);
}

static std::shared_ptr <PassThrough>
createPassThrough ()
{
	return createPassThrough(mediaPipelineId);
}

static void
releasePassTrhough (std::shared_ptr<PassThrough> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}


static std::shared_ptr <SipRtpEndpoint>
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

  return std::dynamic_pointer_cast <SipRtpEndpoint> (rtpEndpoint);
}

static std::shared_ptr <SipRtpEndpoint>
createRtpEndpoint (bool useIpv6, bool useCrypto)
{
	return createRtpEndpoint (mediaPipelineId, useIpv6, useCrypto);
}

static void
releaseRtpEndpoint (std::shared_ptr<SipRtpEndpoint> ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}

static std::shared_ptr<MediaElement> createTestSrc(std::string pipeId) {
  std::shared_ptr <MediaElementImpl> src = std::dynamic_pointer_cast
      <MediaElementImpl> (MediaSet::getMediaSet()->ref (new  MediaElementImpl (
                            boost::property_tree::ptree(),
                            MediaSet::getMediaSet()->getMediaObject (pipeId),
                            "dummysrc") ) );

  g_object_set (src->getGstreamerElement(), "audio", TRUE, "video", TRUE, NULL);

  return std::dynamic_pointer_cast <MediaElement> (src);
}

static std::shared_ptr<MediaElement> createTestSrc()
{
	return createTestSrc (mediaPipelineId);
}

static void
releaseTestElement (std::shared_ptr<MediaElement> &ep)
{
  std::string id = ep->getId();

  ep.reset();
  MediaSet::getMediaSet ()->release (id);
}


#define NUMBER_OF_ENDPOINTS 100

// Set of shared_ptr<SipRtpEndpoint>
static std::list<std::shared_ptr<SipRtpEndpoint>> offerers;
static std::list<std::shared_ptr<SipRtpEndpoint>> answerers;
static std::list<std::shared_ptr <PassThrough>> pts;


static void 
create_offerers_and_answerers (int number, std::shared_ptr <MediaElement> src)
{
  for (int i = 0; i < number; i++) {
	std::shared_ptr<SipRtpEndpoint> offerer = createRtpEndpoint (false, false);
	std::shared_ptr<SipRtpEndpoint> answerer = createRtpEndpoint (false, false);
	std::shared_ptr<PassThrough> pt = createPassThrough ();

	offerers.push_back (offerer);
	answerers.push_back (answerer);
	pts.push_back (pt);
	src->connect (offerer);
	answerer->connect (pt);
  }
}

static void 
release_offerers_and_answerers ()
{
  std::vector<std::thread> threads;

  std::mutex mtx;
  std::condition_variable cv;
  bool ready = false;

  for (std::shared_ptr<SipRtpEndpoint> offerer : offerers) {
    threads.emplace_back([&offerer, &mtx, &cv, &ready]() {
      std::shared_ptr<SipRtpEndpoint> local = offerer;
      std::unique_lock<std::mutex> lock(mtx);
      cv.wait(lock, [&ready] { return ready; });
      releaseRtpEndpoint(local);
    });
  }

  for (std::shared_ptr<SipRtpEndpoint> answerer : answerers) {
    threads.emplace_back([&answerer, &mtx, &cv, &ready]() {
      std::shared_ptr<SipRtpEndpoint> local = answerer;
      std::unique_lock<std::mutex> lock(mtx);
      cv.wait(lock, [&ready] { return ready; });
      releaseRtpEndpoint(local);
    });
  }

  for (std::shared_ptr<PassThrough> pt : pts) {
    threads.emplace_back([&pt, &mtx, &cv, &ready]() {
      std::shared_ptr<PassThrough> local= pt;
      std::unique_lock<std::mutex> lock(mtx);
      cv.wait(lock, [&ready] { return ready; });
      releasePassTrhough(local);
    });
  }

  {
    std::lock_guard<std::mutex> lock(mtx);
    ready = true;
  }
  cv.notify_all();

  for (auto &thread : threads) {
    thread.join();
  }
  offerers.clear ();
  answerers.clear ();
  pts.clear ();

}

static void
connect_offerers_and_answerers (int number)
{
  std::list<std::shared_ptr<SipRtpEndpoint>>::iterator itOfferer = offerers.begin ();
  std::list<std::shared_ptr<SipRtpEndpoint>>::iterator itAnswerer = answerers.begin ();

  for (int i = 0; i < number; i++) {
	std::string offer = (*itOfferer)->generateOffer ();
	std::string answer = (*itAnswerer)->processOffer (offer);
	
	(*itOfferer)->processAnswer (answer);
	itOfferer++;
	itAnswerer++;
  }
}

static void 
siprtp_load_stress ()
{
	std::shared_ptr <MediaElement> src = createTestSrc();
	create_offerers_and_answerers (NUMBER_OF_ENDPOINTS, src);
	dumpPipeline ("siprtp_load_stress.dot");
	connect_offerers_and_answerers (NUMBER_OF_ENDPOINTS);
	// Wait for 5 seconds
	sleep (20);
	release_offerers_and_answerers ();
	dumpPipeline ("siprtp_load_stress_end.dot");
	releaseTestElement (src);
}


test_suite *
init_unit_test_suite ( int , char *[] )
{
	test_suite *test = BOOST_TEST_SUITE ( "SipRtpEndpointPlay" );

  test->add (BOOST_TEST_CASE ( &siprtp_load_stress ), 0, /* timeout */ 15000);
  return test;
}
