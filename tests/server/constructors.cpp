/*
 * (C) Copyright 2014 Kurento (http://kurento.org/)
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

#include <glibmm/module.h>
#include <FactoryRegistrar.hpp>
#include <ModuleManager.hpp>
#include "SipRtpEndpoint.hpp"
#include <MediaObjectImpl.hpp>
#include <KurentoException.hpp>
#include <MediaElement.hpp>
#include <MediaPipelineImpl.hpp>
#include <jsonrpc/JsonSerializer.hpp>
#include <MediaSet.hpp>
#include <gst/gst.h>
#include <config.h>
#include <gmodule.h>

boost::property_tree::ptree config;

void
testSipRtpEndpoint (kurento::ModuleManager &moduleManager,
                 std::shared_ptr <kurento::MediaObjectImpl> mediaPipeline)
{
  kurento::JsonSerializer w (true);

  w.SerializeNVP (mediaPipeline);

  std::shared_ptr <kurento::MediaObjectImpl >  object =
    moduleManager.getFactory ("SipRtpEndpoint")->createObject (config, "",
        w.JsonValue);
  std::shared_ptr <kurento::SipRtpEndpoint> siprtp = std::dynamic_pointer_cast<kurento::SipRtpEndpoint > (object);
  kurento::MediaSet::getMediaSet()->release (object);
}

void
show_library ()
{
	  GstPluginDesc *desc;
	  GModule *module;
	  gboolean ret;
	  GModuleFlags flags;
	  gpointer ptr;


	  flags = G_MODULE_BIND_LOCAL;
	  module = g_module_open ("/home/devel/kms-omni-build/build-Debug/kms-siprtpendpoint/src/gst-plugins/siprtpendpoint/libsiprtpendpoint.so", flags);
	  ret = g_module_symbol (module, "gst_plugin_desc", &ptr);
	  desc = (GstPluginDesc *) ptr;

	  if (desc != NULL)
		  ret = 0;

	  if (ret == 0)
		  desc = NULL;
}

int
main (int argc, char **argv)
{
  std::shared_ptr <kurento::MediaObjectImpl> mediaPipeline;
  std::shared_ptr <kurento::Factory> factory;

  show_library();

  gst_init (&argc, &argv);

  kurento::ModuleManager moduleManager;

  //moduleManager.loadModulesFromDirectories ("./src/server:../../kms-omni-build:../../src/server:../../../../kms-omni-build");
  moduleManager.loadModulesFromDirectories ("../../src/server:./");

  mediaPipeline = moduleManager.getFactory ("MediaPipeline")->createObject (
                    config, "",
                    Json::Value() );

  config.add ("configPath", "../../../tests" );
  config.add ("modules.kurento.SdpEndpoint.numAudioMedias", 0);
  config.add ("modules.kurento.SdpEndpoint.numVideoMedias", 0);
  config.add ("modules.kurento.SdpEndpoint.audioCodecs", "[]");
  config.add ("modules.kurento.SdpEndpoint.videoCodecs", "[]");

  testSipRtpEndpoint (moduleManager, mediaPipeline);

  kurento::MediaSet::getMediaSet()->release (mediaPipeline);

  return 0;
}
