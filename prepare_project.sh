#!/bin/sh

BUILD_TYPE=Release
#BUILD_TYPE=RelWithDebInfo
#BUILD_TYPE=Debug
BUILD_DIR="build-$BUILD_TYPE"
mkdir "$BUILD_DIR" && cd "$BUILD_DIR"
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DGENERATE_JAVA_CLIENT_PROJECT=TRUE -DGENERATE_JS_CLIENT_PROJECT=TRUE ..

make 
make test_constructors
make test_sip_rtp_endpoint
make test_sip_rtp_endpoint_play
make test_sip_rtp_endpoint_agnostic_srtp
make test_event_forwarding
make test_source_connections
make test_codecs_config
make public_ip
make test


make java_install
cd java
mvn javadoc:javadoc
cd target
jar cvf siprtp-javadoc-1.4.0.jar site
cd ..
cd ..

cd js
npm install --save-dev grunt grunt-browserify grunt-contrib-clean grunt-jsdoc grunt-npm2bower-sync minifyify
cd ..
make js
cd js
./node_modules/grunt/bin/grunt jsdoc
tar cvfz kurento-module-siprtp-1.4.0-jsdoc.tgz doc
cd ..

sudo ../../adm-scripts/kurento-buildpackage.sh --srcdir ..
