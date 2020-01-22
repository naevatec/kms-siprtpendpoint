#!/bin/sh

#BUILD_TYPE=Release
#BUILD_TYPE=RelWithDebInfo
BUILD_TYPE=Debug
BUILD_DIR="build-$BUILD_TYPE"
mkdir "$BUILD_DIR" && cd "$BUILD_DIR"
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DGENERATE_JAVA_CLIENT_PROJECT=TRUE -DGENERATE_JS_CLIENT_PROJECT=TRUE ..

make 
make test_constructors
make test_sip_rtp_endpoint
make test_sip_rtp_endpoint_play
make test


make java_install
cd java
mvn javadoc:javadoc
cd ..

cd js
npm install --save-dev grunt-browserify grunt-contrib-clean grunt-jsdoc grunt-npm2bower-sync minifyify
cd ..

make js

sudo ../../adm-scripts/kurento-buildpackage.sh --srcdir ..
