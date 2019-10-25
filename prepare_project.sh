#!/bin/sh
i
#BUILD_TYPE=Release
#BUILD_TYPE=RelWithDebInfo
BUILD_TYPE=Debug
BUILD_DIR="build-$BUILD_TYPE"
mkdir "$BUILD_DIR" && cd "$BUILD_DIR"
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DGENERATE_JAVA_CLIENT_PROJECT=TRUE -DGENERATE_JS_CLIENT_PROJECT=TRUE ..

make 
make test_datachannel
make test


make java_install

