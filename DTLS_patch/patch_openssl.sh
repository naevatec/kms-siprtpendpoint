#!/bin/sh

DEFAULT_IMAGE_NAME='kurento/kurento-media-server'
DEFAULT_IMAGE_VERSION='7.0.0'

IMAGE_NAME="${1:-$DEFAULT_IMAGE_NAME}"
IMAGE_VERSION="${2:-$DEFAULT_IMAGE_VERSION}"

git clone  https://github.com/openssl/openssl
cd openssl
git checkout OpenSSL_1_1_1
git apply ../openssl111.patch
./config shared
make
cd ..
cp -a openssl/lib* docker 
cd docker 
docker build --build-arg IMAGE_NAME=$IMAGE_NAME --build-arg IMAGE_VERSION=$IMAGE_VERSION --tag $IMAGE_NAME:${IMAGE_VERSION}_patched_ssl .
cd ..
rm -rf openssl
