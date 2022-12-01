ARG KMS_VERSION="6.18.0_bionic"
FROM naevatec/kurento-media-server:${KMS_VERSION}

ARG UBUNTU_VERSION="18.04"
ARG SIPRTPEP_VERSION="1.1.2"


MAINTAINER Saul Labajo <slabajo@naevatec.com>


RUN apt-get update \
  && apt-get install -y  libjemalloc1

ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.1

COPY kms-siprtpendpoint_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb /tmp

RUN apt install /tmp/kms-siprtpendpoint_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb && \
    rm /tmp/kms-siprtpendpoint_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb


# TODO: ensure debug symbols are installes for kurento
#COPY tracedump_gdb.sh /
#COPY tracedump_eu.sh /
#COPY extended_entrypoint.sh /
#
#RUN apt update && apt install --no-install-recommends --yes \
#    gdb elfutils
#
#RUN apt update && apt install --no-install-recommends --yes \
#    kurento-dbg
#COPY kms-siprtpendpoint-dbg_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb /tmp
#RUN apt install /tmp/kms-siprtpendpoint-dbg_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb && \
#    rm /tmp/kms-siprtpendpoint-dbg_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb

