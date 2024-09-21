ARG KMS_VERSION="7.1.0"
FROM kurento/kurento-media-server:${KMS_VERSION}

ARG UBUNTU_VERSION="24.04"
ARG SIPRTPEP_VERSION="1.5.2"

MAINTAINER Saul Labajo <slabajo@naevatec.com>


# Jemalloc seems to have problems with Kurento 7
#RUN apt-get update \
#  && apt-get install -y  libjemalloc1
#
#ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.1

# tcmalloc seems to be working good however
RUN apt-get update \
   && apt-get install -y google-perftools

ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libtcmalloc.so.4

# SipRtpEndpoint 1.5.1
COPY kms-siprtpendpoint_${SIPRTPEP_VERSION}ubuntu1_amd64.deb /tmp
COPY kms-siprtpendpoint-dbg_${SIPRTPEP_VERSION}ubuntu1_amd64.deb /tmp

# Gladstone G729 codec for GStreamer
COPY kurento-gladstone_1.1.0.0ubuntu2_amd64.deb /tmp
COPY kurento-gladstone-dbg_1.1.0.0ubuntu2_amd64.deb /tmp
COPY kurento-gladstone-dbgsym_1.1.0.0ubuntu2_amd64.ddeb /tmp

# For debugging purposes
COPY tracedump_gdb.sh /
COPY tracedump_eu.sh /

# Internal specific configuration
COPY extended_entrypoint.sh /

RUN apt update && apt install --no-install-recommends --yes \
    gdb elfutils

RUN apt update && apt install --no-install-recommends --yes \
    kurento-dbg

# Install kms-siprtp endpoint 1.5.1,
RUN apt update && \
    apt install --no-install-recommends --yes pkg-config && \
    apt install --no-install-recommends --yes /tmp/kms-siprtpendpoint_${SIPRTPEP_VERSION}ubuntu1_amd64.deb && \
    apt install --no-install-recommends --yes /tmp/kms-siprtpendpoint-dbg_${SIPRTPEP_VERSION}ubuntu1_amd64.deb

# Install G729 codec for GStreamer
RUN apt install --no-install-recommends --yes /tmp/kurento-gladstone_1.1.0.0ubuntu2_amd64.deb && \
    apt install --no-install-recommends --yes /tmp/kurento-gladstone-dbg_1.1.0.0ubuntu2_amd64.deb && \
    apt install --no-install-recommends --yes /tmp/kurento-gladstone-dbgsym_1.1.0.0ubuntu2_amd64.ddeb

RUN mkdir /crash_dumps && sysctl -w kernel.core_pattern=/crash_dumps/core.%p

# Housekeeping
RUN rm /tmp/kms-siprtpendpoint_${SIPRTPEP_VERSION}ubuntu1_amd64.deb && \
    rm /tmp/kms-siprtpendpoint-dbg_${SIPRTPEP_VERSION}ubuntu1_amd64.deb && \
    rm /tmp/kurento-gladstone_1.1.0.0ubuntu2_amd64.deb && \
    rm /tmp/kurento-gladstone-dbg_1.1.0.0ubuntu2_amd64.deb && \
    rm /tmp/kurento-gladstone-dbgsym_1.1.0.0ubuntu2_amd64.ddeb


















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

