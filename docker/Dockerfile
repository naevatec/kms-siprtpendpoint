ARG KMS_VERSION="6.17"
FROM kurento/kurento-media-server:${KMS_VERSION}

ARG UBUNTU_VERSION="16.04"
ARG SIPRTPEP_VERSION="1.1.0"


MAINTAINER Saul Labajo <slabajo@naevatec.com>

COPY kms-siprtpendpoint_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb /tmp

RUN apt install /tmp/kms-siprtpendpoint_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb && \
    rm /tmp/kms-siprtpendpoint_${SIPRTPEP_VERSION}.${UBUNTU_VERSION}_amd64.deb