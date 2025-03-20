ARG KURENTO_VERSION=7.1.1
ARG DISTRIB_CODENAME=noble
ARG SIPRTP_VERSION=1.7.0
ARG UBUNTU_VERSION=ubuntu1

FROM kurento/kurento-ci-buildtools:${DISTRIB_CODENAME} AS build_module

ARG KURENTO_VERSION
ARG DISTRIB_CODENAME
ARG SIPRTP_VERSION
ARG UBUNTU_VERSION

ENV KURENTO_VERSION=${KURENTO_VERSION}
ENV DISTRIB_CODENAME=${DISTRIB_CODENAME}
ENV SIPRTP_VERSION=${SIPRTP_VERSION}
ENV UBUNTU_VERSION=${UBUNTU_VERSION}

WORKDIR /app

COPY --from=sources ./debian debian
COPY --from=sources ./src src
COPY --from=sources ./tests tests
COPY --from=sources ./CMakeLists.txt .
COPY --from=sources ./config.h.cmake .
COPY --from=sources ./README.md .

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 5AFA7A83

COPY repo_cfg.tpl /tmp

RUN sed -e "s/\$KURENTO_VERSION/$KURENTO_VERSION/g" -e "s/\$DISTRIB_CODENAME/$DISTRIB_CODENAME/g" /tmp/repo_cfg.tpl > /tmp/repo_cfg
RUN bash -c "source /etc/upstream-release/lsb-release 2>/dev/null || source /etc/lsb-release "
RUN tee "/etc/apt/sources.list.d/kurento.list" >/dev/null < /tmp/repo_cfg \
    && rm /tmp/repo_cfg && apt update

RUN apt install -y --no-install-recommends \
    kurento-media-server-dev

RUN apt install -y equivs devscripts wget

RUN wget -O /app/kurento-buildpackage.sh https://github.com/Kurento/kurento/raw/refs/tags/${KURENTO_VERSION}/ci-scripts/kurento-buildpackage.sh  && chmod a+x /app/kurento-buildpackage.sh
RUN wget -O /app/bash.conf.sh https://github.com/Kurento/kurento/raw/refs/tags/${KURENTO_VERSION}/ci-scripts/bash.conf.sh  && chmod a+x /app/bash.conf.sh

FROM build_module AS siprtp_build

RUN /app/kurento-buildpackage.sh --release

RUN mkdir -p /artifacts && \
    cp /app/*.deb /artifacts

FROM build_module AS siprtp_build_java

RUN mkdir ./build && \
    cd ./build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DGENERATE_JAVA_CLIENT_PROJECT=TRUE .. 

RUN cd build && \
    make java_install && \
    cd java && \
    mvn javadoc:javadoc && \
    cd target/reports/apidocs && \
    ls -la && jar cvf ../../siprtp-javadoc-${SIPRTP_VERSION}.jar * && \
    cd ../.. && \
    mkdir -p /artifacts && \
    cp *.jar /artifacts && \
    cd ../.. 

FROM build_module AS siprtp_build_js

RUN mkdir ./build && \
    cd ./build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DGENERATE_JS_CLIENT_PROJECT=TRUE .. 


RUN cd build/js && \
    npm install --save-dev grunt grunt-browserify grunt-contrib-clean grunt-jsdoc grunt-npm2bower-sync minifyify && \
    cd .. && \
    make js && \
    cd js && \
    ./node_modules/grunt/bin/grunt jsdoc && \
    tar cvfz kurento-module-siprtp-${SIPRTP_VERSION}-jsdoc.tgz doc && \
    mkdir -p /artifacts && \
    cp *.tgz /artifacts && \
    cd ..


FROM kurento/kurento-media-server:${KURENTO_VERSION}

ARG KURENTO_VERSION
ARG DISTRIB_CODENAME
ARG SIPRTP_VERSION
ARG UBUNTU_VERSION

ENV KURENTO_VERSION=${KURENTO_VERSION}
ENV DISTRIB_CODENAME=${DISTRIB_CODENAME}
ENV SIPRTP_VERSION=${SIPRTP_VERSION}
ENV UBUNTU_VERSION=${UBUNTU_VERSION}

# SipRtpEndpoint
COPY --from=siprtp_build /artifacts/kms-siprtpendpoint_${SIPRTP_VERSION}${UBUNTU_VERSION}_amd64.deb /tmp
COPY --from=siprtp_build /artifacts/kms-siprtpendpoint-dbg_${SIPRTP_VERSION}${UBUNTU_VERSION}_amd64.deb /tmp

# For debugging purposes
COPY tracedump_gdb.sh /
COPY tracedump_eu.sh /

# Internal specific configuration
COPY extended_entrypoint.sh /

RUN apt update && apt install --no-install-recommends --yes \
    gdb elfutils

RUN apt update && apt install --no-install-recommends --yes \
    kurento-dbg

# Install kms-siprtp endpoint 
RUN apt update && \
    apt install --no-install-recommends --yes pkg-config && \
    apt install --no-install-recommends --yes /tmp/kms-siprtpendpoint_${SIPRTP_VERSION}${UBUNTU_VERSION}_amd64.deb && \
    apt install --no-install-recommends --yes /tmp/kms-siprtpendpoint-dbg_${SIPRTP_VERSION}${UBUNTU_VERSION}_amd64.deb

RUN mkdir /crash_dumps && sysctl -w kernel.core_pattern=/crash_dumps/core.%p

# Housekeeping
RUN rm /tmp/kms-siprtpendpoint_${SIPRTP_VERSION}${UBUNTU_VERSION}_amd64.deb && \
    rm /tmp/kms-siprtpendpoint-dbg_${SIPRTP_VERSION}${UBUNTU_VERSION}_amd64.deb 

ENTRYPOINT [ "/extended_entrypoint.sh" ]




    






