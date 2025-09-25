## General build args
ARG BUILD_PLATFORM=linux/amd64
ARG TARGET=nep

## Stratocaster base container image
FROM --platform=${BUILD_PLATFORM} ubuntu:22.04 AS stratocaster-base
ENV PLATFORM=generic
RUN apt-get update && apt-get install -y make xz-utils curl dpkg vim

## NEP base container image
FROM --platform=${BUILD_PLATFORM} ubuntu:22.04 AS nep-base
ENV PLATFORM=generic
RUN apt-get update && apt-get install -y make xz-utils curl dpkg vim

## Elba base container image
FROM --platform=${BUILD_PLATFORM} centos:7.9.2009 AS elba-base
ENV PLATFORM=elba
# Fixup the bad repo URLs
RUN sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/CentOS-* && \
   sed -i "s|#.*baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
# Add the buildlogs repo for the newer devtoolsets
COPY ./install/fwa/build/patches/llvmtoolset-build.repo  /etc/yum.repos.d/llvmtoolset-build.repo
RUN yum clean all && yum update -y && yum groupinstall -y "Development Tools" && yum install -y openssl-devel glibc-static
# Install version 10 toolset and their deps
RUN yum install -y devtoolset-8 devtoolset-9 llvm-toolset-9.0 devtoolset-10 llvm-toolset-10.0
# Build newer cmake for packaging
ARG CMAKE_VERSION=3.28.3
RUN cd `mktemp -d` && \
    curl -OL https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}.tar.gz && \
    tar -xvf cmake-${CMAKE_VERSION}.tar.gz && \
    cd cmake-${CMAKE_VERSION} && \
    ./bootstrap && \
    make && \
    make install
# Set the compiler and linker versions for the toolchain builds below
SHELL [ "/usr/bin/scl", "enable", "devtoolset-10" , "llvm-toolset-10.0" ]
# Fix a bug in the centos docker where the locale gets clobbered
RUN localedef -i en_US -f UTF-8 en_US.UTF-8
# Setup persisent env
RUN echo "source scl_source enable devtoolset-10" > /etc/profile.d/devtoolset.sh  && \
    echo "source scl_source enable llvm-toolset-10.0" >> /etc/profile.d/devtoolset.sh  && \
    echo "export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib64/pkgconfig:/usr/lib/pkgconfig" > /etc/profile.d/pkgconfig.sh && \
    echo "export LC_ALL=en_US.UTF-8" > /etc/profile.d/lang.sh
# Vpp build patches and dependencies
RUN sed -i 's/const struct timespec \*__tmo);/struct timespec \*__tmo);/' /usr/include/sys/socket.h

## Base container image
# Setting commit sha for packaging
FROM ${TARGET}-base AS base
ARG GIT_COMMIT_SHA=000aaa
ENV GIT_COMMIT_SHA=${GIT_COMMIT_SHA}
COPY ./.git /src/.git

## Agent build stage
FROM base AS agent-base
COPY ./install/fwa/agent/deps /src/agent/deps
WORKDIR /src/agent/deps
RUN make all

## Agent package stage
# The gitconfig file from the host is base64 encoded and passed through GITCONFIG variable
FROM agent-base AS agent-build
ARG GITHUB_TOKEN=""
ARG USE_HTTPS=false
RUN if [ "$USE_HTTPS" = "true" ] ; then \
    git config --global url."https://$GITHUB_TOKEN@github.com/".insteadOf "https://github.com/" ; \
else \
    git config --global url."ssh://git@github.com/".insteadOf "https://github.com/" ; \
fi
COPY . /hubble-fgs
WORKDIR /hubble-fgs
RUN --mount=type=ssh ./install/fwa/build/scripts/create_known_hosts.sh
RUN --mount=type=ssh make fwa
# RUN --mount=type=ssh make fwactl
COPY fwa /src/agent
# COPY fwactl /src/agent
COPY ./install/fwa/agent /src/agent
COPY ./install/fwa/Makefile /src/Makefile
WORKDIR /src/agent
RUN make package
## Final runtime stage
# Sends error message if startup or service scripts are failing
FROM base AS runtime
COPY --from=agent-build /src/agent/dist /src/dist

## NEP container target
FROM runtime AS nep
WORKDIR /src
ENTRYPOINT ["/bin/bash", "-c", "trap : TERM INT; sleep infinity & wait"]

## Catalyst Stratocaster container target
# Adds script to run at container startup
# Deleting /src after install because this image is delivered to customer
FROM runtime AS stratocaster
WORKDIR /src
ENTRYPOINT ["/bin/bash", "-c", "trap : TERM INT; sleep infinity & wait"]

## Elba container target
FROM runtime AS elba
# Install SCL - we do this late to avoid overriding the buildlogs versions of the toolsets
RUN yum install -y centos-release-scl
WORKDIR /src
ENTRYPOINT ["/bin/bash", "-c", "trap : TERM INT; sleep infinity & wait"]
