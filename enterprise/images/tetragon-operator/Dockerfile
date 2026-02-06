# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG BASE_IMAGE=quay.io/isovalent/tetragon-operator:stage_1

FROM ${BASE_IMAGE} AS release

LABEL name="Isovalent Tetragon Operator" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Isovalent Tetragon Operator image" \
      description="Isovalent Tetragon Operator image built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Tetragon Operator image" \
      org.opencontainers.image.description="Isovalent Tetragon Operator image built on top of Red Hat Universal Base Image" \
      io.k8s.description="Isovalent Tetragon Operator image built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Isovalent Tetragon Operator"

ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
