# Copyright (C) Isovalent, Inc. - All Rights Reserved.

ARG BASE_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon-aggregator:stage_1

FROM ${BASE_IMAGE} AS release

LABEL name="Isovalent Tetragon Aggregator" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Isovalent Tetragon Aggregator image" \
      description="Isovalent Tetragon Aggregator image built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Tetragon Aggregator image" \
      org.opencontainers.image.description="Isovalent Tetragon Aggregator image built on top of Red Hat Universal Base Image" \
      io.k8s.description="Isovalent Tetragon Aggregator image built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Isovalent Tetragon Aggregator"

ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"
ARG VERSION=0.0.0
LABEL version=${VERSION}

USER root
COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
USER 65532
