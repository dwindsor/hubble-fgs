# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=quay.io/cilium/cilium-builder:2460ae43ce9ab3ab0ff3a8b6e3bc434e6b58e9c0@sha256:97a6aa77af7f8fd5b2cff11ce2049a57e7debec4684652bd368f5911279da4bc
ARG ALPINE_IMAGE=docker.io/library/alpine:3.12.7@sha256:36553b10a4947067b9fbb7d532951066293a68eae893beba1d9235f7d11a20ad

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP

WORKDIR /go/src/github.com/isovalent/hubble-fgs
RUN --mount=type=bind,readwrite,target=/go/src/github.com/isovalent/hubble-fgs --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    make GOARCH=${TARGETARCH} hubble-enterprise-operator-image \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv hubble-enterprise-operator /out/${TARGETOS}/${TARGETARCH}/usr/bin

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${ALPINE_IMAGE} as certs
RUN apk --update add ca-certificates

FROM ${BASE_IMAGE} as release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/hubble-enterprise-operator /usr/bin/hubble-enterprise-operator
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/hubble-enterprise-operator"]
