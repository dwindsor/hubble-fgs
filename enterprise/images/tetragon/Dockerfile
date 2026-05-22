# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# This Dockerfile builds the Tetragon UBI image without modifying the
# root Dockerfile. It takes the standard release image as SOURCE_IMAGE,
# copies all binaries and BPF objects into a UBI-minimal base, installs
# runtime dependencies, and adds Red Hat certification labels.

ARG SOURCE_IMAGE=artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon:latest
ARG UBI_IMAGE=registry.redhat.io/ubi9/ubi-minimal:9.7@sha256:42c0bdc0534c1465e623a193929a66e9abeb214c61c80c360d99a2a491b0336b

FROM ${SOURCE_IMAGE} AS source

FROM ${UBI_IMAGE} AS release

# Install runtime dependencies
RUN microdnf install -y --nodocs iproute bash && \
    microdnf clean all

# Recreate directory structure
RUN mkdir -p /var/lib/tetragon/ \
             /var/run/tetragon/ \
             /etc/tetragon/tetragon.conf.d/ \
             /etc/tetragon/tetragon.tp.d/ \
             /etc/tetragon/tetragon.policies.d/ \
             libs

# Copy all binaries and BPF objects from the source release image
COPY --from=source /usr/bin/tetragon /usr/bin/
COPY --from=source /usr/bin/tetra /usr/bin/
COPY --from=source /usr/bin/gops /usr/bin/
COPY --from=source /usr/bin/bpftool /usr/bin/
COPY --from=source /var/lib/tetragon/ /var/lib/tetragon/

ENTRYPOINT ["/usr/bin/tetragon"]

LABEL name="Isovalent Tetragon" \
      maintainer="support@isovalent.com" \
      vendor="Isovalent" \
      release="1" \
      summary="Isovalent Tetragon image" \
      description="Isovalent Tetragon image built on top of Red Hat Universal Base Image" \
      org.opencontainers.image.authors="Isovalent" \
      org.opencontainers.image.url="https://isovalent.com" \
      org.opencontainers.image.documentation="https://isovalent.com/product" \
      org.opencontainers.image.vendor="Isovalent, part of Cisco" \
      org.opencontainers.image.title="Isovalent Tetragon image" \
      org.opencontainers.image.description="Isovalent Tetragon image built on top of Red Hat Universal Base Image" \
      io.k8s.description="Isovalent Tetragon image built on top of Red Hat Universal Base Image" \
      io.k8s.display-name="Isovalent Tetragon"

ARG BUILD_DATE
LABEL org.opencontainers.image.created="${BUILD_DATE}"
ARG VERSION=0.0.0
LABEL version=${VERSION}

COPY LICENSE /usr/share/licenses/isovalent/
RUN ln -s /usr/share/licenses /licenses
