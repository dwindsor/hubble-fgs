FROM quay.io/lvh-images/lvh:v0.0.1 as lvh

FROM debian:sid

COPY --from=lvh /usr/bin/lvh /usr/bin/lvh

# Install build dependencies
RUN apt-get -y update
RUN apt-get install --quiet -y --no-install-recommends \
        mmdebstrap \
        libguestfs-tools \
        qemu-utils \
        extlinux \
        linux-image-amd64 \
        netcat-openbsd \
        zstd
RUN apt-get clean autoclean

CMD lvh images build --dir /host/_data

# vi:ft=dockerfile
