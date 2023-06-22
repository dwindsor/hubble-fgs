FROM ubuntu:22.04 AS builder

COPY build.sh build.sh
RUN apt-get update \
 && apt-get install -y bash build-essential wget \
 && bash build.sh

FROM ubuntu:22.04
COPY --from=builder /openssl /openssl
COPY . .
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y bash build-essential pkg-config strace wget vim \
 && bash build-curl.sh \
 && bash configure.sh

