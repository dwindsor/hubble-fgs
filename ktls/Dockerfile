FROM ubuntu:hirsute-20210917 AS builder

COPY build.sh build.sh
RUN apt-get update \
 && apt-get install -y bash build-essential wget \
 && bash build.sh

FROM ubuntu:hirsute-20210917
COPY --from=builder /openssl /openssl
COPY . .
RUN apt-get update \
 && apt-get install -y bash build-essential pkg-config strace wget \
 && bash build-curl.sh \
 && bash configure.sh

