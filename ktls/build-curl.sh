#!/bin/bash -e

VERSION=7.79.1

wget "https://curl.se/download/curl-${VERSION}.tar.gz"
tar xf "curl-${VERSION}.tar.gz"
cd "curl-${VERSION}"
env PKG_CONFIG_PATH=/openssl/lib64/pkgconfig ./configure --with-openssl
make
make install
