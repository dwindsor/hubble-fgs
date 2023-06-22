#!/bin/bash -e

VERSION=3.0.0

# Install openssl under /openssl
wget -q "https://www.openssl.org/source/openssl-${VERSION}.tar.gz"
tar xf "openssl-${VERSION}.tar.gz"
cd "openssl-${VERSION}"
./Configure --prefix=/openssl --openssldir=/openssl enable-ktls
make
make install
