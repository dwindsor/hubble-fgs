#!/bin/bash -e

# Install openssl under /openssl
wget -q https://www.openssl.org/source/openssl-3.0.0.tar.gz
tar xf openssl-3.0.0.tar.gz
cd openssl-3.0.0
./Configure --prefix=/openssl --openssldir=/openssl enable-ktls
make
make install
