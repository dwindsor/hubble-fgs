#!/bin/bash -e

wget https://curl.se/download/curl-7.79.1.tar.gz
tar xf curl-7.79.1.tar.gz
cd curl-7.79.1
env PKG_CONFIG_PATH=/openssl/lib64/pkgconfig ./configure --with-openssl
make
make install
