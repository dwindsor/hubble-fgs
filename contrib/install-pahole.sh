#!/bin/bash
set -eu
PAHOLE_VERSION="v1.22"

echo "Installing pahole $PAHOLE_VERSION"
git clone --depth=1 --shallow-submodules --recurse-submodules \
  -b "$PAHOLE_VERSION" --single-branch \
  https://git.kernel.org/pub/scm/devel/pahole/pahole.git \
  /tmp/pahole
cd /tmp/pahole
mkdir build
cd build
cmake -D__LIB=lib ..
make
sudo make install
sudo ldconfig /usr/local
