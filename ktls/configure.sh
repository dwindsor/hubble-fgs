#!/bin/bash -e

patch /openssl/openssl.cnf < openssl.cnf.patch
echo export LD_LIBRARY_PATH=/usr/local/lib:/openssl/lib64 >> /root/.bashrc
