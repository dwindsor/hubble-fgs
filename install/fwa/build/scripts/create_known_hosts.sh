#!/bin/sh
#
# This script creates a known_hosts file for SSH inside the NEP build
# container. The ED25519 fingerprint for github.com is pinned here to the
# value published on their website to mitigate man-in-the-middle concerns.
set -eu
mkdir -p ~/.ssh
ssh-keyscan -t ed25519 github.com > ~/.ssh/known_hosts

# ED25519 fingerprint from https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
if ! ssh-keygen -lf ~/.ssh/known_hosts | grep -q "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"; then
  echo "ERROR: github.com host key mismatch!" >&2
  exit 1
fi
