#!/usr/bin/env bash
# `|| true` because systemctl status returns non-zero for inactive/masked units;
# a masked acsockd.service reports: Loaded: masked (/dev/null; ...)
systemctl status acsockd.service --no-pager || true
