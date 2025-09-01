#!/bin/sh

if /usr/src/app/agwctl health | grep -q 'healthy'
then
  exit 0
else
  exit 1
fi

