#!/bin/bash

export GOMAXPROCS=1

echo parameters: $@

/usr/src/app/agwctl $@
