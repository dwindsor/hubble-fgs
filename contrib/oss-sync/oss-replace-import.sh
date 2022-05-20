#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <package>"
    exit 1
fi

set -e
set -x
pkg="$1"

# prepare commit message
echo "tetragon: use OSS $pkg" > commit.msg
echo "" >> commit.msg
echo "(deleteme)" >> commit.msg
echo "diff between the two:" >> commit.msg
./contrib/oss-sync/oss-diff.py --gocode --gopkg ./$pkg >> commit.msg

# replace imports
git ls-files -- '*.go' ':!:vendor/*' | xargs sed -i "s:github.com/isovalent/hubble-fgs/$pkg\b:github.com/cilium/tetragon/$pkg:g"

# make linters happy (mostly to fix the proper import order)
git ls-files -m -- '*.go' | xargs goimports -w

# remove the module
git rm -r $pkg

# do the vendoring dance
go mod tidy
go mod vendor
go mod verify
git add vendor

git commit -s -v -a -t commit.msg
