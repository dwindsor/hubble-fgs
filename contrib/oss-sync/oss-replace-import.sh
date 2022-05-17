#!/bin/bash


if [ -z "$1" ]; then
    echo "Usage: $0 <package>"
    exit 1
fi

set -e
set -x
pkg="$1"

# replace imports
git ls-files -- '*.go' ':!:vendor/*' | xargs sed -i "s:github.com/isovalent/hubble-fgs/$pkg:github.com/cilium/tetragon/$pkg:g"

git diff
echo "Does above look OK (enter if so, Ctrl-C otherwise)?"
read

# do the vendoring dance
go mod tidy
go mod vendor
go mod verify

# make linters happy (mostly to fix the proper import order)
git ls-files -m -- '*.go' | xargs goimports -w

echo "Done! Dont forget to:"
echo "git rm -r $pkg"
echo "to remove the module"
