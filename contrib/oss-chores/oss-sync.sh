#!/bin/bash
#
# This script creates a commit that updates to the given OSS branch. If no argument is provided, the
# script will update to the latest main branch on OSS. Otherwise, it will checkout and update based
# on the given argument. For example, for testing a PR on oss, users can use the name of the branch
# there under orign, e.g., origin/pr/kkourt/pizza-is-the-best.
#
# NB(kkourt): please treat this as beta for now, since there might be things that I've missed.

set -e
#set -x

v=""
if [ -z "$1" ]; then
	v=$(git config -f .gitmodules --get submodule.modules/tetragon-oss.branch)
	echo "No argument specified: using default branch: $v"
else
	custom_branch=1
	v="$1"
fi

# Ensure that there are no pending changes
git diff --quiet || (echo "There are pending changes, bailing out" && false)
git diff --quiet --cached || (echo "There are pending changes in the cache, bailing out" && false)

# get the current (old) sha of OSS
old_sha=$(git submodule status modules/tetragon-oss | awk '{ print $1 }')

# checkout the new OSS version
pushd modules/tetragon-oss
git status
git fetch
git checkout $v
if [ "$custom_branch" != "1" ]; then
	git merge --ff-only origin/$v
fi
popd

# get the new sha of OSS
new_sha=$(git submodule status modules/tetragon-oss | awk '{ print $1 }' | sed -e 's/^\+//')

if [ "$old_sha" = "$new_sha" ]; then
	echo "OSS in sync, nothing to do"
	exit 0
fi

# create a temp file for the log message
outf=$(mktemp oss-update.log.XXXXX)
trap 'rm -f -- "$outf"' EXIT
echo "chore: OSS sync" >> $outf
echo "" >> $outf
echo "Synching from $old_sha to $new_sha." >> $outf
echo "Commits:" >> $outf
echo "" >> $outf
git -C modules/tetragon-oss log --pretty=' * cilium/tetragon@%h (%s)'  $old_sha..$new_sha >> $outf

cp modules/tetragon-oss/pkg/k8s/apis/cilium.io/v1alpha1/types.go pkg/k8s/apis/cilium.io/v1alpha1/oss-types.go

# Refresh copies of OSS k8s packages that were previously symlinked.
# These must be real files (not symlinks) so the module can be fetched
# via the Go module proxy (symlinks are not preserved in module zips).
rm -rf pkg/k8s/slim pkg/k8s/versioncheck
cp -R modules/tetragon-oss/pkg/k8s/slim pkg/k8s/slim
cp -R modules/tetragon-oss/pkg/k8s/versioncheck pkg/k8s/versioncheck
make generate
make codegen
make vendor
git add go.mod go.sum vendor pkg/k8s modules/tetragon-oss api

# Generate Helm chart
make -C install/kubernetes
git add install/kubernetes/tetragon

# Generate metrics docs
make metrics-docs || echo "Metrics docs generation failed. Please fix the enterprise code and run 'make metrics-docs'."
git add docs/metrics

# Generate flags docs
make generate-flags
git add docs/configuration/tetragon_flags.yaml

git commit -s -F $outf
