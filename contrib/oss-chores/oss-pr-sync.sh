#!/bin/bash
#
# Create a sync EE branch that syncs with an OSS PR.

declare -A oss2ee=(
	["main"]="master"
	["v1.0"]="v1.12"
	["v1.1"]="v1.13"
	["v1.2"]="v1.14"
	["v1.3"]="v1.15"
	["v1.4"]="v1.16"
)

if [ -z "$1" ]; then
	echo "Usage: $0 <oss_pr_nr>"
	exit 1
fi

set -euxo pipefail

pr="$1"
lbranch="sync-oss-pr-$pr"
ossbase=$(gh -R cilium/tetragon  pr view $pr --json baseRefName --jq .baseRefName)
eebase=${oss2ee[$ossbase]}
git branch $lbranch $eebase

dir="$(git rev-parse --show-toplevel)/../tetragon-${lbranch}"
git worktree add ${dir} ${lbranch}

ossbranch="pr-${pr}"
pushd $dir
make oss-init
git -C modules/tetragon-oss fetch -f origin refs/pull/${pr}/head:${ossbranch}
NO_OSS_DEPFIX=1 ./contrib/oss-chores/oss-sync.sh ${ossbranch}

set +x
echo "EE sync to OSS pr $pr created in $dir"
echo "You can remove everything by:"
echo "git worktree remove --force $dir; git branch -D $lbranch"
