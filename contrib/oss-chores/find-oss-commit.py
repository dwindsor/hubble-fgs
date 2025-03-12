#!/bin/python3

# script to locate in what EE commit and OSS commit was merged.
#
# Example:
# $ ./contrib/oss-chores/find-oss-commit.py 2652255b3
# 097085fed
#

import subprocess as sp
import os.path
import sys

def main(needleshortsha):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    repoPath = os.path.realpath("{}/../../".format(script_dir))
    ossPath = "{}/modules/tetragon-oss".format(repoPath)

    args = ("git", "-C", ossPath, "rev-parse", needleshortsha)
    p = sp.run(args, capture_output=True)
    needlesha = p.stdout.decode("utf-8").rstrip()
    args = ("git", "-C", repoPath, "log", "--raw", "--format=%h", "modules/tetragon-oss")
    p = sp.Popen(args, stdout=sp.PIPE)
    p.wait()
    out = p.stdout.read()
    lines = (l for l in out.decode("utf-8").split("\n") if l != '')
    for line in lines:
        eesha = line
        nextline = next(lines)
        _, _, oldsha, newsha, _, _ = nextline.split()
        args = ("git", "-C", ossPath, "rev-list", "--ancestry-path", "{}..{}".format(oldsha, newsha))
        p = sp.run(args, capture_output=True)
        xlines = (l for l in p.stdout.decode("utf-8").split("\n") if l != '')
        for xl in xlines:
            if needlesha == xl:
                print(eesha)

if __name__ == '__main__':
    needle_sha = sys.argv[1]
    main(needle_sha)
