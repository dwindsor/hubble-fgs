#!/bin/bash

# Usage: golangci-lint --config .golangci.yml run | ./contrib/fix-revive-unused.sh
#
# Repeat as many times as needed until all unused params are gone. Note that
# this solution is NOT a catch-all. You should still inspect the output by hand
# to see if anything can be eliminated.

# Parse out revive output for lines that contain the keyword "revive" and
# "unused-paramter". We capture: the filename, the line number, the column
# number, and the variable name. We then use those values to craft a sed command
# that will replace exactly that variable in exactly that position with a '_'.
awk '$2 ~ /revive/ && $3 ~ /unused-parameter/ { gsub(/'\''/, "", $5); match($1, /([^:]*):([0-9]*):([0-9]*)/, cap); printf("'\''%ds/\\(.\\{%d\\}.*\\)\\b%s\\b/\\1_/'\'' %s\n", cap[2], cap[3] - 1, $5, cap[1]);}' | xargs -L1 sed -i