#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <javac> <output-dir>" >&2
    exit 2
fi
javac=$1
out=$2
mkdir -p "$out/original-src/smoke" "$out/fixed-src/smoke" "$out/original" "$out/fixed"
sed 's/VULNERABLE/PATCHED/' "$(dirname "$0")/PatchProbe.java" > "$out/fixed-src/smoke/PatchProbe.java"
cp "$(dirname "$0")/PatchProbe.java" "$out/original-src/smoke/PatchProbe.java"
"$javac" --release 11 -d "$out/original" "$out/original-src/smoke/PatchProbe.java"
"$javac" --release 11 -d "$out/fixed" "$out/fixed-src/smoke/PatchProbe.java"
