#!/usr/bin/env python3
"""Write one binary manifest consumed by the native JVMTI smoke-test agent."""

import argparse
import pathlib
import struct

parser = argparse.ArgumentParser()
parser.add_argument("--signature", required=True)
parser.add_argument("--class-file", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

signature = args.signature.encode("ascii")
class_bytes = pathlib.Path(args.class_file).read_bytes()
if len(signature) > 0xFFFF or len(class_bytes) > 16 * 1024 * 1024:
    raise SystemExit("class signature or bytecode exceeds the manifest limit")
if not class_bytes.startswith(b"\xca\xfe\xba\xbe"):
    raise SystemExit("input is not a Java class file")

record = struct.pack(">HI", len(signature), len(class_bytes)) + signature + class_bytes
pathlib.Path(args.output).write_bytes(b"TGJVP1\0" + struct.pack(">I", 1) + record)
