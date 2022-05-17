#!/usr/bin/env python3

import os
import subprocess as sp
import filecmp as fc
import argparse as ap

# NB(kkourt): this needs to be run from the top-level directory
oss_path = "./modules/tetragon-oss/"
ent_path = "./"

def get_packages(path, pkg):
    oldpath = os.getcwd()
    os.chdir(path)
    try:
        args = ("go", "list", pkg)
        p = sp.Popen(args, stdout=sp.PIPE)
        p.wait()
        out = p.stdout.read()
    finally:
        os.chdir(oldpath)
    return (l for l in out.decode("utf-8").split("\n") if l != '')

def remove_prefix(s, prefix):
    if not s.startswith(prefix):
        assert False, "%s does not start with %s" % (s, prefix)
    return s[len(prefix):]

def check_go_code(conf):
    pkg = conf.gopkg
    oss_prefix = "github.com/cilium/tetragon/"
    ent_prefix = "github.com/isovalent/hubble-fgs/"
    oss_packages = set(remove_prefix(s, oss_prefix) for s in get_packages(oss_path, pkg))
    ent_packages = set(remove_prefix(s, ent_prefix) for s in get_packages(ent_path, pkg))
    for package in sorted(ent_packages.union(oss_packages)):
        oss_p = package in oss_packages
        ent_p = package in ent_packages
        if oss_p and ent_p:
            if conf.no_diff:
                print(package)
                continue
            #print(" - [ ] %s" % (package,))
            oss_dir = os.path.join(oss_path, package)
            ent_dir = os.path.join(ent_path, package)
            args = ["diff", "-rNu"]
            if conf.diff_ignore_comments:
                args += ["-I", "^//"]
            args.extend((ent_dir,  oss_dir))
            p = sp.Popen(args, stdout=sp.PIPE)
            out = p.stdout.read().decode('utf-8')
            if len(out) > 0:
                print("#### %s is in BOTH OSS/ENT" % (package,))
                for l in out.split('\n'):
                    print(l,)
            else:
                print("#### %s is in BOTH OSS/ENT" % (package,))
                print("no differences.")
            p.wait()
            #diff = fc.dircmp(ent_dir, oss_dir)
            #diff.report_full_closure()
        elif oss_p:
            #print("#### %s is in OSS only" % (package,))
            pass
        elif ent_p:
            #print("#### %s is in ENT only" % (package,))
            pass
        else:
            assert False, "wait, what?"


def check_bpf_code(conf):
    def print_common_files(dcmp):
        for name in dcmp.common_files:
            oss_f = os.path.join(dcmp.left, name)
            ent_f = os.path.join(dcmp.right, name)
            args = ("diff", "-rNu", ent_f,  oss_f)
            p = sp.Popen(args, stdout=sp.PIPE)
            out = p.stdout.read().decode('utf-8')
            if len(out) > 0:
                for l in out.split('\n'):
                    print(l,)
            else:
                print("#### ", ent_f, " is the same")
                pass
            p.wait()
        for sub_dcmp in dcmp.subdirs.values():
            print_common_files(sub_dcmp)
    oss_dir = os.path.join(oss_path, "bpf")
    ent_dir = os.path.join(ent_path, "bpf")
    dcmp = fc.dircmp(oss_dir, ent_dir, ignore=['Makefile',])
    print_common_files(dcmp)
    #diff.report_full_closure()

if __name__ == "__main__":
    parser = ap.ArgumentParser()
    parser.add_argument('--bpfcode', help='check bpf code', action='store_true')
    parser.add_argument('--gocode', help='check go code', action='store_true')
    parser.add_argument('--gopkg', default=None, nargs='?', help='specify go package')
    parser.add_argument('--no-diff', action='store_true')
    parser.add_argument('--diff-ignore-comments', action='store_true')
    args = parser.parse_args()

    if (not args.bpfcode) and (not args.gocode):
        print("please specify --bpfcode or --gocode")
    if args.gocode:
        # if no specific go pckage is specified do all of them, and disable diffs
        if args.gopkg is None:
            args.gopkg = "./..."
            args.no_diff = True
        check_go_code(args)

    if args.bpfcode:
        check_bpf_code(args)
