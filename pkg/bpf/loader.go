// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

package bpf

/*
#cgo CFLAGS: -I ../../bpf/include -I ../../bpf/libbpf/ -I ../../bpf/lib/
#cgo LDFLAGS: -lbpf -lelf -lz

#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "libbpf.h"
#include "libbpf__bpf.h"
#include "hubble_msg.h"

#define NUM_PAGES 8
// hash map only added updates from map value in 4.18
#define MIN_HASH_VERSION 266752

#ifndef BPF_PROG_TYPE_SK_MSG
#define BPF_PROG_TYPE_SK_MSG 16
#endif

#ifndef BPF_SK_MSG_VERDICT
#define BPF_SK_MSG_VERDICT 7
#endif

static int __print(enum libbpf_print_level level __attribute__((unused)),
		   const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int __quiet(enum libbpf_print_level level __attribute__((unused)),
		   const char *format, va_list args)
{
}

void bpf_loader_programs(struct bpf_object *obj, int type, int verbosity) {
	struct bpf_program *prog_bpf;

	bpf_object__for_each_program(prog_bpf, obj) {
		bpf_program__set_type(prog_bpf, type);
		if (verbosity)
			fprintf(stderr,
				"program: kern_version: %u\n",
				bpf_object__kversion(obj));
	}
}

int fgs_map_loader(const int version,
		   const int verbosity,
		   const char *btf,
		   const char *prog,
		   const char *__map,
		   const char *__label_map,
	   	   const int type)
{
	struct bpf_object_load_attr attr = {0};
	struct bpf_program *prog_bpf;
	struct bpf_map *map_bpf;
	struct bpf_map_def *map_def;
	struct bpf_object *obj;
	int err, map_fd;

	if (verbosity > 1)
		libbpf_set_print(__print);
	else
		libbpf_set_print(__quiet);

	obj = bpf_object__open(prog);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open: %i %s\n", err, prog);
		return err;
	}

	bpf_loader_programs(obj, type, verbosity);

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr,
			"bpf_object__load_xattr: failed %i: %s\n",
			err, errstr);
		goto cleanup;
	}


	map_bpf = bpf_object__find_map_by_name(obj, __label_map);
	err = libbpf_get_error(map_bpf);
	if (err) {
		fprintf(stderr,
			"bpf_object__find_map_by_name: obj(%s) map(%s) failed",
			prog, __label_map);
		goto cleanup;
	}

	err = libbpf_get_error(obj);
	bpf_map__unpin(map_bpf, __map);
	err = bpf_map__pin(map_bpf, __map);
	if (err < 0) {
		fprintf(stderr,
		       "bpf_map__pin: failed obj(%s) map(%s) %i\n",
		       prog, __label_map, err);
		goto cleanup;
	}
	map_fd = bpf_map__fd(map_bpf);
	if (map_fd < 0) {
		fprintf(stderr,
			"bpf_map__fd: failed obj(%s) map(%s) %i\n",
			prog, __label_map, err);
	}
	err = bpf_object__unload(obj);
	if (err < 0) {
		fprintf(stderr,
			"bpf_objecT__unload: failed obj(%s) map(%s) %i\n",
			prog, __label_map, err);
	}
	close(map_fd);
cleanup:
	bpf_object__close(obj);
	return err;
}

int __bpf_obj_get(const char *file)
{
	return bpf_obj_get(file);
}

int bpf_loader_set_map(struct bpf_object *obj,
		       const char *mapdir,
		       const char *ciliumdir,
		       int verbosity)
{
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		char pinfd[512];
		int fd, err;

		errno = 0;
		strncpy(pinfd, mapdir, sizeof(pinfd));
		strncat(pinfd, name, sizeof(pinfd) - 1);
		fd = bpf_obj_get(pinfd);
		if (fd < 0) {
			char ciliumfd[512];

			if (ciliumdir) {
				strncpy(ciliumfd, ciliumdir, sizeof(pinfd));
				strncat(ciliumfd, name, sizeof(pinfd) - 1);

				fd = bpf_obj_get(ciliumfd);
				if (fd < 0) {
					if (verbosity)
						fprintf(stderr, "searched for Cilium bpf_map %s not found\n", ciliumfd);
				} else {
					if (verbosity)
						fprintf(stderr, "found Cilium bpf_map %s\n", ciliumfd);
				}
			}

			if (fd < 0) {
				if (verbosity)
					fprintf(stderr, "bpf_map %s not found, use program local\n", pinfd);
				continue;
			}
		}

		err = bpf_map__reuse_fd(map, fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd(map, fd): %i\n", err);
			return err;
		}
		if (verbosity)
			fprintf(stderr, "bpf_map__reused_fd, %s = %d\n", pinfd, fd);

		close(fd);
	}
	return 0;
}

static struct bpf_object *__loader(const int version,
		    const int verbosity,
		    const char *btf,
		    const char *prog,
		    const char *mapdir,
		    const char *ciliumdir,
		    const int type)
{
	struct bpf_object_load_attr attr = {0};
	struct bpf_object *obj;
	int err;

	if (verbosity > 1)
		libbpf_set_print(__print);

	obj = bpf_object__open(prog);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open: %i %s\n", err, prog);
		return NULL;
	}

	bpf_loader_programs(obj, type, verbosity);
	err = bpf_loader_set_map(obj, mapdir, ciliumdir, verbosity);
	if (err) {
		fprintf(stderr, "bpf_loader_set_map failed %d\n", err);
		return NULL;
	}

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "bpf_object__load_xattr: failed %i: %s\n", err, errstr);
		return NULL;
	}
	return obj;
}

int bpf_link(char *target, const char *source, int type)
{
	int err, target_fd, source_fd = bpf_obj_get(source);

	if (source_fd < 0) {
		fprintf(stderr, "bpf_obj_get('%s') failed on load error %i.\n", source, source_fd);
		return -1;
	}

	target_fd = open(target, O_RDONLY);
	if (target_fd < 0) {
		target_fd = bpf_obj_get(target);
		if (target_fd < 0) {
			fprintf(stderr, "open('%s') and bpf_obj_get('%s') failed on load error %i.\n",
				target, target, target_fd);
			return -1;
		}
	}

	err = bpf_prog_attach(source_fd, target_fd, type, 0);
	if (err)
		fprintf(stderr, "bpf_prog_attach: failed (%s->%s) err %i\n", source, target, err);
	close(target_fd);
	close(source_fd);
	return err;
}

int bpf_loader_pin(struct bpf_object *obj,
		   const char *label, const char *__prog)
{
	struct bpf_program *prog_bpf;
	int err;

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find_program_by_title: can't find %s\n", label);
		return -1;
	}
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object__find_program_by_title: failed\n");
		return -1;
	}

	bpf_program__unpin(prog_bpf, __prog);
	err = bpf_program__pin(prog_bpf, __prog);
	if (err < 0) {
		fprintf(stderr, "bpf_program__pin: failed %i\n", err);
		return -1;
	}
	return err;
}

int tc_loader(const int version,
		   const int verbosity,
		   const char *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   const char *ciliumdir)
{
	struct bpf_object *obj;
	int fd, err;

	obj = __loader(version, verbosity, btf, prog, mapdir, ciliumdir, BPF_PROG_TYPE_SCHED_CLS);
	if (!obj)
		return -1;

	err = bpf_loader_pin(obj, label, __prog);
	if (err) {
		fprintf(stderr, "bpf_loader_pin failed: %i\n", err);
		return err;
	}
	fd = bpf_obj_get(__prog);
	bpf_object__close(obj);
	return fd;
}

int fgs_loader(const int version,
		   const int verbosity,
		   const char *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   char *link_path,
		   const int prog_type,
		   const int attach_type)
{
	struct bpf_object *obj;
	int fd, err;

	obj = __loader(version, verbosity, btf, prog, mapdir, 0, prog_type);
	if (!obj)
		return -1;

	err = bpf_loader_pin(obj, label, __prog);
	if (err) {
		fprintf(stderr, "bpf_loader_pin failed: %i\n", err);
		return err;
	}
	fd = bpf_link(link_path, __prog, attach_type);
	bpf_object__close(obj);
	return fd;
}

int skskb_verdict_loader(const int version,
			 const int verbosity,
			 const char *btf,
			 const char *prog,
			 const char *label,
			 const char *__prog,
			 const char *mapdir)
{
	char *path = "/sys/fs/bpf/tcpmon/fgs_sock_map";
	const int type = BPF_PROG_TYPE_SK_SKB;
	const int attach = BPF_SK_SKB_STREAM_VERDICT;

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, type, attach);
}

int skskb_parser_loader(const int version,
			const int verbosity,
			const char *btf,
			const char *prog,
			const char *label,
			const char *__prog,
			const char *mapdir)
{
	char *path = "/sys/fs/bpf/tcpmon/fgs_sock_map";
	const int type = BPF_PROG_TYPE_SK_SKB;
	const int attach = BPF_SK_SKB_STREAM_PARSER;

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, type, attach);
}

int skmsg_loader(const int version,
		 const int verbosity,
		 const char *btf,
		 const char *prog,
		 const char *label,
		 const char *__prog,
		 const char *mapdir)
{
	char *path = "/sys/fs/bpf/tcpmon/fgs_sock_map";
	const int type = BPF_PROG_TYPE_SK_MSG;
	const int attach = BPF_SK_MSG_VERDICT;

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, type, attach);
}


int sockops_loader(const int version,
		   const int verbosity,
		   const char *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   const int prog_type,
		   const int attach_type)
{
	char *path = "/run/hubble-fgs/cgroup2";

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, prog_type, attach_type);
}

int tracepoint_loader(const int version,
		      const int verbosity,
		      const char *btf,
		      const char *prog,
		      const char *attach_category,
		      const char *attach_name,
		      const char *label,
		      const char *__prog,
		      const char *mapdir,
		      const bool retprobe)
{
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	struct bpf_object *obj;
	int err;

	obj = __loader(version, verbosity, btf, prog, mapdir, 0, BPF_PROG_TYPE_TRACEPOINT);
	if (!obj)
		return -1;

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find_program_by_title: null pointer\n");
		return -1;
	}
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object__find_program_by_title: failed\n");
		return err;
	}

	bpf_program__unpin(prog_bpf, __prog);

	prog_attach = bpf_program__attach_tracepoint(prog_bpf, attach_category, attach_name);
	err = libbpf_get_error(prog_attach);
	if (err) {
		// Expected error when attach point probe is happening
		if (verbosity)
			fprintf(stderr, "bpf_program__attach_tracepoint: failed (%s)\n", prog);
		return err;
	}

	err = bpf_program__pin(prog_bpf, __prog);
	if (err < 0) {
		fprintf(stderr, "bpf_program__pin: failed %i\n", err);
		return err;
	}
	bpf_object__close(obj);
	bpf_program__unload(prog_bpf);
	return bpf_link_fd(prog_attach);
}

int kprobe_loader(const int version,
		  const int verbosity,
		  const char *btf,
		  const char *prog,
		  const char *attach,
		  const char *label,
	  	  const char *__prog,
		  const char *mapdir,
		  const bool retprobe)
{
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	struct bpf_object *obj;
	int err;

	obj = __loader(version, verbosity, btf, prog, mapdir, 0, BPF_PROG_TYPE_KPROBE);
	if (!obj)
		return -1;

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find_program_by_title: null pointer\n");
		return -1;
	}
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object__find_program_by_title: failed\n");
		return -1;
	}

	bpf_program__unpin(prog_bpf, __prog);

	prog_attach = bpf_program__attach_kprobe(prog_bpf, retprobe, attach);
	err = libbpf_get_error(prog_attach);
	if (err) {
		// Expected error when attach point probe is happening
		if (verbosity)
			fprintf(stderr, "bpf_program__attach_kprobe: failed (%s)\n", prog);
		return -1;
	}

	err = bpf_program__pin(prog_bpf, __prog);
	if (err < 0) {
		fprintf(stderr, "bpf_program__pin: failed %i\n", err);
		return -1;
	}
	bpf_object__close(obj);
	bpf_program__unload(prog_bpf);
	return bpf_link_fd(prog_attach);
}
*/
import "C"

import (
	"fmt"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func LoadAndPinMaps(__version, __verbosity int, __btf, __prog, __map, __map_label string, __prog_type int) (int, error) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	p := C.CString(__prog)
	m := C.CString(__map)
	ml := C.CString(__map_label)
	pt := C.int(__prog_type)

	fd := C.fgs_map_loader(version, verbosity, btf, p, m, ml, pt)
	fdInt := int(fd)
	if fdInt < 0 {
		return 0, fmt.Errorf("Unable to pin map: %d (%s %s %s)\n", fdInt, __prog, __map, __map_label)
	}
	return fdInt, nil
}

func LoadProgram(__version, __verbosity int, __btf, object, __label, __prog, __mapdir string, __prog_type, __attach_type int) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	pt := C.int(__prog_type)
	at := C.int(__attach_type)
	loader_fd := C.sockops_loader(version, verbosity, btf, o, l, p, mapdir, pt, at)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to sockops load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadSockopsProgram(__version, __verbosity int, __btf, object, __label, __prog, __mapdir string) (error, int) {
	prog_type := 13  // BPF_PROG_TYPE_SOCK_OPS
	attach_type := 3 // BPF_CGROUP_SOCK_OPS

	return LoadProgram(__version, __verbosity, __btf, object, __label, __prog, __mapdir, prog_type, attach_type)
}

func LoadCgroupProgram(__version, __verbosity int, __btf, object, __label, __prog, __mapdir string) (error, int) {
	prog_type := 8   // BPF_PROG_TYPE_CGROUP_SKB
	attach_type := 0 // BPF_CGROUP_INET_INGRESS

	return LoadProgram(__version, __verbosity, __btf, object, __label, __prog, __mapdir, prog_type, attach_type)
}

func LoadSkmsgProgram(__version, __verbosity int, __btf, object, __label, __prog, __mapdir string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	loader_fd := C.skmsg_loader(version, verbosity, btf, o, l, p, mapdir)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to skmsg load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadSkSkbVerdictProgram(__version, __verbosity int, __btf, object, __label, __prog, __mapdir string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	loader_fd := C.skskb_verdict_loader(version, verbosity, btf, o, l, p, mapdir)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to skskb load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadSkSkbParserProgram(__version, __verbosity int, __btf, object, __label, __prog, __mapdir string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	loader_fd := C.skskb_parser_loader(version, verbosity, btf, o, l, p, mapdir)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to skskb load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadTracingProgram(__version, __verbosity int, __btf, object, attach, __label, __prog, __mapdir string, retprobe bool) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	aa := strings.Split(attach, "/")
	if len(aa) != 2 {
		return fmt.Errorf("tracepoint attach argument must be in the form category/tracepoint. Instead got: %s", attach), -1
	}
	a_category := C.CString(aa[0])
	a_name := C.CString(aa[1])
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	ret := C.bool(retprobe)
	loader_fd := C.tracepoint_loader(version, verbosity, btf, o, a_category, a_name, l, p, mapdir, ret)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to tracepoint load: %d %s", loaderInt, object), loaderInt
	}
	return nil, loaderInt
}

func LoadKprobeProgram(__version, __verbosity int, __btf, object, attach, __label, __prog, __mapdir string, retprobe bool) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	ret := C.bool(retprobe)
	loader_fd := C.kprobe_loader(version, verbosity, btf, o, a, l, p, mapdir, ret)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func QdiscTCInsert(linkName string, ingress bool) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %s\n", linkName, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("QdiscList failed (%s): %s\n", linkName, err)
	}
	// If the qdisc exists nothing to do so return nil
	for _, qdisc := range qdiscs {
		_, clsact := qdisc.(*netlink.Clsact)
		if clsact {
			return nil
		}
	}

	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("QdiscAdd failed (%s): %s\n", linkName, err)
	}
	return nil
}

func AttachTCIngress(progFd int, linkName string, ingress bool) (error, int) {
	var parent uint32
	var name string

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %s\n", linkName, err), 0
	}

	if ingress {
		parent = netlink.HANDLE_MIN_INGRESS
		name = "fgs-ingress"
	} else {
		parent = netlink.HANDLE_MIN_EGRESS
		name = "fgs-egress"
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    parent,
		Handle:    netlink.MakeHandle(0, 2),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           progFd,
		Name:         name,
		DirectAction: true,
	}
	if filter.Fd < 0 {
		return fmt.Errorf("BpfFilter failed (%s): %d\n", linkName, filter.Fd), 0
	}
	if err = netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("FilterAdd failed (%s): %s\n", linkName, err), 0
	}
	return err, 0
}

func LoadTC(__version, __verbosity int,
	__btf, object, __label, __prog, __mapdir, __ciliumdir string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	ciliumdir := C.CString(__ciliumdir)
	loader_fd := C.tc_loader(version, verbosity, btf, o, l, p, mapdir, ciliumdir)
	loaderFd := int(loader_fd)
	if loaderFd < 0 {
		return fmt.Errorf("Unable to load tc program: %d %s", loaderFd, object), 0
	}
	return nil, loaderFd
}
