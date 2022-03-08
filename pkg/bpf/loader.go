//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

//go:build linux
// +build linux

package bpf

/*
#cgo CFLAGS: -I ../../bpf/include -I ../../bpf/libbpf/ -I ../../bpf/lib/
#cgo LDFLAGS: -L../../lib -L/usr/local/lib -lbpf -lelf -lz

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

#define __NR_bpf 321

void cgroup_delete(const char *target, const char *prog, int attach_type)
{
	int err, target_fd, prog_fd;
	union bpf_attr attr;

	target_fd = open(target, O_RDONLY);
	if (target_fd < 0) {
		fprintf(stderr, "open('%s') failed on load error %i.\n",
				target, target_fd);
		return;
	}

	prog_fd = bpf_obj_get(prog);
	if (prog_fd < 0) {
		close(target_fd);
		fprintf(stderr, "bpf_obj_get('%s') failed on load error %i.\n",
				prog, prog_fd);
		return;
	}

	memset(&attr, 0, sizeof(attr));
	attr.target_fd = target_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = attach_type;

	syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));

	close(target_fd);
	close(prog_fd);
}

int __bpf_obj_get(const char *file)
{
	return bpf_obj_get(file);
}

int bpf_loader_set_map(struct bpf_object *obj,
		       const char *mapdir,
		       const char *mapdir2,
		       int verbosity)
{
	struct bpf_map *map;
	const char slash[] = "/";

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		char pinfd[512];
		int fd, err;

		errno = 0;
		strncpy(pinfd, mapdir, sizeof(pinfd));
		strncat(pinfd, slash, sizeof(slash));
		strncat(pinfd, name, sizeof(pinfd) - 1);
		fd = bpf_obj_get(pinfd);
		if (fd < 0) {
			char mapdir2fd[512];

			if (mapdir2) {
				strncpy(mapdir2fd, mapdir2, sizeof(pinfd));
				strncat(mapdir2fd, name, sizeof(pinfd) - 1);

				fd = bpf_obj_get(mapdir2fd);
				if (fd < 0) {
					if (verbosity)
						fprintf(stderr, "searched for bpf_map %s not found\n", mapdir2fd);
				} else {
					if (verbosity)
						fprintf(stderr, "found bpf_map %s\n", mapdir2fd);
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
		    struct btf *btf,
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
    else
		libbpf_set_print(__quiet);

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
	attr.target_btf = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "__loader bpf_object__load_xattr(%s): failed %i: %s\n", prog, err, errstr);
		return NULL;
	}
	return obj;
}

int __tracepoint_loader(struct bpf_object *obj,
		      const int verbosity,
		      void *btf,
		      const char *prog,
		      const char *attach_category,
		      const char *attach_name,
		      const char *label,
		      const char *__prog,
		      const char *mapdir)
{
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	int err;

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find_program_by_title(tracepoint:%s): null pointer\n", label);
		bpf_object__close(obj);
		err = -1;
		goto out;
	}
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object__find_program_by_title: failed\n");
		bpf_object__close(obj);
		goto out_object;
	}

	bpf_program__unpin(prog_bpf, __prog);

	prog_attach = bpf_program__attach_tracepoint(prog_bpf, attach_category, attach_name);
	err = libbpf_get_error(prog_attach);
	if (err) {
		// Expected error when attach point probe is happening
		if (verbosity)
			fprintf(stderr, "bpf_program__attach_tracepoint: failed (%s)\n", prog);
		goto out_object;
	}

	err = bpf_program__pin(prog_bpf, __prog);
	if (err < 0) {
		fprintf(stderr, "bpf_program__pin: failed %i\n", err);
		goto out_object;
	}
	bpf_object__close(obj);
	bpf_program__unload(prog_bpf);
	return bpf_link_fd(prog_attach);
out_object:
	bpf_program__unload(prog_bpf);
	bpf_object__close(obj);
out:
	return err;
}

int tracepoint_loader(const int version,
		      const int verbosity,
		      void *btf,
		      const char *prog,
		      const char *attach_category,
		      const char *attach_name,
		      const char *label,
		      const char *__prog,
		      const char *mapdir)
{
	struct bpf_object *obj;
	int err;

	obj = __loader(version, verbosity, btf, prog, mapdir, 0, BPF_PROG_TYPE_TRACEPOINT);
	if (!obj)
		return -1;

	return __tracepoint_loader(obj, verbosity, btf, prog, attach_category, attach_name, label, __prog, mapdir);
}

int __kprobe_loader(struct bpf_object *obj,
		    const int verbosity,
		    const char *attach,
		    const char *label,
		    const char *__prog,
		    const bool retprobe)
{
	struct bpf_link *prog_attach;
	struct bpf_program *prog_bpf;
	int err;

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find_program_by_title(kprobe:%s): null pointer\n", label);
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
			fprintf(stderr, "bpf_program__attach_kprobe: failed (%s)\n", label);
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



#define MAX_ARGS 5
void *generic_loader_args(
	const int version,
	const int verbosity,
	void *btf,
	const char *prog,
	const char *attach,
	const char *label,
	const char *__prog,
	const char *mapdir,
	void *filter,
	const int type)
{
	int map_fd, err, i, zero = 0;
	char map_name[255];
	struct bpf_map *map_bpf, *map_fdinstall;
	struct bpf_object *obj;
	char *filter_map = "filter_map";
	char *fdinstall_map = "fdinstall_map";

	obj = __loader(version, verbosity, btf, prog, mapdir, 0, type);
	if (!obj)
		goto err;

	map_fdinstall = bpf_object__find_map_by_name(obj, fdinstall_map);
	if (map_fdinstall) {
		snprintf(map_name, sizeof(map_name), "%s/fdinstall_map", mapdir);
		bpf_map__unpin(map_fdinstall, map_name);
		err = bpf_map__pin(map_fdinstall, map_name);
		if (err < 0) {
			fprintf(stderr, "bpf_map__pin: obj(%s) map(fd_map) failed: %i", map_name, err);
			goto err;
		}
	} else {
		fprintf(stderr, "bpf_object__find_map_by_name (%s): fdinstall_map failed\n",
			fdinstall_map);
		goto err;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, filter_map);
	if (map_fd >= 0) {
		err = bpf_map_update_elem(map_fd, &zero, filter, BPF_ANY);
		if (err) {
			printf("WARNING: map update elem %s error %d\n", filter_map, err);
		}
	} else {
		printf("WARNING: attempted to set filter args on program %s without filters\n", filter_map);
	}

	switch (type) {
		case BPF_PROG_TYPE_KPROBE:
			snprintf(map_name, sizeof(map_name), "%s-kp-calls", __prog);
			map_bpf = bpf_object__find_map_by_name(obj, "kprobe_calls");
			break;

		case BPF_PROG_TYPE_TRACEPOINT:
			snprintf(map_name, sizeof(map_name), "%s-tp-calls", __prog);
			map_bpf = bpf_object__find_map_by_name(obj, "tp_calls");
			break;

		default:
			fprintf(stderr, "%s(): unknown program type:%d", __FUNCTION__, type);
			goto err;
	}
	if (!map_bpf) {
		fprintf(stderr,
			"bpf_object__find_map_by_name: generic loader args obj(%s) map(%s) failed: ",
			prog, map_name);
		goto err;
	}
	bpf_map__unpin(map_bpf, map_name);
	err = bpf_map__pin(map_bpf, map_name);
	if (err < 0) {
		fprintf(stderr, "bpf_map__pin: obj(%s) map(%s) failed: %i", prog, map_name, err);
		goto err;
	}

	map_fd = bpf_map__fd(map_bpf);
	printf("bpf fgs_kprobe_calls map and progs %s mapfd %d\n", __prog, map_fd);
	if (map_fd >= 0) {
		for (i = 0; i < 11; i++) {
			struct bpf_program *prog;
			char prog_name[20];
			char pin_name[200];
			int fd;

			snprintf(prog_name, sizeof(prog_name), "kprobe/%i", i);
			prog = bpf_object__find_program_by_title(obj, prog_name);
			if (!prog)
				goto out;
			fd = bpf_program__fd(prog);
			if (fd < 0) {
				err = errno;
				goto err;
			}
			snprintf(pin_name, sizeof(pin_name), "%s_%i", __prog, i);
			bpf_program__unpin(prog, pin_name);
			err = bpf_program__pin(prog, pin_name);
			if (err) {
				printf("program pin %s tailcall err %d\n", pin_name, err);
				goto err;
			}
			err = bpf_map_update_elem(map_fd, &i, &fd, BPF_ANY);
			if (err) {
				printf("map update elem  i %i %s tailcall err %d %d\n", i, prog_name, err, errno);
				goto err;
			}
		}
	}
out:
	return obj;
err:
	return NULL;
}

int generic_kprobe_pin_retprobe(struct bpf_object *obj, const char *genmapdir) {
	const char map_name[] = "retprobe_map";
	struct bpf_map *map;
	int err;

	map = bpf_object__find_map_by_name(obj, map_name);
	err = libbpf_get_error(map);
	if (err) {
		fprintf(stderr, "retprobe map not found\n");
		return -1;
	}

	char fname[256];
	snprintf(fname, sizeof(fname), "%s/%s", genmapdir, map_name);
	err = bpf_map__pin(map, fname);
	if (err < 0) {
		fprintf(stderr, "failed to pin retprobe map: %i\n", err);
	}
	return 0;
}

int generic_kprobe_loader(const int version,
		  const int verbosity,
		  void *btf,
		  const char *prog,
		  const char *attach,
		  const char *label,
		  const char *__prog,
		  const char *mapdir,
		  const char *genmapdir,
		  void *filters) {
	struct bpf_object *obj;
	int err;
	obj = generic_loader_args(version, verbosity, btf, prog, attach, label, __prog, mapdir, filters, BPF_PROG_TYPE_KPROBE);
	if (!obj) {
		return -1;
	}
	err = generic_kprobe_pin_retprobe(obj, genmapdir);
	if (err) {
		// TODO: cleanup
		return -1;
	}
	return __kprobe_loader(obj, verbosity, attach, label, __prog, false);
}

int generic_kprobe_ret_loader(const int version,
		  const int verbosity,
		  void *btf,
		  const char *prog,
		  const char *attach,
		  const char *label,
		  const char *__prog,
		  const char *mapdir,
		  const char *genmapdir)
{
	struct bpf_object *obj;
	obj = __loader(version, verbosity, btf, prog, mapdir, genmapdir, BPF_PROG_TYPE_KPROBE);
	if (!obj)
		return -1;

	return __kprobe_loader(obj, verbosity, attach, label, __prog, true);
}



int tracepoint_loader_args(const int version,
		  const int verbosity,
		  void *btf,
		  const char *prog,
		  const char *attach_category,
		  const char *attach,
		  const char *label,
		  const char *__prog,
		  const char *mapdir,
		  const bool retprobe,
		  void *filters) {
	struct bpf_object *obj;
	obj = generic_loader_args(version, verbosity, btf, prog, attach, label, __prog, mapdir, filters, BPF_PROG_TYPE_TRACEPOINT);
	if (!obj)
		return -1;
	return __tracepoint_loader(obj, verbosity, btf, prog, attach_category, attach, label, __prog, mapdir);
}

int kprobe_loader(const int version,
		  const int verbosity,
		  void *btf,
		  const char *prog,
		  const char *attach,
		  const char *label,
		  const char *__prog,
		  const char *mapdir,
		  const bool retprobe)
{
	struct bpf_object *obj;
	obj = __loader(version, verbosity, btf, prog, mapdir, 0, BPF_PROG_TYPE_KPROBE);
	if (!obj)
		return -1;

	return __kprobe_loader(obj, verbosity, attach, label, __prog, retprobe);
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func LoadTracingProgram(__version, __verbosity int, btf uintptr, object, attach, __label, __prog, __mapdir string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
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
	loader_fd := C.tracepoint_loader(version, verbosity, unsafe.Pointer(btf), o, a_category, a_name, l, p, mapdir)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to tracepoint load: %d %s", loaderInt, object), loaderInt
	}
	return nil, loaderInt
}

func LoadKprobeProgram(__version, __verbosity int, btf uintptr, object, attach, __label, __prog, __mapdir string, retprobe bool) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	ret := C.bool(retprobe)
	loader_fd := C.kprobe_loader(version, verbosity, unsafe.Pointer(btf), o, a, l, p, mapdir, ret)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadGenericKprobeProgram(__version, __verbosity int,
	btf uintptr,
	object, attach, __label, __prog, __mapdir string, __genmapdir string,
	filters [4096]byte) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	genmapdir := C.CString(__genmapdir)
	loader_fd := C.generic_kprobe_loader(version,
		verbosity,
		unsafe.Pointer(btf),
		o, a, l, p, mapdir, genmapdir, unsafe.Pointer(&filters))
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadGenericKprobeRetProgram(__version, __verbosity int, btf uintptr, object, attach, __label, __prog, __mapdir string, __genmapdir string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	genmapdir := C.CString(__genmapdir)
	loader_fd := C.generic_kprobe_ret_loader(version, verbosity, unsafe.Pointer(btf), o, a, l, p, mapdir, genmapdir)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadTracepointArgsProgram(__version, __verbosity int,
	btf uintptr,
	object, attach, __label, __prog, __mapdir string,
	retprobe bool,
	filters [4096]byte) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
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
	loader_fd := C.tracepoint_loader_args(version,
		verbosity,
		unsafe.Pointer(btf),
		o, a_category, a_name, l, p, mapdir, ret, unsafe.Pointer(&filters))
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func QdiscTCInsert(linkName string, ingress bool) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %w", linkName, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("QdiscList failed (%s): %w", linkName, err)
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
		return fmt.Errorf("QdiscAdd failed (%s): %w", linkName, err)
	}
	return nil
}

func AttachTCIngress(progFd int, linkName string, ingress bool) error {
	var parent uint32
	var name string

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %w", linkName, err)
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
		return fmt.Errorf("BpfFilter failed (%s): %d", linkName, filter.Fd)
	}
	if err = netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("FilterAdd failed (%s): %w", linkName, err)
	}
	return err
}

func CgroupDestroyEgress(progPath string) {
	targetPath := "/run/hubble-fgs/cgroup2"
	attach_type := int(0) // BPF_CGROUP_INET_INGRESS

	C.cgroup_delete(C.CString(targetPath), C.CString(progPath), C.int(attach_type))

}

func CgroupDestroyIngress(progPath string) {
	targetPath := "/run/hubble-fgs/cgroup2"
	attach_type := int(1) // BPF_CGROUP_INET_INGRESS

	C.cgroup_delete(C.CString(targetPath), C.CString(progPath), C.int(attach_type))
}

func CgroupDestroySockOpt(progPath string) {
	targetPath := "/run/hubble-fgs/cgroup2"
	attach_type := int(22) // BPF_CGROUP_SETSOCKOPT

	C.cgroup_delete(C.CString(targetPath), C.CString(progPath), C.int(attach_type))
}

// Sockops programs are somewhat special because they are attached to
// many different we assume loader and unloader code is serialized by
// callers. It must be otherwise we have more problems than a refcnt
// being incorrect and what BPF programs are running will be generally
// confused.
var (
	sockopsRef int
)

func CgroupDestroySockops(progPath string) {
	targetPath := "/run/hubble-fgs/cgroup2"
	attach_type := int(3) // BPF_CGROUP_SOCK_OPS

	if IsSockopsLoaded() {
		CgroupSockopsRefDec()
		C.cgroup_delete(C.CString(targetPath), C.CString(progPath), C.int(attach_type))
	}
}

func CgroupSockopsRefInc() {
	sockopsRef++
}

func CgroupSockopsRefDec() {
	sockopsRef--
}

func IsSockopsLoaded() bool {
	return sockopsRef != 0
}

func SockopsRefCnt() int {
	return sockopsRef
}
