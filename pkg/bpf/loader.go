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

int sockmap_map_loader(const int version,
		       const int verbosity,
		       const char *btf,
		       const char *prog,
		       const char *__map,
		       const char *__label_map)
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
		return err;
	}


	map_bpf = bpf_object__find_map_by_name(obj, __label_map);
	err = libbpf_get_error(map_bpf);
	if (err) {
		fprintf(stderr,
			"bpf_object__find_map_by_name: obj(%s) map(%s) failed",
			prog, __label_map);
		return err;
	}

	bpf_map__unpin(map_bpf, __map);
	err = bpf_map__pin(map_bpf, __map);
	if (err < 0) {
		fprintf(stderr,
		       "bpf_map__pin: failed obj(%s) map(%s) %i\n",
		       prog, __label_map, err);
		return err;
	}
	return bpf_map__fd(map_bpf);
}

int kprobe_map_loader(const int version,
		      const int verbosity,
		      const char *btf,
		      const char *prog,
		      const char *__map,
		      const char *__label_map)
{
	struct bpf_object_load_attr attr = {0};
	struct bpf_program *prog_bpf;
	char *name = "execve_map";
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

	map_bpf = bpf_object__find_map_by_name(obj, name);
	err = libbpf_get_error(map_bpf);
	if (err) {
		fprintf(stderr, "bpf_object__find_map_by_name: obj(%s) map(execve_map)\n", prog);
		return err;
	}

	map_def = (struct bpf_map_def *)bpf_map__def(map_bpf);
	if (version > MIN_HASH_VERSION)
		map_def->type = BPF_MAP_TYPE_HASH;

	bpf_object__for_each_map(map_bpf, obj) {
		const struct bpf_map_def *def = bpf_map__def(map_bpf);

		if (verbosity)
			fprintf(stderr, "map: type %u key_size %u value_size %u max %u flags %u\n",
				def->type, def->key_size, def->value_size,
				def->max_entries, def->map_flags);
	}

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
		return err;
	}

	bpf_object__for_each_program(prog_bpf, obj) {
		bpf_program__set_type(prog_bpf, BPF_PROG_TYPE_KPROBE);
		if (verbosity)
			fprintf(stderr,
				"program: kern_version: %u\n",
				bpf_object__kversion(obj));
	}

	map_bpf = bpf_object__find_map_by_name(obj, __label_map);
	err = libbpf_get_error(map_bpf);
	if (err) {
		fprintf(stderr,
			"bpf_object__find_map_by_name: obj(%s) map(%s) failed",
			prog, __label_map);
		return err;
	}

	if (!map_bpf) {
		fprintf(stderr,
			"bpf_object__find_map_by_name: obj(%s) map(%s) null\n",
			prog, __label_map);
		return -1;
	}

	bpf_map__unpin(map_bpf, __map);
	err = bpf_map__pin(map_bpf, __map);
	if (err < 0) {
		fprintf(stderr,
		       "bpf_map_pin: failed obj(%s) map(%s) pin %s err %i\n",
		       prog, __label_map, __map, err);
		return err;
	}
	return bpf_map__fd(map_bpf);
}

int bpf_loader_set_map(struct bpf_object *obj, const char *mapdir, int verbosity)
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
			if (verbosity)
				fprintf(stderr, "bpf_map %s not found, use program local\n", pinfd);
			continue;
		}

		err = bpf_map__reuse_fd(map, fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd(map, fd): %i\n", err);
			return err;
		}
		if (verbosity)
			fprintf(stderr, "bpf_map__reused_fd, %s = %d\n", pinfd, fd);
	}
	return 0;
}

void bpf_loader_print_maps(struct bpf_object *obj, int verbosity)
{
	struct bpf_map *map_bpf;

	bpf_object__for_each_map(map_bpf, obj) {
		const struct bpf_map_def *def = bpf_map__def(map_bpf);

		if (verbosity)
			fprintf(stderr,
				"map: type %u key_size %u value_size %u max %u flags %u\n",
				def->type, def->key_size, def->value_size, def->max_entries, def->map_flags);
	}
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

static struct bpf_object *__loader(const int version,
		    const int verbosity,
		    const char *btf,
		    const char *prog,
		    const char *mapdir,
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

	bpf_loader_print_maps(obj, verbosity);
	bpf_loader_programs(obj, type, verbosity);
	err = bpf_loader_set_map(obj, mapdir, verbosity);
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

	if (target_fd < 0) {
		fprintf(stderr, "Get target %s failed\n", target);
		return 0;
	}

	err = bpf_prog_attach(source_fd, target_fd, type, 0);
	if (err) {
		fprintf(stderr, "bpf_prog_attach: failed (%s->%s) err %i\n", source, target, err);
		return -1;
	}
	return 0;
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
}

int skmsg_loader(const int version,
		 const int verbosity,
		 const char *btf,
		 const char *prog,
		 const char *label,
		 const char *__prog,
		 const char *mapdir)
{
	int err;
	struct bpf_object *obj = __loader(version, verbosity,
					  btf, prog, mapdir, BPF_PROG_TYPE_SK_MSG);

	if (!obj)
		return -1;

	err = bpf_loader_pin(obj, label, __prog);
	if (err) {
		fprintf(stderr, "bpf_loader_pin failed: %i\n", err);
		return err;
	}
	return bpf_link("/sys/fs/bpf/tcpmon/fgs_sock_map", __prog, BPF_SK_MSG_VERDICT);
}

int sockops_loader(const int version,
		   const int verbosity,
		   const char *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   const int prog_type, const int attach_type)
{
	struct bpf_object_load_attr attr = {0};
	struct bpf_link *prog_attach;
	struct bpf_object *obj, *execve_obj;
	struct bpf_map *map, *execve_map;
	int cg_fd, bpf_fd, fd, err, map_fd = 0;
	char *cgroup_path = "/run/hubble-fgs/cgroup2";

	if (verbosity > 1)
		libbpf_set_print(__print);

	obj = bpf_object__open(prog);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open: %i %s\n", err, prog);
		return err;
	}

	bpf_loader_print_maps(obj, verbosity);
	bpf_loader_programs(obj, prog_type, verbosity);
	err = bpf_loader_set_map(obj, mapdir, verbosity);
	if (err) {
		fprintf(stderr, "bpf_loader_set_map failed %d\n", err);
		return err;
	}

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "bpf_object__load_xattr: failed %i: %s\n", err, errstr);
		return err;
	}

	bpf_loader_pin(obj, label, __prog);
	return bpf_link(cgroup_path, __prog, attach_type);
}

int tracepoint_loader(const int version,
		      const int verbosity,
		      const char *btf,
		      const char *prog,
		      const char *attach,
		      const char *label,
		      const char *__prog,
		      const char *mapdir,
		      const bool retprobe)
{
	struct bpf_object_load_attr attr = {0};
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	struct bpf_object *obj, *execve_obj;
	struct bpf_map *map, *execve_map;
	int fd, err, map_fd = 0;

	if (verbosity > 1)
		libbpf_set_print(__print);

	obj = bpf_object__open(prog);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open: %i %s\n", err, prog);
		return err;
	}


	bpf_loader_print_maps(obj, verbosity);
	bpf_loader_programs(obj, BPF_PROG_TYPE_TRACEPOINT, verbosity);
	err = bpf_loader_set_map(obj, mapdir, verbosity);
	if (err) {
		fprintf(stderr, "bpf_loader_set_map failed %d\n", err);
		return err;
	}

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "bpf_object__load_xattr: failed %i: %s\n", err, errstr);
		return err;
	}

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

	prog_attach = bpf_program__attach_tracepoint(prog_bpf, "sched", "sched_process_exec");
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
	struct bpf_object_load_attr attr = {0};
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	struct bpf_object *obj, *execve_obj;
	struct bpf_map *map, *execve_map;
	int fd, err, map_fd = 0;

	if (verbosity > 1)
		libbpf_set_print(__print);

	obj = bpf_object__open(prog);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open: %i %s\n", err, prog);
		return -1;
	}

	bpf_loader_print_maps(obj, verbosity);
	bpf_loader_programs(obj, BPF_PROG_TYPE_KPROBE, verbosity);
	err = bpf_loader_set_map(obj, mapdir, verbosity);
	if (err) {
		fprintf(stderr, "bpf_loader_set_map failed %d\n", err);
		return err;
	}

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "bpf_object__load_xattr: failed %i: %s\n", err, errstr);
		return -1;
	}

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
	return bpf_link_fd(prog_attach);
}
*/
import "C"

import (
	"fmt"
)

func LoadAndPinMaps(__version, __verbosity int, __btf, __prog, __map, __map_label string) (int, error) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	p := C.CString(__prog)
	m := C.CString(__map)
	ml := C.CString(__map_label)

	fd := C.kprobe_map_loader(version, verbosity, btf, p, m, ml)
	fdInt := int(fd)
	if fdInt < 0 {
		return 0, fmt.Errorf("Unable to pin map: %d (%s %s %s)\n", fdInt, __prog, __map, __map_label)
	}
	return fdInt, nil
}

func LoadAndPinSockmapMaps(__version, __verbosity int, __btf, __prog, __map, __map_label string) (int, error) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	p := C.CString(__prog)
	m := C.CString(__map)
	ml := C.CString(__map_label)

	fd := C.sockmap_map_loader(version, verbosity, btf, p, m, ml)
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
		return fmt.Errorf("Unable to sockops load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadTracingProgram(__version, __verbosity int, __btf, object, attach, __label, __prog, __mapdir string, retprobe bool) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	ret := C.bool(retprobe)
	loader_fd := C.tracepoint_loader(version, verbosity, btf, o, a, l, p, mapdir, ret)
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
