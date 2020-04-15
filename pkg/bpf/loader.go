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
#cgo CFLAGS: -I ../../bpf/
#cgo LDFLAGS: -L ../../libs/ -lbpf -lelf -lz

#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libbpf.h"
#include "hubble_msg.h"

#define NUM_PAGES 8
// hash map only added updates from map value in 4.18
#define MIN_HASH_VERSION 266752

static int __print(enum libbpf_print_level level __attribute__((unused)),
		   const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int __quiet(enum libbpf_print_level level __attribute__((unused)),
		   const char *format, va_list args)
{
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
		fprintf(stderr, "bpf_object__open_xattr: %i %s\n", err, prog);
		return -1;
	}

	map_bpf = bpf_object__find_map_by_name(obj, name);
	err = libbpf_get_error(map_bpf);
	if (err) {
		fprintf(stderr, "bpf_object__find_map_by_name: obj(%s) map(execve_map)\n", prog);
		return -1;
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
			"bpf_object__load: failed %i: %s\n",
			err, errstr);
		return -1;
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
		       "bpf_map_pin: failed obj(%s) map(%s) %i\n",
		       prog, __label_map, err);
		return err;
	}
	return bpf_map__fd(map_bpf);
}

int bpf_loader_set_map(struct bpf_object *obj, int execve_fd, int tcp_events_fd, int verbosity)
{
	struct bpf_map *map;
	int err = 0;

	if (execve_fd) {
		char *name = "execve_map";

		map = bpf_object__find_map_by_name(obj, name);
		err = libbpf_get_error(map);
		if (err) {
			fprintf(stderr, "bpf_object__find_map_by_name: obj map(execve_map)\n");
			return -1;
		}

		err = bpf_map__reuse_fd(map, execve_fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd(map, fd): %i\n", err);
			return -1;
		}
		if (verbosity)
			fprintf(stderr, "bpf_map__reused_fd, %s = %d\n", name, execve_fd);
	} else {
		if (verbosity)
			fprintf(stderr, "bpf_map create execve_map.");
	}

	if (tcp_events_fd) {
		map = bpf_object__find_map_by_name(obj, "tcpmon_map");
		err = libbpf_get_error(map);
		if (err) {
			fprintf(stderr,
				"bpf_object__find_map_by_name: obj map(kprobe_tcp_events)\n");
			return -1;
		}

		err = bpf_map__reuse_fd(map, tcp_events_fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd(map, fd): %i\n", err);
			return -1;
		}
		if (verbosity)
			fprintf(stderr, "bpf_map__reused_fd, tcpmon_map = %d\n", tcp_events_fd);
	} else {
		if (verbosity)
			fprintf(stderr, "bpf_map create tcpmon_map.");
	}
	return err;
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

int tracepoint_loader(const int version,
		      const int verbosity,
		      const char *btf,
		      const char *prog,
		      const char *attach,
		      const char *label,
		      const char *__prog,
		      const bool retprobe,
		      const int execve_fd,
		      const int tcp_events_fd) {
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
		fprintf(stderr, "bpf_object__open_xattr: %i %s\n", err, prog);
		return -1;
	}


	bpf_loader_print_maps(obj, verbosity);
	bpf_loader_programs(obj, BPF_PROG_TYPE_TRACEPOINT, verbosity);

	err = bpf_loader_set_map(obj, execve_fd, tcp_events_fd, verbosity);
	if (err)
		return err;

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "bpf_object__load: failed %i: %s\n", err, errstr);
		return -1;
	}

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find__: null pointer\n");
		return -1;
	}
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object_find: failed\n");
		return -1;
	}

	bpf_program__unpin(prog_bpf, __prog);

	prog_attach = bpf_program__attach_tracepoint(prog_bpf, "sched", "sched_process_exec");
	err = libbpf_get_error(prog_attach);
	if (err) {
		// Expected error when attach point probe is happening
		if (verbosity)
			fprintf(stderr, "bpf_program__attach_tracepoint: failed (%s)\n", prog);
		return -1;
	}

	err = bpf_program__pin(prog_bpf, __prog);
	if (err < 0) {
		fprintf(stderr, "bpf_prog_pin: failed %i\n", err);
		return -1;
	}
	return map_fd;
}

int kprobe_loader(const int version,
		  const int verbosity,
		  const char *btf,
		  const char *prog,
		  const char *attach,
		  const char *label,
	  	  const char *__prog,
		  const bool retprobe,
	  	  const int execve_fd,
	  	  const int tcp_events_fd) {
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
		fprintf(stderr, "bpf_object__open_xattr: %i %s\n", err, prog);
		return -1;
	}

	bpf_loader_print_maps(obj, verbosity);
	bpf_loader_programs(obj, BPF_PROG_TYPE_KPROBE, verbosity);

	err = bpf_loader_set_map(obj, execve_fd, tcp_events_fd, verbosity);
	if (err)
		return err;

	attr.obj = obj;
	attr.target_btf_path = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr, "bpf_object__load: failed %i: %s\n", err, errstr);
		return -1;
	}

	prog_bpf = bpf_object__find_program_by_title(obj, label);
	if (!prog_bpf) {
		fprintf(stderr, "bpf_object__find__: null pointer\n");
		return -1;
	}
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object_find: failed\n");
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
		fprintf(stderr, "bpf_prog_pin: failed %i\n", err);
		return -1;
	}
	return map_fd;
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

func LoadTracingProgram(__version, __verbosity int, __btf, object, attach, __label, __prog string, retprobe bool, execve_fd int, tcp_fd int) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	ret := C.bool(retprobe)
	fd := C.int(execve_fd)
	tcp := C.int(tcp_fd)
	loader_fd := C.tracepoint_loader(version, verbosity, btf, o, a, l, p, ret, fd, tcp)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadKprobeProgram(__version, __verbosity int, __btf, object, attach, __label, __prog string, retprobe bool, execve_fd int, tcp_fd int) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	btf := C.CString(__btf)
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	ret := C.bool(retprobe)
	fd := C.int(execve_fd)
	tcp := C.int(tcp_fd)
	loader_fd := C.kprobe_loader(version, verbosity, btf, o, a, l, p, ret, fd, tcp)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}
