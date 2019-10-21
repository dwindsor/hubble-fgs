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

int kprobe_loader(const char *prog,
		  const char *attach,
		  const char *label,
	  	  const char *__prog,
	  	  const char *__map,
	  	  const char *__label_map,
		  const bool retprobe,
	  	  const int execve_fd,
	  	  const int tcp_events_fd) {
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	struct bpf_object *obj, *execve_obj;
	struct bpf_map *map_bpf, *map, *execve_map;
	int fd, map_fd, err;

	obj = bpf_object__open(prog);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "bpf_object__open_xattr: %i %s\n", err, prog);
		return -1;
	}

	bpf_object__for_each_map(map_bpf, obj) {
		const struct bpf_map_def *def = bpf_map__def(map_bpf);

		fprintf(stderr, "map: type %u key_size %u value_size %u max %u flags %u\n",
			def->type, def->key_size, def->value_size, def->max_entries, def->map_flags);
	}

	bpf_object__for_each_program(prog_bpf, obj) {
		bpf_program__set_type(prog_bpf, BPF_PROG_TYPE_KPROBE);
		fprintf(stderr, "program: kern_version: %u\n", bpf_object__kversion(obj));
	}

	if (execve_fd) {
		map = bpf_object__find_map_by_name(obj, "execve_map");
		err = libbpf_get_error(map);
		if (err) {
			fprintf(stderr, "bpf_object__find_map_by_name: (execve_map)\n");
			return -1;
		}

		err = bpf_map__reuse_fd(map, execve_fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd(map, fd): %i\n", err);
			return -1;
		}
	}

	if (tcp_events_fd) {
		map = bpf_object__find_map_by_name(obj, "tcpmon_map");
		err = libbpf_get_error(map);
		if (err) {
			fprintf(stderr, "bpf_object__find_map_by_name: (kprobe_tcp_events)\n");
			return -1;
		}

		fprintf(stderr, "tcp_events_fd %i map kprobe_tcp_events\n", tcp_events_fd);
		err = bpf_map__reuse_fd(map, tcp_events_fd);
		if (err) {
			fprintf(stderr, "bpf_map__reuse_fd(map, fd): %i\n", err);
			return -1;
		}
		fprintf(stderr, "tcp_events_fd map reused\n");
	}

	err = bpf_object__load(obj);
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

	if (strcmp(__map, "") != 0) {
		map_bpf = bpf_object__find_map_by_name(obj, __label_map);
		err = libbpf_get_error(map_bpf);
		if (err) {
			fprintf(stderr, "bpf_object__find_map_by_name: (%s) failed", __label_map);
			return -1;
		}

		bpf_map__unpin(map_bpf, __map);
		err = bpf_map__pin(map_bpf, __map);
		if (err < 0) {
			fprintf(stderr, "bpf_prog_pin: failed (%s) %i\n", __label_map, err);
			return -1;
		}
		map_fd = bpf_map__fd(map_bpf);
	}

	prog_attach = bpf_program__attach_kprobe(prog_bpf, retprobe, attach);
	err = libbpf_get_error(prog_attach);
	if (err) {
		fprintf(stderr, "bpf_program__attach_kprobe: failed\n");
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

func LoadKprobe(object, attach, __label, __prog, __map, __map_label string, retprobe bool, execve_fd int, tcp_fd int) (error, int) {
	o := C.CString(object)
	a := C.CString(attach)
	l := C.CString(__label)
	p := C.CString(__prog)
	m := C.CString(__map)
	ml := C.CString(__map_label)
	ret := C.bool(retprobe)
	fd := C.int(execve_fd)
	tcp := C.int(tcp_fd)
	loader_fd := C.kprobe_loader(o, a, l, p, m, ml, ret, fd, tcp)
	if int(loader_fd) < 0 {
		return fmt.Errorf("Unable to kprobe load: %d %s", loader_fd, object), 0
	}
	return nil, int(loader_fd)
}
