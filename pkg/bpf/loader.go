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

// +build linux

package bpf

/*
#cgo CFLAGS: -I ../../bpf/include -I ../../bpf/libbpf/ -I ../../bpf/lib/
#cgo LDFLAGS: -L../../lib -lbpf -lelf -lz

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
		   void *btf,
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
		fprintf(stderr, "fgs_map_loader: bpf_object__open: %i %s\n", err, prog);
		return err;
	}

	bpf_loader_programs(obj, type, verbosity);

	attr.obj = obj;
	attr.target_btf = btf;
	attr.kern_version = version;
	err = bpf_object__load_xattr(&attr);
	if (err < 0) {
		char errstr[256];

		libbpf_strerror(err, errstr, sizeof(errstr));
		fprintf(stderr,
			"map_loader bpf_object__load_xattr (%s): failed %i: %s\n",
			prog, err, errstr);
		goto cleanup;
	}


	map_bpf = bpf_object__find_map_by_name(obj, __label_map);
	err = libbpf_get_error(map_bpf);
	if (err) {
		fprintf(stderr,
			"bpf_object__find_map_by_name: fgs map loader obj(%s) map(%s) failed",
			prog, __label_map);
		goto cleanup;
	}

	err = libbpf_get_error(obj);
	bpf_map__unpin(map_bpf, __map);
	err = bpf_map__pin(map_bpf, __map);
	if (err < 0) {
		fprintf(stderr,
			"fgs_map_loader: bpf_map__pin: failed obj(%s) map(%s) pin(%s) %i\n",
		       prog, __label_map, __map,  err);
		goto cleanup;
	}
	map_fd = bpf_map__fd(map_bpf);
	if (map_fd < 0) {
		fprintf(stderr,
			"fgs_map_loader: bpf_map__fd: failed obj(%s) map(%s) %i\n",
			prog, __label_map, err);
	}
	err = bpf_object__unload(obj);
	if (err < 0) {
		fprintf(stderr,
			"fgs_map_loader: bpf_object__unload: failed obj(%s) map(%s) %i\n",
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

int bpf_install_tail_calls(struct bpf_object *obj,
			   const char *progname,
			   const char *mapdir, char *mapname, char *progtype)
{
	char calls_name[255];
	int i, map_fd;
	int err = 0;

	snprintf(calls_name, sizeof(calls_name), "%s/%s", mapdir, mapname);

	map_fd = bpf_obj_get(calls_name);
	if (map_fd >= 0) {
		for (i = 0; i < 6; i++) {
			struct bpf_program *prog;
			char prog_name[20];
			char pin_name[200];
			int fd;

			snprintf(prog_name, sizeof(prog_name), "%s/%i", progtype, i);
			prog = bpf_object__find_program_by_title(obj, prog_name);
			if (!prog)
				continue;
			fd = bpf_program__fd(prog);
			if (fd < 0) {
				err = errno;
				goto out;
			}
			snprintf(pin_name, sizeof(pin_name), "%s_%i", progname, i);
			err = bpf_map_update_elem(map_fd, &i, &fd, BPF_ANY);
			if (err) {
				printf("map updat elem  i %i tailcall err %d %d\n", i, err, errno);
				goto out;
			}
		}
	}
out:
	return err;
}

int tc_loader(const int version,
		   const int verbosity,
		   void *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   const char *ciliumdir,
		   void *filter)
{
	struct bpf_object *obj;
	int fd, map_fd, err;
	char *tls_filter_map = "tls_filter_map";
	int zero = 0;


	obj = __loader(version, verbosity, btf, prog, mapdir, ciliumdir, BPF_PROG_TYPE_SCHED_CLS);
	if (!obj)
		return -1;

	err = bpf_loader_pin(obj, label, __prog);
	if (err) {
		fprintf(stderr, "bpf_loader_pin failed: %i\n", err);
		goto out;
	}

	// Install filter
	map_fd = bpf_object__find_map_fd_by_name(obj, tls_filter_map);
	if (map_fd >= 0) {
		err = bpf_map_update_elem(map_fd, &zero, filter, BPF_ANY);
		if (err) {
			fprintf(stderr, "bpf_map_update_elem: obj(%s) failed filter\n",
				__prog);
			goto out;
		}
	} else {
		fprintf(stderr, "bpf_object__find_map_fd_by_name: obj(%s) could not find %s\n", __prog, tls_filter_map);
		goto out;
	}

	// Install tail calls
	bpf_install_tail_calls(obj, __prog, mapdir, "tls_calls", "classifier");

	fd = bpf_obj_get(__prog);
	bpf_object__close(obj);
	return fd;
out:
	bpf_object__close(obj);
	return err;
}

int fgs_load_filter(struct bpf_object *obj, char *map_name, void  *filter)
{
	int map_fd, err;
	int zero = 0;

	if (!filter)
		return 0;

	map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
	if (map_fd >= 0) {
		err = bpf_map_update_elem(map_fd, &zero, filter, BPF_ANY);
		if (err) {
			printf("WARNING: map update elem %s error %d\n", map_name, err);
		}
	} else {
		err = errno;
		printf("WARNING: attempted to set filter args on program %s without filters\n", map_name);
	}
	return err;
}

int fgs_loader(const int version,
		   const int verbosity,
		   void *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   char *link_path,
		   const int prog_type,
		   const int attach_type,
		   void *tlsfilter, void *httpfilter)
{
	char *tls_filter_map = "tls_filter_map";
	char *http_filter_map = "http_filter_map";
	int fd, err, map_fd, zero = 0;
	struct bpf_object *obj;

	obj = __loader(version, verbosity, btf, prog, mapdir, 0, prog_type);
	if (!obj) {
		err = -1;
		goto out;
	}

	err = fgs_load_filter(obj, "tls_filter_map", tlsfilter);
	if (err)
		goto out;
	err = fgs_load_filter(obj, "http_filter_map", httpfilter);
	if (err)
		goto out;

	err = bpf_loader_pin(obj, label, __prog);
	if (err) {
		fprintf(stderr, "bpf_loader_pin failed: %i\n", err);
		goto out;
	}
	bpf_install_tail_calls(obj, __prog, mapdir, "http1_calls", "sk_msg");
	bpf_install_tail_calls(obj, __prog, mapdir, "http1_calls_skb", "sk_skb");
	fd = bpf_link(link_path, __prog, attach_type);
	bpf_object__close(obj);
	return fd;
out:
	return err;
}

int skskb_verdict_loader(const int version,
			 const int verbosity,
			 void *btf,
			 const char *prog,
			 const char *label,
			 const char *__prog,
			 const char *mapdir,
			 char *path)
{
	const int type = BPF_PROG_TYPE_SK_SKB;
	const int attach = BPF_SK_SKB_STREAM_VERDICT;

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, type, attach, 0, 0);
}

int skskb_parser_loader(const int version,
			const int verbosity,
			void *btf,
			const char *prog,
			const char *label,
			const char *__prog,
			const char *mapdir,
			char *path)
{
	const int type = BPF_PROG_TYPE_SK_SKB;
	const int attach = BPF_SK_SKB_STREAM_PARSER;

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, type, attach, 0, 0);
}

int skmsg_loader(const int version,
		 const int verbosity,
		 void *btf,
		 const char *prog,
		 const char *label,
		 const char *__prog,
		 const char *mapdir,
		 char *path)
{
	const int type = BPF_PROG_TYPE_SK_MSG;
	const int attach = BPF_SK_MSG_VERDICT;

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, type, attach, 0, 0);
}


int sockops_loader(const int version,
		   const int verbosity,
		   void *btf,
		   const char *prog,
		   const char *label,
		   const char *__prog,
		   const char *mapdir,
		   const int prog_type,
		   const int attach_type,
		   void *tlsfilter,
	   	   void *httpfilter)
{
	char *path = "/run/hubble-fgs/cgroup2";

	return fgs_loader(version, verbosity, btf, prog, label,
	                  __prog, mapdir, path, prog_type, attach_type,
			  tlsfilter, httpfilter);
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

func LoadAndPinMaps(__version, __verbosity int, btf uintptr, __prog, __map, __map_label string, __prog_type int) (int, error) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	p := C.CString(__prog)
	m := C.CString(__map)
	ml := C.CString(__map_label)
	pt := C.int(__prog_type)

	fd := C.fgs_map_loader(version, verbosity, unsafe.Pointer(btf), p, m, ml, pt)
	fdInt := int(fd)
	if fdInt < 0 {
		return 0, fmt.Errorf("Unable to pin map: %d (%s %s %s)", fdInt, __prog, __map, __map_label)
	}
	return fdInt, nil
}

func LoadProgram(__version, __verbosity int,
	btf uintptr,
	object, __label, __prog, __mapdir string,
	__prog_type, __attach_type int,
	tlsFilter, httpFilter unsafe.Pointer) (error, int) {

	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	pt := C.int(__prog_type)
	at := C.int(__attach_type)
	loader_fd := C.sockops_loader(
		version, verbosity,
		unsafe.Pointer(btf), o, l, p, mapdir, pt, at,
		tlsFilter, httpFilter)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to sockops load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadSockopsProgram(__version, __verbosity int, btf uintptr, object, __label, __prog, __mapdir string, tlsFilter, httpFilter [128]byte) (error, int) {
	prog_type := 13  // BPF_PROG_TYPE_SOCK_OPS
	attach_type := 3 // BPF_CGROUP_SOCK_OPS

	return LoadProgram(__version, __verbosity, btf, object, __label, __prog, __mapdir, prog_type, attach_type, unsafe.Pointer(&tlsFilter), unsafe.Pointer(&httpFilter))
}

func LoadCgroupProgram(__version, __verbosity int, btf uintptr, object, __label, __prog, __mapdir string) (error, int) {
	prog_type := 8   // BPF_PROG_TYPE_CGROUP_SKB
	attach_type := 0 // BPF_CGROUP_INET_INGRESS

	return LoadProgram(__version, __verbosity, btf, object, __label, __prog, __mapdir, prog_type, attach_type, unsafe.Pointer(nil), unsafe.Pointer(nil))
}

func LoadSkmsgProgram(__version, __verbosity int, btf uintptr, object, __label, __prog, __mapdir, __path string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	path := C.CString(__path)
	loader_fd := C.skmsg_loader(version, verbosity, unsafe.Pointer(btf), o, l, p, mapdir, path)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to skmsg load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadSkSkbVerdictProgram(__version, __verbosity int, btf uintptr, object, __label, __prog, __mapdir, __path string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	path := C.CString(__path)
	loader_fd := C.skskb_verdict_loader(version, verbosity, unsafe.Pointer(btf), o, l, p, mapdir, path)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to skskb load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

func LoadSkSkbParserProgram(__version, __verbosity int, btf uintptr, object, __label, __prog, __mapdir, __path string) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	path := C.CString(__path)
	loader_fd := C.skskb_parser_loader(version, verbosity, unsafe.Pointer(btf), o, l, p, mapdir, path)
	loaderInt := int(loader_fd)
	if loaderInt < 0 {
		return fmt.Errorf("Unable to skskb load: %d %s", loaderInt, object), 0
	}
	return nil, loaderInt
}

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

func AttachTCIngress(progFd int, linkName string, ingress bool) (error, int) {
	var parent uint32
	var name string

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %w", linkName, err), 0
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
		return fmt.Errorf("BpfFilter failed (%s): %d", linkName, filter.Fd), 0
	}
	if err = netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("FilterAdd failed (%s): %w", linkName, err), 0
	}
	return err, 0
}

func LoadTC(__version, __verbosity int,
	btf uintptr,
	object, __label, __prog, __mapdir, __ciliumdir string,
	filters [128]byte) (error, int) {
	version := C.int(__version)
	verbosity := C.int(__verbosity)
	o := C.CString(object)
	l := C.CString(__label)
	p := C.CString(__prog)
	mapdir := C.CString(__mapdir)
	ciliumdir := C.CString(__ciliumdir)
	loader_fd := C.tc_loader(version, verbosity, unsafe.Pointer(btf), o, l, p, mapdir, ciliumdir, unsafe.Pointer(&filters))
	loaderFd := int(loader_fd)
	if loaderFd < 0 {
		return fmt.Errorf("Unable to load tc program: %d %s", loaderFd, object), 0
	}
	return nil, loaderFd
}
