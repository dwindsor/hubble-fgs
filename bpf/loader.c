#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libbpf.h"
#include "hubble_msg.h"

static struct bpf_object *do_load(const char *file)
{
	struct bpf_prog_load_attr attr;
	struct bpf_object *obj = NULL;
	int err, fd;

	memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
	attr.file = file;
	attr.prog_type = BPF_PROG_TYPE_KPROBE;
	attr.log_level = 4;
	err = bpf_prog_load_xattr(&attr, &obj, &fd);
	return obj;
}

static void socket_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct msg_ipv4_tcp_connect *msg = data;
	struct in_addr saddr, daddr;

       	saddr.s_addr = msg->tuple.saddr;
       	daddr.s_addr = msg->tuple.daddr;

	fprintf(stdout, "(%i): (%s):%i -> (%s):%i, net_ns %u cid %i dockerID %.12s\n",
			msg->common.op,
			inet_ntoa(saddr),
			msg->tuple.sport,
			inet_ntoa(daddr),
			ntohs(msg->tuple.dport),
			msg->kube.net_ns,
			msg->kube.cid,
			msg->kube.docker_id);
}

#define NUM_PAGES 8

int main(int arg, char **argc) {
	const char *prog_label = "kprobe/tcp_connect";
	const char *prog = "./tcpmon.o";
	const char *tcpmon_file = "/sys/fs/bpf/tcpmon/kprobe_tcp_connect";//kprobe_tcp_connect";
	const char *tcpmon_dir = "/sys/fs/bpf/tcpmon/";
	struct bpf_program *prog_bpf;
	struct bpf_link *prog_attach;
	struct bpf_object *obj;
	struct bpf_map *tcpmon_map;
	struct perf_buffer *tcpmon_events;
	cpu_set_t cpu_seen;
	int nr, fd, err;
	struct perf_buffer_opts pb_opts = {};
	struct bpf_object_open_attr attr = {
		.file = tcpmon_file,
		.prog_type = BPF_PROG_TYPE_KPROBE,
	};
	__u64 samples = 0;

	obj = bpf_object__open_xattr(&attr);
	err = libbpf_get_error(obj);
	if (!err) {
		fprintf(stdout, "bpf_prog_load: program exists\n");
		bpf_object__unpin_programs(obj, tcpmon_file);
		bpf_object__close(obj);	
	} else {
		fprintf(stdout, "bpf_prog_load: program not loaded\n");
	}

	err = bpf_prog_load(prog, BPF_PROG_TYPE_KPROBE, &obj, &fd);
	if (err < 0) {
		fprintf(stderr, "bpf_prog_load: failed %i\n", err);
		return -1;
	}

	fprintf(stdout, "load\n");

	prog_bpf = bpf_object__find_program_by_title(obj, prog_label);
	err = libbpf_get_error(prog_bpf);
	if (err) {
		fprintf(stderr, "bpf_object_find: failed\n");
		return -1;
	}

	fprintf(stdout, "program pin\n");
	err = 0;//bpf_program__pin(prog_bpf, tcpmon_file);
	//err = bpf_object__pin_programs(obj, tcpmon_dir);
	if (err) {
		fprintf(stderr, "bpf_program__pin_programs: fail");
		return -1;
	}

	fprintf(stdout, "num possible cpus \n");
	//err = bpf_program__pin(prog_bpf, tcpmon_file);
	// Open perf buffer
	nr = libbpf_num_possible_cpus();
	if (nr < 0) {
		fprintf(stderr, "libbpf_num_possible_cpus: failed");
		return -1;
	}

	fprintf(stdout, "find map by name\n");
	tcpmon_map = bpf_object__find_map_by_name(obj, "tcpmon_map");
	err = libbpf_get_error(tcpmon_map);
	if (err) {
		fprintf(stderr, "bpf_object__find_map_by_name: (tcpmon_map) failed");
		return -1;
	}

	fprintf(stdout, "program by title\n");
	prog_attach = bpf_program__attach_kprobe(prog_bpf, false, "tcp_connect");
	err = libbpf_get_error(prog_attach);
	if (err) {
		fprintf(stderr, "bpf_program__attach_kprobe: failed\n");
		return -1;
	}

	fprintf(stdout, "buffer new\n");
	pb_opts.sample_cb = socket_event;
	pb_opts.ctx = &samples;
	tcpmon_events = perf_buffer__new(bpf_map__fd(tcpmon_map), NUM_PAGES, &pb_opts);
	err = libbpf_get_error(tcpmon_events);
	if (err) {
		fprintf(stderr, "perf_buffer_new: (tcpmon_events) failed");
		return -1;
	}
	fprintf(stdout, "polling:\n");
	while (1) {
		err = perf_buffer__poll(tcpmon_events, 10000);
		if (err < 0) {
			fprintf(stderr, "perf_buffer__poll: (tcp_events) failed");
			return -1;
		}
	}
}
