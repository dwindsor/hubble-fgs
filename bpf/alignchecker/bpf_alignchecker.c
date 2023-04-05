#define ALIGNCHECKER

#include "vmlinux.h"
#include "api.h"
#include "hubble_msg.h"
#include "parsers/http/http.h"
#include "generic.h"
#include "lib/file.h"
#include "networking/bpf_udp.h"

// from perf_event_output
struct msg_generic_kprobe _1;
struct msg_execve_event _2;
struct msg_exit _3;
struct msg_http_event _4;
struct msg_tls_cont_event _5;
struct msg_tls_event _6;
struct msg_test _7;
// Old, unused event.
// struct msg_ipv4_tcp_connect _8;
struct msg_ip_event _9;
struct msg_kfree_skb _10;
struct msg_udp_event _11;

// from maps
struct event _12;
struct msg_execve_key _13;
struct execve_map_value _14;
struct msg_tls_ip _15;
struct socketmap_value _16;

// from FIM
struct hash_map_file_key _17;
struct hash_map_file_val _18;
struct msg_file_path _19;
struct msg_fs_info _20;
struct msg_file_ops _21;
struct msg_file_split_path _22;
struct msg_rename_elem _23;
struct msg_file_rename_ops _24;
struct file_config_map_value _25;
