#define ALIGNCHECKER

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "parsers/http/http.h"
#include "generic.h"
#include "lib/file.h"
#include "networking/l3/udp/bpf_udp_event.h"
#include "networking/bpf_fd_lookup.h"

// Layer 3
struct msg_ip_event _msg_ip_event;
struct msg_ip_with_stats_event _msg_ip_with_stats_event;

// Layer 7
struct __msg_http_event _msg_http_event;
struct msg_tls_event _msg_tls_event;
struct __http_state_stats _http_state_stats;

// FIM
struct inode_key _inode_key;
struct inode_val _inode_val;
struct msg_file_path _msg_file_path;
struct msg_fs_info _msg_fs_info;
struct msg_file_ops _msg_file_ops;
struct msg_file_split_path _msg_file_split_path;
struct msg_rename_elem _msg_rename_elem;
struct msg_file_rename_ops _msg_file_rename_ops;
struct file_config_map_value _file_config_map_value;
struct file_exec_config_map_value _file_exec_config_map_value;
struct lpm_key _lpm_key;
struct lpm_val _lpm_val;
struct digest_key _digest_key;
struct file_exec_stats _file_exec_stats;
struct file_sel_caps _file_sel_caps;
struct file_sel_namespaces _file_sel_namespaces;
struct file_errors _file_errors;
struct pattern_val _pattern_val;
struct full_path _full_path;
struct glob_state _glob_state;

struct fd_lookup_config _fd_lookup_config;
