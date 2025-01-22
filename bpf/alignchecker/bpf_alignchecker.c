#define ALIGNCHECKER

#include "vmlinux.h"
#include "api.h"
#include "bpf_event.h"
#include "parsers/http/http.h"
#include "generic.h"
#include "lib/file.h"
#include "networking/l3/udp/bpf_udp_event.h"
#include "networking/bpf_fd_lookup.h"
#include "parsers/dns/dns_parser.h"
#include "process/process_endpoint.h"

// Layer 3
struct msg_ip_event _msg_ip_event;
struct msg_ip_with_stats_event _msg_ip_with_stats_event;
struct tcpsocketmap_value _tcpsocketmap_value;
struct udp_info_key _udp_info_key;
struct udp_info_value _udp_info_value;
struct msg_socket_stats _msg_socket_stats;

// Layer 7
struct __msg_http_event _msg_http_event;
struct __msg_http _msg_http;
struct msg_tls_event _msg_tls_event;
struct msg_tls _msg_tls;
struct __http_state_stats _http_state_stats;
struct ip_addr _ip_addr;

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

// App model
struct msg_execve_key _process_execve_key;
struct process_tree_value _process_tree_value;
struct process_tree_key _process_tree_key;
struct destination_endpoint_key _destination_endpoint_key;
struct destination_endpoint_value _destination_endpoint_value;
struct listen_endpoint_key _listen_endpoint_key;
struct listen_endpoint_value _listen_endpoint_value;
struct endpoint_id_key _endpoint_id_key;
struct endpoint_id_value _endpoint_id_value;
struct process_tree_binary_uid_key _process_tree_binary_uid_key;
