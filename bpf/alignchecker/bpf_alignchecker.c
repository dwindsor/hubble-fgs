#define ALIGNCHECKER

#include "vmlinux.h"
#include "api.h"
#include "hubble_msg.h"
#include "parsers/http/http.h"
#include "lib/file.h"

/* DECLARE declares a unique usage of the union or struct 'x' on the stack.
 *
 * To prevent compiler from optimizing away the var, we pass a reference
 * to the var to a BPF helper function which accepts a reference as
 * an argument.
 *
 * We make the variable here pointer in order to fit all structs
 * even in this case object files contain all the required information
 */
#define DECLARE(datatype, x, iter)               \
	{                                        \
		datatype x *s##iter = 0;         \
		trace_printk("%p", 1, &s##iter); \
		iter++;                          \
	}

/* This function is a placeholder for C struct definitions shared with Go,
 * it is never executed.
 */
int main(void)
{
	int iter = 0;

	// from perf_event_output
	DECLARE(struct, msg_generic_kprobe, iter);
	DECLARE(struct, msg_execve_event, iter);
	DECLARE(struct, msg_exit, iter);
	DECLARE(struct, msg_http_event, iter);
	DECLARE(struct, msg_tls_cont_event, iter);
	DECLARE(struct, msg_tls_event, iter);
	DECLARE(struct, msg_test, iter);
	DECLARE(struct, msg_ipv4_tcp_connect, iter);
	DECLARE(struct, msg_ip_event, iter);
	DECLARE(struct, msg_kfree_skb, iter);
	DECLARE(struct, msg_udp_event, iter);

	// from maps
	DECLARE(struct, event, iter);
	DECLARE(struct, msg_execve_key, iter);
	DECLARE(struct, execve_map_value, iter);
	DECLARE(struct, msg_tls_ip, iter);
	DECLARE(struct, socketmap_value, iter);

	// from FIM
	DECLARE(struct, hash_map_file_key, iter);
	DECLARE(struct, hash_map_file_val, iter);
	DECLARE(struct, msg_file_path, iter);
	DECLARE(struct, msg_fs_info, iter);
	DECLARE(struct, msg_file_ops, iter);
	DECLARE(struct, msg_file_split_path, iter);
	DECLARE(struct, msg_rename_elem, iter);
	DECLARE(struct, msg_file_rename_ops, iter);

	return 0;
}
