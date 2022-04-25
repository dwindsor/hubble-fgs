#define ALIGNCHECKER

#include "include/vmlinux.h"
#include "include/api.h"
#include "lib/hubble_msg.h"
#include "parsers/http/http.h"

/* DECLARE declares a unique usage of the union or struct 'x' on the stack.
 *
 * To prevent compiler from optimizing away the var, we pass a reference
 * to the var to a BPF helper function which accepts a reference as
 * an argument.
 *
 * We make the variable here pointer in order to fit all structs
 * even in this case object files contain all the required information
 */
#define DECLARE(datatype, x, iter)                                             \
	{                                                                      \
		datatype x *s##iter = 0;                                       \
		trace_printk("%p", 1, &s##iter);                               \
		iter++;                                                        \
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
	DECLARE(struct, msg_ipv4_event, iter);
	DECLARE(struct, msg_kfree_skb, iter);
	DECLARE(struct, msg_ipv4_udp_event, iter);

	// from maps
	DECLARE(struct, event, iter);
	DECLARE(struct, execve_map_value, iter);
	DECLARE(struct, msg_tls_ipv4, iter);
	DECLARE(struct, socketmap_value, iter);

	return 0;
}
