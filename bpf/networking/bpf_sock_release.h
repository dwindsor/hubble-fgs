#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "cookie.h"
#include "bpf_fd_lookup.h"

static inline __attribute__((always_inline)) int
__sock_release(struct pt_regs *ctx, bool lazy)
{
	struct socket *socket = (struct socket *)((ctx)->di);
	struct sock *sk;
	__u64 cookie;
	u16 protocol;
	int zero = 0;
	struct fd_lookup_config *config;

	probe_read(&sk, sizeof(sk), _(&(socket->sk)));
	write_cookie_from_sk(&cookie, sk, lazy);
	if (!cookie) {
		emit_ip_error_event(ctx, 0, 0, false,
				    IP_ERROR_SOCK_RELEASE_NO_COOKIE);
		return 0;
	}

	/* We only want to release sockets for UDP as TCP is handled via
	 * calls to tcp_set_state.
	 */
	config = (struct fd_lookup_config *)map_lookup_elem(
		&fd_lookup_config_map, &zero);
	if (!config)
		return 0;
	probe_read(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (config->proto_shift) {
		protocol >>= 8;
	}

	if (protocol != IPPROTO_UDP) {
		return 0;
	}

	del_socketmap(&cookie, sk, 0, lazy);
	return 1;
}
