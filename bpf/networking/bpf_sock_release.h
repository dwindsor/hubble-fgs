#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "cookie.h"

static inline __attribute__((always_inline)) int
__sock_release(struct pt_regs *ctx, bool lazy, bool pre56)
{
	struct socket *socket = (struct socket *)((ctx)->di);
	struct sock *sk;
	__u64 cookie;
	u16 protocol;

	probe_read(&sk, sizeof(sk), _(&(socket->sk)));
	write_cookie_from_sk(&cookie, sk, lazy);
	if (!cookie)
		return 0;

	/* We only want to release sockets for UDP as TCP is handled via
	 * calls to tcp_set_state.
	 */
	probe_read(&protocol, sizeof(protocol), _(&(sk->sk_protocol)));
	if (pre56) {
		protocol >>= 8;
	}

	if (protocol != IPPROTO_UDP) {
		return 0;
	}

	del_socketmap(&cookie, sk, 0, lazy);
	return 1;
}
