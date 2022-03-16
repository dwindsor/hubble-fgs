#ifndef netns_h_INCLUDED
#define netns_h_INCLUDED

#include "api.h"

static inline __attribute__((always_inline))
u32 sock_netns(struct sock *skp)
{
	struct ns_common *common;
	struct net *netns;
	u32 ns;

	if (!skp)
		return 0;

	probe_read_kernel(&netns, sizeof(netns), _(&skp->__sk_common.skc_net));
	if (!netns)
		return 0;

	common = _(&netns->ns);
	probe_read_kernel(&ns, sizeof(ns), _(&common->inum));

	return ns;
}

#ifdef SK_MSG

static inline __attribute__((always_inline))
u32 msg_netns(struct sk_msg_md *msg)
{
	struct bpf_sock *bpfsk;
	struct sock *sk;

	if (!bpf_core_field_exists(msg->sk) || !msg->sk)
		return 0;

	/* We need to first load the socket pointer onto the stack.
         * Direct read from &msg->sk yields NULL. */
	bpfsk = msg->sk;
	probe_read_kernel(&sk, sizeof(sk), &bpfsk);
	if (!sk)
		return 0;

    return sock_netns(sk);
}

#endif /* SK_MSG */

#ifdef SK_SKB

static inline __attribute__((always_inline))
u32 skskb_netns(struct __sk_buff *skb)
{
	struct bpf_sock *bpfsk;
	struct sock *sk;

	if (!skb->sk)
		return 0;

	/* We need to first load the socket pointer onto the stack.
         * Direct read from &skb->sk yields NULL. */
	bpfsk = skb->sk;
	probe_read_kernel(&sk, sizeof(sk), &bpfsk);
	if (!sk)
		return 0;

    return sock_netns(sk);
}

#endif /* SK_SKB */

#endif /* netns_h_INCLUDED */
