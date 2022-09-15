#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "iso_msg_types.h"

struct network_key {
	u64 index;
	u64 netns;
};

#define NAME_STRING 16

/* Qdisc qlen historgram with 8 buckets */
struct qdisc_qlen_hist {
	u32 b99;
	u32 b90;
	u32 b75;
	u32 b50;
	u32 b25;
	u32 b10;
	u32 b01;
	u32 b00;
};

struct network_value {
	char name[NAME_STRING];
	u64 txbytes;
	u64 rxbytes;
	u64 txpackets;
	u64 rxpackets;
	struct qdisc_qlen_hist qlen;
};

struct bpf_map_def __attribute__((section("maps"), used)) network_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct network_key),
	.value_size = sizeof(struct network_value),
	.max_entries = 256,
};

struct bpf_map_def __attribute__((section("maps"), used)) key_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct network_key),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) value_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct network_value),
	.max_entries = 1,
};

#define P99 990
#define P90 900
#define P75 750
#define P50 500
#define P25 250
#define P10 100
#define P01 10
#define P00 0

static inline __attribute__((always_inline)) void
qlen_hist(struct network_value *value, __u32 qlen)
{
	if (qlen >= P99)
		value->qlen.b99++;
	else if (qlen >= P90)
		value->qlen.b90++;
	else if (qlen >= P75)
		value->qlen.b75++;
	else if (qlen >= P50)
		value->qlen.b50++;
	else if (qlen >= P25)
		value->qlen.b25++;
	else if (qlen >= P10)
		value->qlen.b10++;
	else if (qlen >= P01)
		value->qlen.b01++;
	else if (qlen >= P00)
		value->qlen.b00++;
}

static inline __attribute__((always_inline)) u64
get_netns(struct net_device *dev)
{
	struct ns_common nscommon;
	possible_net_t nd_net;
	struct net *net;

	probe_read(&nd_net, sizeof(nd_net), _(&(dev->nd_net)));
	if (!nd_net.net)
		return 0;

	probe_read(&net, sizeof(net), _(&(nd_net.net)));
	if (!net)
		return 0;

	probe_read(&nscommon, sizeof(nscommon), _(&(net->ns)));
	return nscommon.inum;
}

static inline __attribute__((always_inline)) int
interface_stats(struct sk_buff *skb, bool xmit)
{
	struct network_value *value;
	struct network_key *key;
	struct net_device *dev;
	int len, zero = 0;

	key = map_lookup_elem(&key_heap, &zero);
	if (!key)
		return 1;

	probe_read(&dev, sizeof(dev), _(&skb->dev));
	if (!dev)
		return 1;

	probe_read(&key->index, sizeof(int), _(&(dev->ifindex)));
	key->netns = get_netns(dev);

	value = map_lookup_elem(&network_map, key);
	if (!value) {
		value = map_lookup_elem(&value_heap, &zero);
		if (!value)
			return 1;
		probe_read(&value->name, NAME_STRING, _(&(dev->name)));
		value->txbytes = value->rxbytes = value->txpackets =
			value->rxpackets = 0;
		map_update_elem(&network_map, key, value, BPF_NOEXIST);
	}

	probe_read(&len, sizeof(len), _(&(skb->len)));
	if (xmit) {
		struct Qdisc *qdisc;
		struct qdisc_skb_head q;

		__sync_fetch_and_add(&value->txbytes, (u64)len);
		__sync_fetch_and_add(&value->txpackets, 1);

		/* Look up Qdisc, the safty of this is not obvious. The trick
		 * is we are inside a rcu critical section and rcu dereference
		 * is just a load in most cases. Then inc/dec on the qlen stats
		 * are done with local atomics. Finally we don't really care if
		 * we get the answer +-num_cores we are bucktizing the values
		 * anyways. :wave :wave :wave
		 */
		probe_read(&qdisc, sizeof(qdisc), _(&(dev->qdisc)));
		if (!qdisc)
			return 0;
		probe_read(&q, sizeof(q), _(&(qdisc->q)));
		qlen_hist(value, q.qlen);
	} else {
		__sync_fetch_and_add(&value->rxbytes, (u64)len);
		__sync_fetch_and_add(&value->rxpackets, 1);
	}

	return 0;
}

__attribute__((section(("kprobe/dev_queue_xmit")), used)) int
dev_queue_xmit(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->di;

	return interface_stats(skb, true);
}

__attribute__((section("kprobe/netif_receive_skb"), used)) int
__netif_receive_skb_core(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->di;

	return interface_stats(skb, false);
}

__attribute__((section("kprobe/napi_gro_receive"), used)) int
napi_gro_receive(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->si;

	return interface_stats(skb, false);
}

__attribute__((section("kprobe/__netif_rx"), used)) int
__netif_rx(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx->di;

	return interface_stats(skb, false);
}

#define NETDEV_UNREGISTER 6

__attribute__((section("kprobe/call_netdevice_notifiers_info"), used)) int
unregister_netdevice(struct pt_regs *ctx)
{
	struct netdev_notifier_info *info =
		(struct netdev_notifier_info *)ctx->si;
	unsigned long type = (unsigned long)ctx->di;
	struct network_key *key;
	struct net_device *dev;
	int zero = 0;

	if (type != NETDEV_UNREGISTER)
		return 1;

	key = map_lookup_elem(&key_heap, &zero);
	if (!key)
		return 1;

	probe_read(&dev, sizeof(dev), _(&(info->dev)));
	probe_read(&key->index, sizeof(int), _(&(dev->ifindex)));
	key->netns = get_netns(dev);

	map_delete_elem(&network_map, key);
	return 0;
}

struct msg_netns_exit {
	struct msg_common common;
	__u64 inum;
};

struct bpf_map_def __attribute__((section("maps"), used)) netns_exit_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct msg_netns_exit),
	.max_entries = 1,
};

__attribute__((section("kprobe/net_ns_net_exit"), used)) int
net_ns_net_exit(struct pt_regs *ctx)
{
	struct net *net = (struct net *)ctx->di;
	struct msg_netns_exit *val;
	struct ns_common nscommon;
	int zero = 0;

	probe_read(&nscommon, sizeof(nscommon), _(&(net->ns)));

	val = map_lookup_elem(&netns_exit_heap, &zero);
	if (!val)
		return 1;
	val->common.op = ISO_MSG_OP_NETNS_EXIT;
	val->common.size = sizeof(struct msg_netns_exit);
	val->inum = nscommon.inum;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, val,
			  sizeof(struct msg_netns_exit));
	return 0;
}

char _license[] __attribute__((section(("license")), used)) = "GPL";
