#include "vmlinux.h"

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"

struct network_key {
	u64 index;
	u64 netns;
};

#define NAME_STRING 16

struct network_value {
	char name[NAME_STRING];
	u64 txbytes;
	u64 rxbytes;
	u64 txpackets;
	u64 rxpackets;
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
		map_update_elem(&network_map, key, value, BPF_NOEXIST);
	}

	probe_read(&len, sizeof(len), _(&(skb->len)));
	if (xmit) {
		__sync_fetch_and_add(&value->txbytes, (u64)len);
		__sync_fetch_and_add(&value->txpackets, 1);
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

char _license[] __attribute__((section(("license")), used)) = "GPL";
