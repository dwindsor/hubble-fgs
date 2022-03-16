#ifndef __BPF_INET_H_
#define __BPF_INET_H_

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#define SOCK_CTX

#include "api.h"
#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_udp.h"
#include "bpf_burst_process.h"
#include "bpf_burst.h"
#include "cookie.h"

#define NSTOSEC 1000000000L
#define MSTONS  1000000L
#define MSTOSEC 1000L

#define MAX_DNS_PORTS 32

struct udp_sensor_config {
	u16 dnsPorts[4];
	u64 watermark_enable;
	u64 watermark_avg_window_size_ms;
	u64 watermark_window_size;
	u64 watermark_trigger_percent;
};

struct bpf_map_def __attribute__((section("maps"), used)) udp_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct udp_sensor_config),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) dns_ports_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u16),
	.value_size = sizeof(u8),
	.max_entries = MAX_DNS_PORTS,
};

static inline __attribute__((always_inline))
u8 ip_payload_off(struct iphdr *ip)
{
	u8 ip_off;

	ip_off = ip->ihl;
	ip_off &= 0x0f;
	ip_off *= 4;
	return ip_off;
}

static inline __attribute__((always_inline))
struct udp_info_key *udp4_key_lazy(struct __sk_buff *skb,
			      struct iphdr *ip,
			      int *payload_off, int *payload_sz)
{
	struct udp_info_key *key;
	struct udphdr udp;
	int err, zero = 0;
	__u8 udp_off;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 0;

	udp_off = ip_payload_off(ip);

	err = skb_load_bytes(skb, udp_off, &udp, sizeof(struct udphdr));
	if (err)
		return 0;

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->sport = udp.source;
	key->dport = udp.dest;
	key->padding = 0;
	key->cookie = 0;

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp.len) - sizeof(struct udphdr);
	return key;
}

static inline __attribute__((always_inline))
struct udp_info_key *udp4_key(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, int *payload_off, int *payload_sz, bool cookie)
{
	struct udp_info_key *key;
	struct udphdr *udp;
	int zero = 0;
	__u8 udp_off;

	key = map_lookup_elem(&udp_key_heap, &zero);
	if (!key)
		return 0;

	udp_off = ip_payload_off(ip);

	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return 0;

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->sport = udp->source;
	key->dport = udp->dest;
	key->padding = 0;
	if (cookie)
		key->cookie = get_socket_cookie(skb);
	else
		key->cookie = 0;

	*payload_off = udp_off + sizeof(struct udphdr);
	*payload_sz = bpf_ntohs(udp->len) - sizeof(struct udphdr);
	return key;
}

static inline __attribute__((always_inline))
void swap_key(struct udp_info_key *key)
{
	u32 addr = key->saddr;
	u16 port = key->sport;

	key->saddr = key->daddr;
	key->sport = key->dport;
	key->daddr = addr;
	key->dport = port;
}

/* This logic is a bit racy, but we can handle it. Thinking through the
 * cases. Multiple sends may happen concurrently on the same key. If
 * the key is not in the map we may have multiple cores in the !value
 * branch. This is OK as long as the user space is aware this may happen.
 * In this case user space will see duplicate 'connect' events and
 * metrics will correctly aggreagate them. One of these connects will
 * win the map_update_elem race. And any future lookups from BPF side
 * will be additive on that event. The value branch must be slightly
 * careful with pkt/byte couonter updates to ensure concurrent update
 * on the value are handled, we use __fetch_and_adds here for this to
 * be safe. And the only remaining ugly bit is ktime can't be trusted.
 * If more than one core is writing into ktime we may corrupt it. So
 * we need a WRITE_ONCE to ensure the compiler does this in a single
 * store. Then we get a coherent ktime although we don't know what
 * core its from. We don't really care though as long as its
 * approximately accurate which it will be or we wouldn't have
 * concurrent cores here.
 *
 * To accomodate older kernels that do not have cookie set we leave
 * pid and pid_ktime empty on receive case when no proces is found.
 * These values are then populated from the skb_consume_udp path where
 * we are in user context and can get the process info through normal
 * event_find_curr() hooks. We can't do that here because the current
 * pointer is set to kernel context at IP stack. This is not ideal
 * because it can mean if no process calls recv() on the data it may
 * never be accounted for. It will however, be in the udp_map and
 * user space can decide how to handle these cases. In the worse
 * case its expected user space can use the tuple key and timestamp
 * plus socket events to track back the process in a time series
 * database.
 */
static inline __attribute__((always_inline))
struct udp_info_value *__udp4_send(struct __sk_buff *skb,
				   struct udp_info_key *key,
				   int payload_off, int payload_sz, bool send)
{
	struct udp_info_value *value;
	int zero = 0;

	value = map_lookup_elem(&udp_map, key);
	if (!value) {
		struct execve_map_value *process;

		value = map_lookup_elem(&udp_value_heap, &zero);
		if (!value)
			return 0;

		if (send)
			udp_info_tx_reset(value, payload_sz);
		else
			udp_info_rx_reset(value, payload_sz);

		process = map_lookup_elem(&socket_cookie_to_proc_map,
					  &key->cookie);
		if (process) {
			value->pid = process->key.pid;
			value->pid_ktime = process->key.ktime;
		} else {
			value->pid = 0;
			value->pid_ktime = 0;
		}
		map_update_elem(&udp_map, key, value, 0);
	} else {
		if (send)
			update_tx_value(value, payload_sz);
		else
			update_rx_value(value, payload_sz);
	}
	return value;
}

/* Lazy versions of udp4 send have two deficiencies that make them
 * sub-optimal. First keys do not include cookie info this means we
 * could in-theory collide across network namespaces, e.g. two sockets
 * in different network namespaces with the same 5-tuple will aggregate
 * their statistics -- this feels unlikely. The other one is payload
 * copy to user land is not supported this is to support loading on
 * older kernels without the necessary bpf helpers.
 */
static inline __attribute__((always_inline))
int udp4_send_lazy(struct __sk_buff *skb, struct iphdr *ip, bool send)
{
	int payload_off, payload_sz;
	struct udp_info_key *key;

	key = udp4_key_lazy(skb, ip, &payload_off, &payload_sz);
	if (!key)
		return 1;

	if (!send) {
		swap_key(key);
		key->sport = bpf_ntohs(key->sport);
	} else {
		key->sport = bpf_ntohs(key->sport);
	}
	__udp4_send(skb, key, payload_off, payload_sz, send);
	return 1;
}

static inline __attribute__((always_inline))
int dns_port_match(u16 *ports, u16 port1, u16 port2)
{
	if (ports[0] == port1 || ports[0] == port2 ||
		ports[1] == port1 || ports[1] == port2 ||
		ports[2] == port1 || ports[2] == port2 ||
		ports[3] == port1 || ports[3] == port2) {
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline))
int udp4_send(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, bool send, bool cookie)
{
	int zero, payload_off, payload_sz;
	struct udp_info_value *info;
	struct udp_info_key *key;
	struct udp_sensor_config *config;

	key = udp4_key(skb, ip, data, data_end, &payload_off, &payload_sz, cookie);
	if (!key)
		return 1;

	if (!send) {
		swap_key(key);
		key->sport = bpf_ntohs(key->sport);
	} else {
		key->sport = bpf_ntohs(key->sport);
	}

	info = __udp4_send(skb, key, payload_off, payload_sz, send);
	if (!info)
		return 1;

	zero = 0;
	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config)
		return 1;

	if (config->dnsPorts[0] != 0 && dns_port_match(config->dnsPorts, key->sport, bpf_ntohs(key->dport))) {
		/* We subtract 1 from payload_sz because we need to +1 it
		 * later to sat verifier constraint that skb_load_bytes
		 * must be nonzero.
		 */
		emit_udp_payload_event(skb, key, info, payload_off, payload_sz - 1);
	}
	return 1;
}

static inline __attribute__((always_inline))
void init_burst_log(u64 burst_key, u64 vol, u64 current_time_ns)
{
	struct process_network_burst_log *burst_log;
	int err, zero = 0;
	u64 *cntr;

	burst_log = map_lookup_elem(&pn_burst_value_heap, &zero);
	if (!burst_log)
		return;
	burst_log->hist_vol = 0;
	burst_log->win_vol = vol;
	burst_log->last_win_vol = 0;
	burst_log->last_packet_time = current_time_ns;
	burst_log->burst = false;
	err = map_update_elem(&pn_burst_map, &burst_key, burst_log, BPF_ANY);
	if (!err && (cntr = map_lookup_elem(&pn_burst_map_stats, &zero)))
		*cntr = *cntr + 1;
}

// There are two critical design decisions with the UDP burst monitor.
// First, if we wanted to implement a sliding window approach (comparing
// sliding window average to the historical long-term average), then we
// would need to temporarily store payload sizes against time stamps, to
// allow us to calculate the volume within the sliding window. This
// approach would require a data structure where older entries could be
// aged off and subtracted from a total (not easy in BPF) or the
// entire data structure would need to be traversed to calculate the
// current window volume (not nice in BPF). Additionally, sizing the data
// structure would not be trivial, potentially leading to missing data.
//
// The solution is to use fixed-position windows. By dividing time since
// the process started into a series of (non-overlapping) windows, we can
// simply deal with packets that arrived before the current window
// (historical data), or within our current window. It is trivial to calc
// which a packet is from its arrival time.
//
// Second, we need to account for multiple cores accessing the global
// historical values. Switching from one fixed-position window to the next
// must only happen in one thread, and if multiple threads collide, then
// this approach would fail.

static inline __attribute__((always_inline))
void udp_burst(struct __sk_buff *skb, struct iphdr *ip, void *data, void *data_end, u64 send)
{
	struct udp_sensor_config *config;
	u64 burst_key;
	u64 cookie;
	struct execve_map_value *process;
	u8 udp_off;
	struct udphdr *udp;
	int vol;
	struct process_network_burst_log *burst_log;
	int zero = 0;

	u64 current_time_ns = ktime_get_ns();

	config = map_lookup_elem(&udp_config_map, &zero);
	if (!config || !config->watermark_enable)
		return;

	cookie = get_socket_cookie(skb);
	process = map_lookup_elem(&socket_cookie_to_proc_map, &cookie);
	if (!process)
		return;

	udp_off = ip_payload_off(ip);
	udp = (struct udphdr *)(data + udp_off);
	if (data + udp_off + sizeof(*udp) > data_end)
		return;
	vol = bpf_ntohs(udp->len) - sizeof(struct udphdr);

	burst_key = pid_to_udp_burst_key(process->key.pid, send);

	burst_log = map_lookup_elem(&pn_burst_map, &burst_key);
	if (!burst_log) {
		// First packet for this process in this direction.
		// This could be racy in the sense that multiple cores could initialise the
		// global entry for this process.
		init_burst_log(burst_key, vol, current_time_ns);
		return;
	}

	u64 ns_since_win_start = (current_time_ns - process->key.ktime) % config->watermark_window_size;
	u64 current_win_start_ns = current_time_ns - ns_since_win_start;
	u64 last_win_start_ns = current_win_start_ns - config->watermark_window_size;

	u32 old_burst = READ_ONCE(burst_log->burst);

	// Read and write the last packet time with atomic instructions
	// to reduce the race in the 'if' statement. Once the read/write
	// has occurred, subsequent threads will see a last packet time
	// in the current window and simply add to that. There is a slim
	// chance of multiple threads arriving within 1 instruction of
	// each other and all attempting to update the windows/history,
	// but this is considered unlikely.
	//
	// If the unlikely race condition occurs, both threads will attempt
	// to move the current window to the last window and the last window
	// to history, resulting in the current window missing one packet's
	// volume, and the old window being added twice to last or history.
	// This will cause the averages to be wrong, so the effect will be
	// skewed by the historical averages and the packet volumes -
	// sometimes it would matter, and other times not so much.
	u64 last_packet_time = READ_ONCE(burst_log->last_packet_time);
	WRITE_ONCE(burst_log->last_packet_time, current_time_ns);

	if (last_packet_time > current_win_start_ns) {
		// Add packet volume to current window.
		__sync_fetch_and_add(&burst_log->win_vol, vol);
	} else {
		// Volume currently accumulated in current window is old.
		if (last_packet_time > last_win_start_ns) {
			// The current window volume is actually for the last window
			// (e.g. a new window has started since the last packet was
			// received).
			//
			// Move the last window to history, current window to last,
			// and store current packet in new current window.
			__sync_fetch_and_add(&burst_log->hist_vol, burst_log->last_win_vol);
			WRITE_ONCE(burst_log->last_win_vol, READ_ONCE(burst_log->win_vol));
			WRITE_ONCE(burst_log->win_vol, vol);
		} else {
			// The current window volume is actually older than the
			// last window and therefore historic (e.g. two windows
			// have started since the last packet was received).
			//
			// Move the last window and current window to history,
			// and store the current packet in new current window.
			// Also, any existing burst must be over.
			__sync_fetch_and_add(&burst_log->hist_vol, burst_log->last_win_vol);
			__sync_fetch_and_add(&burst_log->hist_vol, burst_log->win_vol);
			WRITE_ONCE(burst_log->win_vol, vol);
			// Zero the last window
			WRITE_ONCE(burst_log->last_win_vol, 0);
			old_burst = 0;
		}
	}

	u64 hist_vol = READ_ONCE(burst_log->hist_vol);
	u64 win_vol = READ_ONCE(burst_log->win_vol);
	u64 last_win_vol = READ_ONCE(burst_log->last_win_vol);
	u64 hist_avg = (hist_vol * NSTOSEC) / (last_win_start_ns - process->key.ktime);
	u64 hist_avg_trigger = (hist_avg * config->watermark_trigger_percent) / 100;

	// Check if the average volume over the last complete window and the current
	// partial window exceeds the trigger threshold. This approach provides a
	// fair average of the current rate.
	u64 new_win_rate = ((last_win_vol + win_vol) * NSTOSEC) / (config->watermark_window_size + ns_since_win_start);
	if (old_burst ^ (new_win_rate > hist_avg_trigger)) {
		// If we were already bursting and no longer are, or weren't bursting
		// but now are (XOR) then emit event.
		struct msg_process_network_burst_event *val;
		int zero = 0;

		val = map_lookup_elem(&pn_burst_event_heap, &zero);
		if (!val)
			return;

		*val = (struct msg_process_network_burst_event) {
			.common.op = MSG_OP_IPV4_PROCESS_BURST,
			.common.size = sizeof(struct msg_process_network_burst_event),
			.common.ktime = ktime_get_ns(),
			.key.pid = process->key.pid,
			.key.ktime = process->key.ktime,
			.protocol = IPPROTO_UDP,
			.burst_start_dir = burst_start_dir(old_burst == 0, send),
			.window_size = config->watermark_avg_window_size_ms,
			.hist_avg = hist_avg,
			.hist_trigger = hist_avg_trigger,
			.window_avg = new_win_rate,
		};
		perf_event_output(skb, &tcpmon_map, BPF_F_CURRENT_CPU, val, sizeof(struct msg_process_network_burst_event));
		WRITE_ONCE(burst_log->burst, (old_burst == 0));
	}
}

static inline __attribute__((always_inline))
void inet_handler_lazy(struct __sk_buff *skb, int send)
{
	struct iphdr ip;
	u8 v4_prot;
	int err;

	err = skb_load_bytes(skb, 0, &ip, sizeof(struct iphdr));
	if (err < 0) {
		return;
	}
	v4_prot = ip.protocol;
	if (v4_prot == IPPROTO_UDP)
		udp4_send_lazy(skb, &ip, send);
	return;
}

static inline __attribute__((always_inline))
void inet_handler(struct __sk_buff *skb, int send, int cookie)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (long *)(long)skb->data;
	struct iphdr *ip;
	u8 v4_prot;

	if (data + sizeof(struct iphdr) > data_end)
		return;
	ip = (struct iphdr *)data;
	v4_prot = ip->protocol;

	if (v4_prot == IPPROTO_TCP) { // TCP
		return; 
	} else if (v4_prot == IPPROTO_UDP) { // UDP
		udp4_send(skb, ip, data, data_end, send, cookie);
		udp_burst(skb, ip, data, data_end, send);
	}
	return;
}

#endif //__BPF_INET_H_
