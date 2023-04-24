#ifndef __BPF_LATENCY_H__
#define __BPF_LATENCY_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Applying 'packed' attribute to structs causes clang to write to the
 * members byte-by-byte, as offsets may not be aligned. This is bad for
 * performance, instruction count and complexity, so don't apply this
 * attribute to structs where members are correctly aligned already
 * (e.g. by padding, layout).
 */

struct timestamp_option {
	unsigned char type;
	unsigned char len;
	unsigned char pointer;
	unsigned char flag;
	__u32 magic;
	__u32 timestamp_low;
	__u32 magic2;
	__u32 timestamp_high;
};

/* Define our magic number that we place in the timestamp IP option in place of
 * an IP address. We use this magic number to check the timestamp value is one
 * that we placed rather than a genuine timestamp IP option. Note, it translates
 * to 0.85.170.129 which is an invalid IP address.
 * We define this in terms of bytes and in network order so that the compiler
 * can optimise all of this to a fixed calculation when we calculate the
 * checksum.
 */
#define IPO_MAGIC_B0 0x00
#define IPO_MAGIC_B1 0x55
#define IPO_MAGIC_B2 0xAA
#define IPO_MAGIC_B3 0x81

#define IPO_MAGIC_H1 ((IPO_MAGIC_B0 << 8) | IPO_MAGIC_B1) // network order
#define IPO_MAGIC_H2 ((IPO_MAGIC_B2 << 8) | IPO_MAGIC_B3) // network order
#define IPO_MAGIC_W  ((IPO_MAGIC_H1 << 16) | IPO_MAGIC_H2) // network order

#define IPO_TYPE 0x44 // 68
#define IPO_LEN	 sizeof(struct timestamp_option)
#define IPO_PTR	 (IPO_LEN + 1)
#define IPO_FLAG 3 // IP address fields are prespecified

struct subnet_selector {
	u64 addr[2];
	u8 ipv6;
	u8 prefix_len;
	u8 pad[6];
};

struct latency_protocol_config {
	u8 enable;
	u8 pad1;
	u16 maxPacketSize;
	u32 pad2;
	struct subnet_selector subnets[4];
	u16 ports[4];
	u32 bucket00;
	u32 bucket01;
	u32 bucket10;
	u32 bucket25;
	u32 bucket50;
	u32 bucket75;
	u32 bucket90;
	u32 bucket99;
};

struct latency_config {
	u64 boot_ns;
	struct latency_protocol_config udp;
	struct latency_protocol_config tcp;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct latency_config);
	__uint(max_entries, 1);
} latency_config_map SEC(".maps");

/* Calculate latency from packet send time stamp. */
static inline __attribute__((always_inline)) s64
calc_latency(u64 bootns, u64 ts_low, u64 ts_high)
{
	/* Get time in microseconds. */
	u64 curr_time = (ktime_get_ns() + bootns + 500) / 1000;
	/* Clear bit 31 on both timestamps. High needs shifting by 31 bits */
	u64 ts = (ts_low & 0x7fffffff) | ((ts_high & 0x7fffffff) << 31);
	return curr_time - ts;
}

/* Allocate the latency to a histogram bucket.
 */
static inline __attribute__((always_inline)) void
add_latency(struct latency_protocol_config *cfg, u64 *buckets,
	    s64 latency)
{
	/* Negative latency is a clock sync error.
	 * Zero latency indicates latency wasn't provided.
	 */
	if (latency <= 0)
		return;

	if (cfg->bucket00 > latency)
		buckets[0]++;
	else if (cfg->bucket01 > latency)
		buckets[1]++;
	else if (cfg->bucket10 > latency)
		buckets[2]++;
	else if (cfg->bucket25 > latency)
		buckets[3]++;
	else if (cfg->bucket50 > latency)
		buckets[4]++;
	else if (cfg->bucket75 > latency)
		buckets[5]++;
	else if (cfg->bucket90 > latency)
		buckets[6]++;
	else
		buckets[7]++;
}

#endif // __BPF_LATENCY_H__
