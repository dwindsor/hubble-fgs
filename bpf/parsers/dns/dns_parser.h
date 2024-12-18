// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "vmlinux.h"
#include "bpf_task.h"
#include "../../lib/address_family.h"
#include "../../lib/config.h"

#define DNS_PORT     53
#define DNS_HDR_SIZE 12
#define A_RECORD     1
#define AAAA_RECORD  28

#define MAX_NAME_SIZE  255
#define MAX_LABEL_SIZE 63

// https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
#define UDP_MAX_SIZE 512

// Ethernet header (14 bytes) are already parsed in skb and the IP headers size
// can be from 20 to 60 bytes.
#define SKB_DATA_MAX_SIZE UDP_MAX_SIZE + 60

// A DNS name can contain MAX_NUMBER_LABEL labels. These would be of length one,
// so 127 bytes needed to set length to 1, 127 bytes for the actual char and a
// zero at the end.
#define MAX_NUMBER_LABEL 127

// A DNS A answer will contain at minimum a 2 bytes compressed name, 10 bytes
// for type, class, TTL, data_length and 4 bytes for the IPv4 address.
#define MIN_ANSWER_LEN 16

// Let's compute how many answers a UDP DNS query can contain.
// ---
// Protocol overhead:
// UDP + DNS headers
// 8   + 12          = 20 bytes
// ---
// One A query:
// minimal name + type + class
// 3              2      2     = 7 bytes
// ---
// Typical answer is:
// Name (compressed) + Type + Class + TTL + Length + IPv4 Addresss
// 2                 + 2    + 2     + 4   + 2      + 4             = 16 bytes
// ---
// UDP_MAX_SIZE(512) - (20 + 7) = 485
// 485 / 16 = 30,3125
#define MAX_DNS_ANSWERS_UDP 30

// The first two bits of a compressed message are ones. This allows a pointer to
// be distinguished from a label, since the label must begin with two zero bits
// because labels are restricted to 63 octets or less.
#define COMPRESSED_MSG_MASK 0b11000000

#define MAX_ERROR_CODE 40

#define DNS_PARSER_SKIP	   1
#define DNS_PARSER_SUCCESS 0

struct dnshdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	// we can't tell the verifier that (name_offset + label_length < 255) so we need 63 extra bytes.
	__type(value, char[MAX_NAME_SIZE + MAX_LABEL_SIZE]);
} name_heap_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 56); // This is an arbitrary number for testing, TBD
	__type(key, __u32);
	__type(value, char[MAX_NAME_SIZE]);
} ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_ERROR_CODE);
	__type(key, __u32);
	__type(value, __u32);
} tg_dns_error_map SEC(".maps");

uint32_t zero = 0;

FUNC_INLINE bool dns_parser_enabled()
{
	struct cfg_value *cfg;
	cfg = (struct cfg_value *)map_lookup_elem(&tg_cfg_map, &zero);
	return cfg && cfg->enable_bpf_dns_parser;
}

// parse_dns_name_label parses a label in a uncompressed DNS name and write it
// into the name heap map. It returns the offset needed to advance into the data
// to skip the label on success. You need to add one to skip the last zero byte.
// The length of the label is equal to the returned offset minus one, because of
// the first length byte. On failure, it returns < 0.
__attribute__((noinline)) int
parse_dns_name_label(struct __sk_buff *skb, __u16 off, char *data_start)
{
	__u8 name_offset, label_length;
	char *data, *data_end, *name;

	data_end = (void *)(long)skb->data_end;
	if (off > SKB_DATA_MAX_SIZE) {
		return -20;
	}
	data = (void *)(long)skb->data + off;

	// This is the total current length of the name, check that it does not overflow
	if (data - data_start > MAX_NAME_SIZE)
		return -21;

	name_offset = data - data_start;

	if (data + 1 > data_end)
		return -22;

	// Regular label, read the label length and skip the label
	label_length = *((__u8 *)data) & MAX_LABEL_SIZE; // Max length is 63
	data += 1; // Move past length byte

	name = map_lookup_elem(&name_heap_map, &zero);
	if (!name)
		return -23;

	if (name_offset > 0) {
		// Move one byte too much because of label length. On newer kernels, we
		// can directly use name[name_offset - 1] that minimize the number of
		// instructions but it doesn't work on older ones.
		name_offset--;
		if (label_length == 0) {
			name[name_offset] = '\0';
			// Remember that caller should add the last zero byte to the offset
			return 0;
		}
		// Adding the dot after the label
		name[name_offset++] = '.';
	}

	// Copy one byte at a time
	for (size_t i = 0; i < label_length; ++i) {
		// We can't do the check globally on the pointer because the verifier can't
		// track that data is "similar" to data[i] later on, so that we need to do
		// the check every iteration. It's not optimal to read one byte at a time
		// but it's still better than doing probe_read_kernel.
		if (data + (i + 1) > data_end)
			return -24;

		name[name_offset + i] = data[i];
	}

	return label_length + 1;
}

// parse_dns_answer parses a DNS query answer, it skips any non A-type answer,
// parses the IPv4 given along an A-type answer and writes it into the domain
// name to IP map. It returns the offset needed to advance into the data to skip
// the answer on success and < 0 on failure.
__attribute__((noinline)) int8_t
parse_dns_answer(struct __sk_buff *skb, __u16 off)
{
	__u8 first_byte, offset;
	__u16 type, data_len;
	__u32 ipv4;
	char *data, *data_end;

	data_end = (void *)(long)skb->data_end;
	if (off > SKB_DATA_MAX_SIZE) {
		return -30;
	}
	data = (void *)(long)skb->data + off;

	if (!data) {
		return -31;
	}

	// Light parse the compressed DNS name: do not actually retrieve the offset
	// from the pointer, just make sure it's a valid compressed name starting
	// with the correct two bits and skipping the two bytes of the pointer.
	//
	// Simplification: we assume a DNS query response can contain at maximum one
	// question, so the domain should be unique. Even in case of canonical alias
	// we still consider the main domain is the correct one.
	//
	// A valid compressed name should be two bytes.
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// | 1  1|                OFFSET                   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	if (data + sizeof(u8) * 2 > data_end)
		return -32;

	first_byte = *((__u8 *)data);
	if ((first_byte & COMPRESSED_MSG_MASK) != COMPRESSED_MSG_MASK)
		return -33;

	// Potential TODO: verify the pointer is correct or give up
	// Skip the pointer byte
	offset = sizeof(u8) * 2;
	data += offset;

	// The answer should contain type, class, TTL and data_len
	if (data + (sizeof(u16) * 2 + sizeof(u32) + sizeof(u16)) > data_end)
		return -34;

	type = bpf_ntohs(*(__u16 *)data);
	data_len = bpf_ntohs(*(__u16 *)(data + sizeof(u16) * 2 + sizeof(u32)));
	offset += sizeof(u16) * 2 + sizeof(u32) + sizeof(u16);
	data += sizeof(u16) * 2 + sizeof(u32) + sizeof(u16);

	if (type != A_RECORD) {
		data_len &= 255; // TODO this is a incorrect approximation
		return offset + data_len;
	}

	// Parse Data (IPv4 or IPv6)
	if (data_len == sizeof(u32) && type == (A_RECORD)) {
		if (data + sizeof(u32) > data_end)
			return -35;

		ipv4 = bpf_ntohl(*(__u32 *)data);
		DEBUG("A Record: %d.%d.%d.%d", (ipv4 >> 24), (ipv4 >> 16) & 0xFF, (ipv4 >> 8) & 0xFF, ipv4 & 0xFF);

		char *name = map_lookup_elem(&name_heap_map, &zero);
		if (!name)
			return -36;

		if (map_update_elem(&ip_map, &ipv4, name, BPF_ANY) < 0)
			return -37;

		return offset + sizeof(u32);
	}

	return -39;
}

// parse_dns parses a DNS query response, it assumes checks have been made that
// the packet is an IP packet with a UDP datagram using the DNS source port
// (53), it parses from the UDP payload, needing an offset. It returns 0 on
// success, 1 on not-applicable and < 0 on failure.
__attribute__((noinline)) int parse_dns(struct __sk_buff *skb, __u64 offset)
{
	struct dnshdr *dns;
	void *data, *data_end;
	char *data_start;
	int8_t error, ret;
	uint32_t error_idx, *counter;

	offset &= UDP_MAX_SIZE - 1;
	dns = (void *)(long)skb->data + offset;
	// Verify that there's something next to the DNS header.
	if (dns + 1 > (void *)(long)skb->data_end)
		return DNS_PARSER_SKIP;

	// Verify if it's a response and there are answers.
	if ((bpf_ntohs(dns->flags) & BIT(15)) == 0 || dns->ancount == 0)
		return DNS_PARSER_SKIP; // Skip incorrect DNS answers packets.

	// Move to DNS answer section.
	data = (void *)dns + DNS_HDR_SIZE;
	data_end = (void *)(long)skb->data_end;
	if (data >= data_end)
		return DNS_PARSER_SKIP;

	error = 0;

	// "In the DNS, QDCOUNT Is (Usually) One"
	// https://datatracker.ietf.org/doc/rfc9619/
	if (bpf_ntohs(dns->qdcount) != 1) {
		error = -10;
		goto give_up;
	}

	// Parse Question Section
	// Parse QName (domain name)
	data_start = data;
	// writing 'if (ret == 0 ) break;' inside the loop increases the complexity
	ret = 1;
	// Conditions: maximum of 127 labels plus the last zero: 128 iterations. The
	// data should have at least 3 remaning bytes at anytime, one for the
	// length, one for the char for the last zero. Total length will remain
	// under 255 chars.
	for (int i = 0; i < (MAX_NUMBER_LABEL + 1) && data + sizeof(u8) * 3 <= data_end && ret > 0; i++) {
		ret = parse_dns_name_label(skb, (size_t)(data - skb->data), data_start);
		if (ret < 0) {
			error = ret;
			goto give_up;
		}
		// Skip the parsed label
		if (data + ret > data_end) {
			error = -12;
			goto give_up;
		}
		data += ret;
	}
	// Skip the null byte at the end of the name
	data += 1;

#ifdef TETRAGON_BPF_DEBUG
	char *name = map_lookup_elem(&name_heap_map, &zero);
	if (name) {
		DEBUG("domain: %s", name);
	}
#endif

	// Parse QType and QClass
	if (data + sizeof(u16) * 2 > data_end) {
		error = -13;
		goto give_up;
	}
	__u16 qtype = bpf_ntohs(*(__u16 *)data);
	if (qtype != A_RECORD) {
		error = -14;
		goto give_up;
	}
	data += sizeof(u16) * 2;

	// Parse Answer Section
	ret = 1;
	for (int i = 0; i < MAX_DNS_ANSWERS_UDP && data + MIN_ANSWER_LEN <= data_end && ret > 0; i++) {
		ret = parse_dns_answer(skb, (size_t)data - skb->data);
		if (ret < 0) {
			error = ret;
			goto give_up;
		}
		// Skip the parsed answer
		if (data + ret > data_end) {
			error = -15;
			goto give_up;
		}
		data += ret;
	}

	return DNS_PARSER_SUCCESS;

give_up:
	if (error < 0) {
		error_idx = -error;
		counter = map_lookup_elem(&tg_dns_error_map, &error_idx);
		if (counter)
			(*counter)++; // It's a per cpu array
	}
	return error;
}

FUNC_INLINE int parse_dns_from_ip(struct __sk_buff *skb)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct dnshdr *dns;

	// Verify if the frame contains an IP packet.
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return DNS_PARSER_SKIP; // Skip non-IP packets.

	// Parse IP header.
	ip = (struct iphdr *)(long)skb->data;
	// Verify that there's something next to the IP header.
	if (ip + 1 > (void *)(long)skb->data_end)
		return DNS_PARSER_SKIP;

	// Verify if protocol is UDP.
	if (ip->protocol != IPPROTO_UDP)
		return DNS_PARSER_SKIP; // Skip non-UDP packets.

	// Parse UDP header.
	udp = (void *)ip + (ip->ihl * sizeof(u32)); // ihl is in 32 bits words.
	// Verify that there's something next to the UDP header.
	if (udp + 1 > (void *)(long)skb->data_end)
		return DNS_PARSER_SKIP;

	// Verify if that source port (answer) is DNS.
	if (udp->source != bpf_htons(DNS_PORT))
		return DNS_PARSER_SKIP; // Skip non-DNS answers packets.

	// Parse the DNS header.
	dns = (void *)udp + sizeof(struct udphdr);

	return parse_dns(skb, (void *)dns - (void *)ip);
}

#endif // DNS_PARSER_H
