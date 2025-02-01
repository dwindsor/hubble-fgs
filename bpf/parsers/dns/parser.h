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

#include "dns.h"
#include "pstree.h"
#include "lib/address_family.h"
#include "lib/config.h"

uint32_t zero = 0;

FUNC_INLINE bool bpf_dns_parser_enabled()
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
	if (data - data_start > DNS_MAX_NAME_SIZE)
		return -21;

	name_offset = data - data_start;

	if (data + 1 > data_end)
		return -22;

	// Regular label, read the label length and skip the label
	label_length = *((__u8 *)data) & DNS_MAX_LABEL_SIZE; // Max length is 63
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

// parse_dns_name is an inlined function looping to read the dns name labels
// called by the parsing of the DNS question and the parsing of the DNS answers
// in the case the packet doesn't use message compression. It returns the length
// of the parsed name or an error.
FUNC_INLINE int parse_dns_name(struct __sk_buff *skb, char *data, __u16 offset_start)
{
	int8_t ret;
	uint16_t init_offset = offset_start;
	char *data_end;

	data_end = (char *)(long)skb->data_end;
	// Note that data could be recomputed from skb->data + offset but that
	// generates slightly more complexity
	ret = 1;

	// Even though we NULL byte end the string, it will be used as a key so it needs to be cleared
	char *name = map_lookup_elem(&name_heap_map, &zero);
	if (!name)
		return -25;
	memset((uint64_t *)name, 0, DNS_MAX_NAME_SIZE + 1);

	// Conditions: maximum of 127 labels plus the last zero: 128 iterations. The
	// data should have at least 3 remaning bytes at anytime, one for the
	// length, one for the char for the last zero. Total length will remain
	// under 255 chars.
	//
	// writing 'if (ret == 0 ) break;' inside the loop increases the complexity
	for (int i = 0; i < (MAX_NUMBER_LABEL + 1) && data + sizeof(u8) * 3 <= data_end && ret > 0; i++) {
		ret = parse_dns_name_label(skb, offset_start, data);
		if (ret < 0) {
			return ret;
		}
		offset_start += ret;
	}
	// Skip the null byte at the end of the name
	return offset_start + 1 - init_offset;
}

// parse_dns_answer parses a DNS query answer, it skips any non A-type answer,
// parses the IPv4 given along an A-type answer and writes it into the domain
// name to IP map. It returns the offset needed to advance into the data to skip
// the answer on success and < 0 on failure.
__attribute__((noinline)) int8_t
parse_dns_answer(struct __sk_buff *skb, int16_t off)
{
	__u8 first_byte, offset;
	__u16 type, data_len;
	int name_len;
	struct ip_addr ip = { 0 };
	char *data, *data_end, *name;

	data_end = (void *)(long)skb->data_end;
	if (off < 0 || off > SKB_DATA_MAX_SIZE) {
		return -28;
	}
	data = (void *)(long)skb->data + off;

	if (!data) {
		return -29;
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
		return -30;

	first_byte = *((__u8 *)data);
	if ((first_byte & COMPRESSED_MSG_MASK) == COMPRESSED_MSG_MASK) {
		// Potential TODO: verify the pointer is correct or give up
		// Skip the pointer byte
		offset = sizeof(u8) * 2;
		data += offset;
	} else {
		// Might be not using message compression
		name_len = parse_dns_name(skb, data, off);
		if (name_len < 0)
			return -31;

		if (name_len > SKB_DATA_MAX_SIZE)
			return -32;

		offset = name_len;
		data += offset;
	}

	// The answer should contain type, class, TTL and data_len
	if (data + (sizeof(u16) * 2 + sizeof(u32) + sizeof(u16)) > data_end)
		return -33;

	type = bpf_ntohs(*(__u16 *)data);
	data_len = bpf_ntohs(*(__u16 *)(data + sizeof(u16) * 2 + sizeof(u32)));
	offset += sizeof(u16) * 2 + sizeof(u32) + sizeof(u16);
	data += sizeof(u16) * 2 + sizeof(u32) + sizeof(u16);

	// Skip non A and AAAA records
	if (type != A_RECORD && type != AAAA_RECORD) {
		data_len &= 255; // TODO this is a incorrect approximation
		return offset + data_len;
	}

	name = map_lookup_elem(&name_heap_map, &zero);
	if (!name)
		return -34;

	if (data_len == sizeof(u32) && type == (A_RECORD)) {
		if (data + sizeof(u32) > data_end)
			return -35;

		ip.addr[0] = *(__u32 *)data;
		ip.addr[1] = 0;
		ip.af_inet6 = 0;
		DEBUG("A Record: %d.%d.%d.%d", ip.addr[0] & 0xFF, (ip.addr[0] >> 8) & 0xFF, (ip.addr[0] >> 16) & 0xFF, ip.addr[0] >> 24);

		if (map_update_elem(&tg_dns_ip_map, &ip, name, BPF_ANY) < 0)
			return -36;

		assign_dns_id_mapping((struct endpoint_id_key *)&ip, name);

		return offset + sizeof(u32);
	} else if (data_len == sizeof(u128) && type == (AAAA_RECORD)) {
		if (data + sizeof(u128) > data_end)
			return -37;

		ip.addr[0] = *(__u64 *)data;
		ip.addr[1] = *(__u64 *)(data + sizeof(u64));
		ip.af_inet6 = 1;
#ifdef TETRAGON_BPF_DEBUG
		__u16 *addr = (__u16 *)ip.addr;
		DEBUG("AAAA Record: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		      bpf_htons(addr[0]),
		      bpf_htons(addr[1]),
		      bpf_htons(addr[2]),
		      bpf_htons(addr[3]),
		      bpf_htons(addr[4]),
		      bpf_htons(addr[5]),
		      bpf_htons(addr[6]),
		      bpf_htons(addr[7]));
#endif

		if (map_update_elem(&tg_dns_ip_map, &ip, name, BPF_ANY) < 0)
			return -38;

		return offset + sizeof(u128);
	}

	// We should never arrive here
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
	int name_len;
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

	error = DNS_PARSER_SUCCESS;

	// "In the DNS, QDCOUNT Is (Usually) One"
	// https://datatracker.ietf.org/doc/rfc9619/
	if (bpf_ntohs(dns->qdcount) != 1) {
		error = -10;
		goto give_up;
	}

	// Parse Question Section
	name_len = parse_dns_name(skb, data, (size_t)(data - skb->data));
	if (name_len < 0) {
		error = name_len;
		goto give_up;
	}

	if (name_len > SKB_DATA_MAX_SIZE) {
		error = -11;
		goto give_up;
	}
	data += name_len;

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
	if (qtype != A_RECORD && qtype != AAAA_RECORD) {
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

	// For testing purposes, we want to know how many time the parser succeeded,
	// so we use error = 0 as success, we might remove this and just return.
	// return DNS_PARSER_SUCCESS;

give_up:
	if (error <= 0) {
		error_idx = -error;
		counter = map_lookup_elem(&tg_dns_error_map, &error_idx);
		if (counter)
			(*counter)++; // It's a per cpu array
	}
	return error;
}

#endif // DNS_PARSER_H
