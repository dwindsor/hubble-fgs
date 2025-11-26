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
#include "dns_pstree.h"
#include "lib/address_family.h"
#include "lib/config.h"
#include "lib/strncmp.h"

volatile __CONST __u8 DNS_PARSER_ENABLED;

// parse_dns_name_label parses a label in a uncompressed DNS name and write it
// into the name heap map. If skip is true, nothing is written in the domain
// name buffer. It returns the offset needed to advance into the data to skip
// the label on success. You need to add one to skip the last zero byte.  The
// length of the label is equal to the returned offset minus one, because of the
// first length byte. On failure, it returns < 0.
__attribute__((noinline)) int
parse_dns_name_label(struct __sk_buff *skb, __u16 off, char *data_start, int skip)
{
	__u8 name_offset, label_length;
	char *data, *data_end, *name;
	uint32_t zero = 0;

	data_end = (void *)(long)skb->data_end;
	if (off > SKB_DATA_MAX_SIZE)
		return -DNS_ERR_LABEL_OFFSET_OVERFLOW;

	data = (void *)(long)skb->data + off;

	// This is the total current length of the name, check that it does not overflow
	if (data - data_start > DNS_MAX_NAME_SIZE)
		return -DNS_ERR_LABEL_NAME_OVERFLOW;

	name_offset = data - data_start;

	if (data + 1 > data_end)
		return -DNS_ERR_LABEL_LENGTH_OVERFLOW;

	// Regular label, read the label length and skip the label
	label_length = *((__u8 *)data) & DNS_MAX_LABEL_SIZE; // Max length is 63
	data += 1; // Move past length byte

	if (!skip) {
		name = map_lookup_elem(&tg_h_dns_name, &zero);
		if (unlikely(!name))
			return -DNS_ERR_ZERO_ELEM_NULL;
	}

	if (name_offset > 0) {
		// Move one byte too much because of label length. On newer kernels, we
		// can directly use name[name_offset - 1] that minimize the number of
		// instructions but it doesn't work on older ones.
		name_offset--;
		if (label_length == 0) {
			if (!skip)
				name[name_offset] = '\0';
			// Remember that caller should add the last zero byte to the offset
			return 0;
		}
		// Adding the dot after the label
		if (!skip)
			name[name_offset++] = '.';
	}

	// Copy one byte at a time
	if (!skip) {
		for (size_t i = 0; i < label_length; ++i) {
			// We can't do the check globally on the pointer because the verifier can't
			// track that data is "similar" to data[i] later on, so that we need to do
			// the check every iteration. It's not optimal to read one byte at a time
			// but it's still better than doing probe_read_kernel.
			if (data + (i + 1) > data_end)
				return -DNS_ERR_LABEL_COPY_OVERFLOW;

			name[name_offset + i] = data[i];
		}
	}

	return label_length + 1;
}

// parse_dns_name is an inlined function looping to read the dns name labels
// called by the parsing of the DNS question and the parsing of the DNS answers
// in the case the packet doesn't use message compression. If skip is true,
// nothing is written in the domain name buffer. It returns the length of the
// parsed name or an error (which includes the bytes specifying the length of
// the different labels and length of the labels themselves but not the NULL
// byte at the end of the full name).
FUNC_INLINE int parse_dns_name(struct __sk_buff *skb, char *data, __u16 offset_start, int skip)
{
	int8_t ret;
	uint16_t init_offset = offset_start;
	char *data_end, *name;
	uint32_t zero = 0;

	data_end = (char *)(long)skb->data_end;
	// Note that data could be recomputed from skb->data + offset but that
	// generates slightly more complexity
	ret = 1;

	// Even though we NULL byte end the string, it will be used as a key so it needs to be cleared
	if (!skip) {
		name = map_lookup_elem(&tg_h_dns_name, &zero);
		if (unlikely(!name))
			return -DNS_ERR_ZERO_ELEM_NULL;

		memset((uint64_t *)name, 0, DNS_MAX_NAME_SIZE + 1);
	}

	// Conditions: maximum of 127 labels plus the last zero: 128 iterations. The
	// data should have at least 3 remaning bytes at anytime, one for the
	// length, one for the char for the last zero. Total length will remain
	// under 255 chars.
	//
	// writing 'if (ret == 0 ) break;' inside the loop increases the complexity
	for (int i = 0; i < (MAX_NUMBER_LABEL + 1) && data + sizeof(u8) * 3 <= data_end && ret > 0; i++) {
		ret = parse_dns_name_label(skb, offset_start, data, skip);
		if (ret < 0)
			return ret;

		offset_start += ret;
	}
	return offset_start - init_offset;
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
FUNC_INLINE int shallow_parse_compression(char **data, char *data_end, uint8_t *offset)
{
	uint8_t first_byte;

	if (*data + sizeof(u8) * 2 > data_end)
		return -DNS_ERR_ANSWER_COMPRESSED_OVERFLOW;

	first_byte = **((char **)data);
	if ((first_byte & COMPRESSED_MSG_MASK) == COMPRESSED_MSG_MASK) {
		// Potential TODO: verify the pointer is correct or give up
		// Skip the pointer bytes
		*offset += sizeof(u8) * 2;
		*data += sizeof(u8) * 2;
		return 1;
	}
	return 0;
}

// parse_dns_answer parses a DNS query answer, it skips any non A-type answer,
// parses the IPv4 given along an A-type answer and writes it into the domain
// name to IP map. It returns the offset needed to advance into the data to skip
// the answer on success and < 0 on failure.
__attribute__((noinline)) int
parse_dns_answer(struct __sk_buff *skb, int16_t off)
{
	__u16 type, data_len;
	int name_len, assign, compressed;
	char *data, *data_end, *name;
	struct ip_addr ip = { 0 };
	uint32_t zero = 0;
	uint8_t offset = 0;

	data_end = (void *)(long)skb->data_end;
	if (off < 0 || off > SKB_DATA_MAX_SIZE)
		return -DNS_ERR_ANSWER_MAX_OVERFLOW;

	data = (void *)(long)skb->data + off;
	if (!data)
		return -DNS_ERR_ANSWER_OFFSET_OVERFLOW;

	compressed = shallow_parse_compression(&data, data_end, &offset);
	if (compressed < 0)
		return compressed;

	if (!compressed) {
		// Need to parse (skip) the name
		name_len = parse_dns_name(skb, data, off, true);
		if (name_len < 0)
			return -DNS_ERR_ANSWER_PARSENAME;

		if (name_len > SKB_DATA_MAX_SIZE)
			return -DNS_ERR_ANSWER_PARSENAME_NAME_OVERFLOW;

		offset = name_len;
		data += offset;

		// Partial compression: compression can be seen again here
		compressed = shallow_parse_compression(&data, data_end, &offset);
		if (compressed < 0)
			return compressed;

		if (!compressed) {
			// Skip the NULL byte at the end of the name
			offset++;
			data++;
		}
	}

	// The answer should contain type, class, TTL and data_len
	if (data + (sizeof(u16) * 2 + sizeof(u32) + sizeof(u16)) > data_end)
		return -DNS_ERR_ANSWER_TYPE_CLASS_TTL_LEN_OVERFLOW;

	type = bpf_ntohs(*(__u16 *)data);
	data_len = bpf_ntohs(*(__u16 *)(data + sizeof(u16) * 2 + sizeof(u32)));
	offset += sizeof(u16) * 2 + sizeof(u32) + sizeof(u16);
	data += sizeof(u16) * 2 + sizeof(u32) + sizeof(u16);

	// Skip non A and AAAA records
	if (type != A_RECORD && type != AAAA_RECORD)
		return offset + data_len;

	name = map_lookup_elem(&tg_h_dns_name, &zero);
	if (unlikely(!name))
		return -DNS_ERR_ZERO_ELEM_NULL;

	if (data_len == sizeof(u32) && type == (A_RECORD)) {
		if (data + sizeof(u32) > data_end)
			return -DNS_ERR_ANSWER_IPV4_OVERFLOW;

		ip.addr[0] = *(__u32 *)data;
		ip.addr[1] = 0;
		ip.af_inet6 = 0;
		DEBUG("A Record: %d.%d.%d.%d", ip.addr[0] & 0xFF, (ip.addr[0] >> 8) & 0xFF, (ip.addr[0] >> 16) & 0xFF, ip.addr[0] >> 24);

		assign = assign_dns_id_mapping(skb, &ip, name);
		if (assign < 0)
			return assign;

		return offset + sizeof(u32);
	} else if (data_len == sizeof(u128) && type == (AAAA_RECORD)) {
		if (data + sizeof(u128) > data_end)
			return -DNS_ERR_ANSWER_IPV6_OVERFLOW;

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

		assign = assign_dns_id_mapping(skb, &ip, name);
		if (assign < 0)
			return assign;

		return offset + sizeof(u128);
	}

	// We should never arrive here
	return -DNS_ERR_ANSWER_UNREACH;
}

// parse_dns parses a DNS query response, it assumes checks have been made that
// the packet is an IP packet with a UDP datagram using the DNS source port
// (53), it parses from the UDP payload, needing an offset. It returns 0 on
// success, 1 on not-applicable and < 0 on failure.
__attribute__((noinline)) int parse_dns(struct __sk_buff *skb, __u64 offset, int send)
{
	struct dnshdr *dns;
	void *data, *data_end;
	char *name, *req_name;
	void *id_found;
	int name_len, max_ancount, ret, error;
	uint16_t qtype;
	uint32_t error_idx, *counter, transaction_id;
	uint32_t zero = 0;

	if (offset > UDP_MAX_SIZE)
		offset = UDP_MAX_SIZE;

	dns = (void *)(long)skb->data + offset;
	// Verify that there's something next to the DNS header.
	if (dns + 1 > (void *)(long)skb->data_end)
		return DNS_PARSER_SKIP;

	// The transaction_id used cannot be just the dns->id because of local
	// requests/responses: on some hosts, all DNS queries go through a local
	// resolver, so when trying to do a request you end up in a situation
	// like the following diagram.
	//
	// +--------------------------------+
	// |  client          local server  |       outside
	// |                                |
	// |      egress      ingress       |
	// |   +---+ -----------> +---+ ----|------> +---+
	// |   |   |              |   |     |        |   |
	// |   +---+ <----------- +---+ <---|------- +---+
	// |      ingress     egress        |
	// +--------------------------------+
	//             localhost
	//
	// From the localhost PoV, you see each requests twice, as egress and
	// ingress, and then the responses twice as egress and ingress. While
	// for request, the parser recording the transaction ID is idempotent,
	// it's not for checking that the ID (because the first response will
	// delete the entry from the map) and thus the parser will identify the
	// following response as an unrequested response, and thus poisoning.
	//
	// Here we use the ingress/egress indicator, and we flip the bit on
	// receiving the response so we can scope the transaction ID to two
	// local sockets.
	transaction_id = ((send & 1U) << 16) | dns->id;

	if (bpf_ntohs(dns->flags) & BIT(15)) { // response
		transaction_id ^= (1U << 16);
		// If there are no answers, skip the malformed response.
		if (dns->ancount == 0)
			return DNS_PARSER_SKIP;

		// Early check for existing ID from requests map.
		id_found = map_lookup_elem(&tg_dns_req_id_map, &transaction_id);
		if (!id_found) {
			// Didn't expect a response with this ID.
			error = -DNS_ERR_UNEXPECTED_RESPONSE;
			goto done;
		}
	}

	// Move to DNS answer section.
	data = (void *)dns + sizeof(struct dnshdr);
	data_end = (void *)(long)skb->data_end;
	if (data >= data_end)
		return DNS_PARSER_SKIP;

	error = DNS_PARSER_SUCCESS;

	// "In the DNS, QDCOUNT Is (Usually) One"
	// https://datatracker.ietf.org/doc/rfc9619/
	if (bpf_ntohs(dns->qdcount) != 1) {
		error = -DNS_ERR_INVALID_QDCOUNT;
		goto done;
	}

	// Parse Question Section
	name_len = parse_dns_name(skb, data, (size_t)(data - skb->data), false);
	if (name_len < 0) {
		error = name_len;
		goto done;
	}
	// Skip the NULL byte at the end
	name_len++;

	if (name_len > SKB_DATA_MAX_SIZE) {
		error = -DNS_ERR_NAME_OVERFLOW;
		goto done;
	}
	data += name_len;

	// Parse QType and QClass
	if (data + sizeof(u16) * 2 > data_end) {
		error = -DNS_ERR_QTYPE_QCLASS_OVERFLOW;
		goto done;
	}
	qtype = bpf_ntohs(*(uint16_t *)data);
	// Skip non A or AAAA query types (also in standard query responses)
	if (qtype != A_RECORD && qtype != AAAA_RECORD)
		return DNS_PARSER_SKIP;

	data += sizeof(u16) * 2;

	// Record the request ID or verify the response domain is correct with the ID.
	name = map_lookup_elem(&tg_h_dns_name, &zero);
	if (unlikely(!name)) {
		error = -DNS_ERR_ZERO_ELEM_NULL;
		goto done;
	}

	if (!(bpf_ntohs(dns->flags) & BIT(15))) { // request
		if (map_update_elem(&tg_dns_req_id_map, &transaction_id, name, BPF_ANY))
			error = -DNS_ERR_REQID_UPDATE_FAILED;
		// End of the request parsing.
		goto done;
	}

	// Rest of the execution is for parsing responses content.
	req_name = map_lookup_elem(&tg_dns_req_id_map, &transaction_id);
	// This should never happen as it was already checked before parsing the
	// questions.
	if (unlikely(!req_name)) {
		error = -DNS_ERR_UNEXPECTED_RESPONSE;
		goto done;
	}

	if (strncmp_truncated(req_name, DNS_MAX_NAME_SIZE, name)) {
		error = -DNS_ERR_NAME_MISMATCH;
		goto done;
	}

	if (map_delete_elem(&tg_dns_req_id_map, &transaction_id)) {
		error = -DNS_ERR_REQID_DELETE_FAILED;
		goto done;
	}

	// Parse Answer Section
	max_ancount = bpf_ntohs(dns->ancount) > MAX_DNS_ANSWERS_UDP ? MAX_DNS_ANSWERS_UDP : bpf_ntohs(dns->ancount);
	ret = 1;
	for (int i = 0; i < max_ancount && data + MIN_ANSWER_LEN <= data_end && ret > 0; i++) {
		ret = parse_dns_answer(skb, (size_t)data - skb->data);
		if (ret < 0) {
			error = ret;
			goto done;
		}
		// Skip the parsed answer
		if (data + ret > data_end) {
			error = -DNS_ERR_PARSED_ANSWER_OVERFLOW;
			goto done;
		}
		data += ret;
	}

done:
	if (error <= 0) {
		error_idx = -error;

		if (error_idx >= DNS_ERR_MAX) {
			errmetrics(EINVAL);
			return -DNS_ERR_MAX;
		}

		counter = map_lookup_elem(&tg_dns_error_map, &error_idx);
		if (counter)
			(*counter)++; // It's a per cpu array
	}
	return error;
}

#endif // DNS_PARSER_H
