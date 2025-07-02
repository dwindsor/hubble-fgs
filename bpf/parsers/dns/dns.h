// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef DNS_H
#define DNS_H

#include "vmlinux.h"
#include "bpf_task.h"

#define DNS_PORT    53
#define A_RECORD    1
#define AAAA_RECORD 28

#define DNS_MAX_NAME_SIZE  255
#define DNS_MAX_LABEL_SIZE 63

// RFC1035 defines the size limit of the UDP packet to be 512
// https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
//
// However EDNS(0) specified in RFC6891 increases the maximum possible size.
// For now let's use 1232 for the EDNS buffer size since it's the maximum size
// it will avoid fragmentation on most networks. See https://www.dnsflagday.net/2020/.
#define UDP_MAX_SIZE 1232

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
// UDP_MAX_SIZE(1232) - (20 + 7) = 1205
// 1205 / 16 = 75,3125
#define MAX_DNS_ANSWERS_UDP 75

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

struct ip_addr {
	uint64_t addr[2];
	uint8_t af_inet6;
	uint8_t pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	// we can't tell the verifier that (name_offset + label_length < 255) so we need 63 extra bytes.
	__type(value, char[DNS_MAX_NAME_SIZE + DNS_MAX_LABEL_SIZE]);
} tg_h_dns_name SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_ERROR_CODE);
	__type(key, __u32);
	__type(value, __u32);
} tg_dns_error_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // This will be resized by userspace
	__type(key, __u32);
	__type(value, char[DNS_MAX_NAME_SIZE + 1]);
} tg_dns_req_id_map SEC(".maps");

#endif // DNS_H
