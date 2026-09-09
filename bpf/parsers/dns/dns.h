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
#include "lib/fgs_debug.h"

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

// The offsets added to a packet pointer in parse_dns_answer() and parse_dns()
// are masked so the verifier keeps their range under +alu32. Both masks must
// stay wider than any value that reaches them, so they never change an offset.
#define DNS_ANSWER_OFF_MASK 0x7ff
_Static_assert(SKB_DATA_MAX_SIZE <= DNS_ANSWER_OFF_MASK,
	       "DNS_ANSWER_OFF_MASK would truncate a valid answer offset");

// parse_dns_answer() returns at most offset (uint8_t) + data_len (__u16).
#define DNS_ANSWER_LEN_MASK 0x1ffff
_Static_assert(0xff + 0xffff <= DNS_ANSWER_LEN_MASK,
	       "DNS_ANSWER_LEN_MASK would truncate a valid answer length");

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

// Errors related to DNS parsing
//
// IMPORTANT: Keep in sync with pkg/dnsparser/errors.go:Errors
#define DNS_ERR_SUCCESS		       0
#define DNS_ERR_ZERO_ELEM_NULL	       1
#define DNS_ERR_UNEXPECTED_RESPONSE    2
#define DNS_ERR_INVALID_QDCOUNT	       3
#define DNS_ERR_NAME_OVERFLOW	       4
#define DNS_ERR_PACKET_MALFORMED       5
#define DNS_ERR_PARSED_ANSWER_OVERFLOW 6
#define DNS_ERR_REQID_UPDATE_FAILED    7
#define DNS_ERR_NAME_MISMATCH	       8
#define DNS_ERR_REQID_DELETE_FAILED    9
#define DNS_ERR_QTYPE_QCLASS_OVERFLOW  10
// Unused for now as we ignore non A and AAAA QType
#define DNS_ERR_INVALID_QTYPE 11
// Errors related to parsing labels
#define DNS_ERR_LABEL_OFFSET_OVERFLOW 12
#define DNS_ERR_LABEL_NAME_OVERFLOW   13
#define DNS_ERR_LABEL_LENGTH_OVERFLOW 14
#define DNS_ERR_LABEL_COPY_OVERFLOW   15
// Errors related to parsing answers
#define DNS_ERR_ANSWER_MAX_OVERFLOW		   16
#define DNS_ERR_ANSWER_OFFSET_OVERFLOW		   17
#define DNS_ERR_ANSWER_COMPRESSED_OVERFLOW	   18
#define DNS_ERR_ANSWER_PARSENAME		   19
#define DNS_ERR_ANSWER_PARSENAME_NAME_OVERFLOW	   20
#define DNS_ERR_ANSWER_TYPE_CLASS_TTL_LEN_OVERFLOW 21
#define DNS_ERR_ANSWER_IPV4_OVERFLOW		   22
#define DNS_ERR_ANSWER_IPV6_OVERFLOW		   23
#define DNS_ERR_ANSWER_UNREACH			   24
// Errors related to assigning the DNS ID mappings
#define DNS_ERR_ASSIGN_INVALID_SOURCE	    25
#define DNS_ERR_ASSIGN_FQDNID_UPDATE_FAILED 26
#define DNS_ERR_ASSIGN_IDFQDN_UPDATE_FAILED 27
#define DNS_ERR_ASSIGN_INNER_MISSING	    28
#define DNS_ERR_ASSIGN_IPID_UPDATE_FAILED   29
// Errors related to finding the alloc ID
#define DNS_ERR_ALLOCID_BIND 30
// Maximum DNS error
#define DNS_ERR_MAX 31

#define DNS_PARSER_SKIP	   1
#define DNS_PARSER_SUCCESS 0

#define DEBUG_DNS(__fmt, ...) FGS_DEBUG_AREA(BPF_AREA_DNS, __fmt, ##__VA_ARGS__)

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
	__uint(max_entries, DNS_ERR_MAX);
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
