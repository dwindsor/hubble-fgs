// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsparser

// Keep in sync with errors in parsers/dns/dns.h
var Errors = map[int]string{
	0:  "DNS_ERR_SUCCESS",
	1:  "DNS_ERR_ZERO_ELEM_NULL",
	2:  "DNS_ERR_UNEXPECTED_RESPONSE",
	3:  "DNS_ERR_INVALID_QDCOUNT",
	4:  "DNS_ERR_NAME_OVERFLOW",
	5:  "DNS_ERR_PACKET_MALFORMED",
	6:  "DNS_ERR_PARSED_ANSWER_OVERFLOW",
	7:  "DNS_ERR_REQID_UPDATE_FAILED",
	8:  "DNS_ERR_NAME_MISMATCH",
	9:  "DNS_ERR_REQID_DELETE_FAILED",
	10: "DNS_ERR_QTYPE_QCLASS_OVERFLOW",
	11: "DNS_ERR_INVALID_QTYPE",
	// Errors related to parsing labels
	12: "DNS_ERR_LABEL_OFFSET_OVERFLOW",
	13: "DNS_ERR_LABEL_NAME_OVERFLOW",
	14: "DNS_ERR_LABEL_LENGTH_OVERFLOW",
	15: "DNS_ERR_LABEL_COPY_OVERFLOW",
	// Errors related to parsing answers
	16: "DNS_ERR_ANSWER_MAX_OVERFLOW",
	17: "DNS_ERR_ANSWER_OFFSET_OVERFLOW",
	18: "DNS_ERR_ANSWER_COMPRESSED_OVERFLOW",
	19: "DNS_ERR_ANSWER_PARSENAME",
	20: "DNS_ERR_ANSWER_PARSENAME_NAME_OVERFLOW",
	21: "DNS_ERR_ANSWER_TYPE_CLASS_TTL_LEN_OVERFLOW",
	22: "DNS_ERR_ANSWER_IPV4_OVERFLOW",
	23: "DNS_ERR_ANSWER_IPV6_OVERFLOW",
	24: "DNS_ERR_ANSWER_UNREACH",
	// Errors related to assigning the DNS ID mappings
	25: "DNS_ERR_ASSIGN_INVALID_SOURCE",
	26: "DNS_ERR_ASSIGN_FQDNID_UPDATE_FAILED",
	27: "DNS_ERR_ASSIGN_IDFQDN_UPDATE_FAILED",
	28: "DNS_ERR_ASSIGN_INNER_MISSING",
	29: "DNS_ERR_ASSIGN_IPID_UPDATE_FAILED",
	// Errors related to finding the alloc ID
	30: "DNS_ERR_ALLOCID_BIND",
	// Maximum DNS error
	31: "DNS_ERR_MAX",
}
