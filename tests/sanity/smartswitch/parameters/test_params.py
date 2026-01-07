#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

from helper.policy_generator import create_rule
from helper.packet_builder import build_packet


def get_port_proto_test_params():
    return [
        ("l3-dst-single-tcp", [
            create_rule("10.0.1.0/24", "10.0.2.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 443)])
        ]),
        ("l3-dst-single-udp", [
            create_rule("10.0.1.0/24", "10.0.3.0/24", source_vrf="default",
                       dest_proto_ports=[("UDP", 53)])
        ]),
        ("l3-dst-single-icmp", [
            create_rule("10.0.1.0/24", "10.0.4.0/24", source_vrf="default",
                       dest_proto_ports=[("ICMP", None)])
        ]),
        ("l3-dst-single-tu", [
            create_rule("10.0.1.0/24", "10.0.5.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 80), ("UDP", 80)])
        ]),
        ("l3-dst-single-ti", [
            create_rule("10.0.1.0/24", "10.0.6.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 22), ("ICMP", None)])
        ]),
        ("l3-dst-range-tcp", [
            create_rule("10.0.1.0/24", "10.0.10.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 5000, 5010)])
        ]),
        ("l3-dst-range-tu-diff", [
            create_rule("10.0.1.0/24", "10.0.13.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 5000, 5010), ("UDP", 6000, 6010)])
        ]),
        ("l3-dst-range-any", [
            create_rule("10.0.1.0/24", "10.0.16.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 10000, 10010), ("UDP", 10000, 10010), ("ICMP", None)])
        ]),
        ("l3-dst-mix", [
            create_rule("10.0.1.0/24", "10.0.17.0/24", source_vrf="default",
                       dest_proto_ports=[("TCP", 443), ("UDP", 5000, 5010)])
        ]),
    ]


def get_port_range_packet_test_params():
    port_min, port_max = 5000, 5010
    rules = [create_rule(
        source_cidr="0.0.0.0/0",
        dest_cidr="0.0.0.0/0",
        dest_proto_ports=[("TCP", port_min, port_max), ("UDP", port_min, port_max), ("ICMP", port_min, port_max)]
    )]
    return [
        (5005, True, rules, build_packet().tcp(dport=5005)),
        (5011, False, rules, build_packet().tcp(dport=5011)),
        (4999, False, rules, build_packet().tcp(dport=4999)),
    ]


def get_protocol_packet_test_params():
    test_port = 8080
    rules = [create_rule(
        source_cidr="0.0.0.0/0",
        dest_cidr="0.0.0.0/0",
        dest_proto_ports=[("TCP", None)]
    )]
    return [
        ("TCP", True, rules, build_packet().tcp(dport=test_port)),
        ("UDP", False, rules, build_packet().udp(dport=test_port)),
    ]
