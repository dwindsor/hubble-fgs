#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

from helper.policy_generator import create_rule, create_multi_cidr_rule
from helper.packet_builder import build_packet
from helper.policy_models import VRF_NAME_TO_ID


def get_port_proto_test_params():
    return [
        (
            "l3-dst-single-tcp",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.2.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("TCP", 443)],
                )
            ],
        ),
        (
            "l3-dst-single-udp",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.3.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("UDP", 53)],
                )
            ],
        ),
        (
            "l3-dst-single-icmp",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.4.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("ICMP", None)],
                )
            ],
        ),
        (
            "l3-dst-single-tu",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.5.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("TCP", 80), ("UDP", 80)],
                )
            ],
        ),
        (
            "l3-dst-single-ti",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.6.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("TCP", 22), ("ICMP", None)],
                )
            ],
        ),
        (
            "l3-dst-range-tcp",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.10.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("TCP", 5000, 5010)],
                )
            ],
        ),
        (
            "l3-dst-range-tu-diff",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.13.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("TCP", 5000, 5010), ("UDP", 6000, 6010)],
                )
            ],
        ),
        (
            "l3-dst-range-any",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.16.0/24",
                    source_vrf="default",
                    dest_proto_ports=[
                        ("TCP", 10000, 10010),
                        ("UDP", 10000, 10010),
                        ("ICMP", None),
                    ],
                )
            ],
        ),
        (
            "l3-dst-mix",
            [
                create_rule(
                    "10.0.1.0/24",
                    "10.0.17.0/24",
                    source_vrf="default",
                    dest_proto_ports=[("TCP", 443), ("UDP", 5000, 5010)],
                )
            ],
        ),
    ]


def get_port_range_packet_test_params():
    port_min, port_max = 5000, 5010
    rules = [
        create_rule(
            source_cidr="0.0.0.0/0",
            dest_cidr="0.0.0.0/0",
            dest_proto_ports=[
                ("TCP", port_min, port_max),
                ("UDP", port_min, port_max),
                ("ICMP", None),
            ],
        )
    ]
    return [
        (5005, True, rules, build_packet().tcp(dport=5005)),
        (5011, False, rules, build_packet().tcp(dport=5011)),
        (4999, False, rules, build_packet().tcp(dport=4999)),
    ]


def get_protocol_packet_test_params():
    test_port = 8080
    rules = [
        create_rule(
            source_cidr="0.0.0.0/0",
            dest_cidr="0.0.0.0/0",
            dest_proto_ports=[("TCP", None)],
        )
    ]
    return [
        ("TCP", True, rules, build_packet().tcp(dport=test_port)),
        ("UDP", False, rules, build_packet().udp(dport=test_port)),
    ]


CIDR_CONFIGS = [
    {
        "cidr": "10.0.0.0/8",
        "before": "9.255.255.255",
        "inside": "10.128.0.1",
        "after": "11.0.0.1",
    },
    {
        "cidr": "192.168.0.0/16",
        "before": "192.167.255.255",
        "inside": "192.168.128.1",
        "after": "192.169.0.1",
    },
    {
        "cidr": "172.16.5.0/24",
        "before": "172.16.4.255",
        "inside": "172.16.5.128",
        "after": "172.16.6.1",
    },
]


def get_cidr_source_packet_test_params():
    """Test parameters for source CIDR mask enforcement."""
    params = []
    for config in CIDR_CONFIGS:
        cidr = config["cidr"]
        rules = [
            create_rule(
                source_cidr=cidr,
                dest_cidr="0.0.0.0/0",
                dest_proto_ports=[("TCP", None), ("UDP", None), ("ICMP", None)],
            )
        ]
        packets = [
            (config["before"], build_packet().tcp(src_ip=config["before"])),
            (config["inside"], build_packet().tcp(src_ip=config["inside"])),
            (config["after"], build_packet().tcp(src_ip=config["after"])),
        ]
        params.append((cidr, rules, packets))
    return params


def get_cidr_dest_packet_test_params():
    """Test parameters for destination CIDR mask enforcement."""
    params = []
    for config in CIDR_CONFIGS:
        cidr = config["cidr"]
        rules = [
            create_rule(
                source_cidr="0.0.0.0/0",
                dest_cidr=cidr,
                dest_proto_ports=[("TCP", None), ("UDP", None), ("ICMP", None)],
            )
        ]
        packets = [
            (config["before"], build_packet().tcp(dst_ip=config["before"])),
            (config["inside"], build_packet().tcp(dst_ip=config["inside"])),
            (config["after"], build_packet().tcp(dst_ip=config["after"])),
        ]
        params.append((cidr, rules, packets))
    return params


def get_cidr_combined_packet_test_params():
    """Test parameters for combined source AND destination CIDR enforcement.

    Tests that BOTH source and destination must match for traffic to be allowed.
    Uses first two CIDRs from CIDR_CONFIGS for source and destination.

    Test cases:
    - Source allowed, destination blocked → expect blocked
    - Source blocked, destination allowed → expect blocked
    - Both allowed → expect allowed
    """
    src_cidr = CIDR_CONFIGS[0]  # 10.0.0.0/8
    dest_cidr = CIDR_CONFIGS[1]  # 192.168.0.0/16

    rules = [
        create_rule(
            source_cidr=src_cidr["cidr"],
            dest_cidr=dest_cidr["cidr"],
            dest_proto_ports=[("TCP", None), ("UDP", None), ("ICMP", None)],
        )
    ]

    packets = [
        (
            "src_allowed_dest_blocked",
            build_packet().tcp(src_ip=src_cidr["inside"], dst_ip=dest_cidr["before"]),
            False,
        ),
        (
            "src_blocked_dest_allowed",
            build_packet().tcp(src_ip=src_cidr["before"], dst_ip=dest_cidr["inside"]),
            False,
        ),
        (
            "both_allowed",
            build_packet().tcp(src_ip=src_cidr["inside"], dst_ip=dest_cidr["inside"]),
            True,
        ),
    ]

    return [(f"{src_cidr['cidr']}+{dest_cidr['cidr']}", rules, packets)]


def get_initial_incremental_policy():
    """Return initial incremental policy: 2 rules (TCP 80, TCP 443)."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 443)],
            description="Rule2: Allow TCP port 443",
        ),
    ]


def get_incremental_policy_3rules():
    """Return incremental policy with 3 rules (adds TCP 8080)."""
    return get_initial_incremental_policy() + [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8080)],
            description="Rule3: Allow TCP port 8080",
        ),
    ]


def get_incremental_policy_5rules():
    """Return incremental policy with 5 rules (adds UDP 53, TCP 22)."""
    return get_incremental_policy_3rules() + [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Rule4: Allow UDP port 53 (DNS)",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Rule5: Allow TCP port 22 (SSH)",
        ),
    ]


def get_two_policies_single_rule():
    """Return two different policies with 1 rule each.

    Returns:
        tuple: (policy1_name, policy1_rules, policy2_name, policy2_rules)
    """
    policy1_rules = [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Policy1: Allow TCP port 80",
        ),
    ]
    policy2_rules = [
        create_rule(
            "172.16.0.0/16",
            "172.17.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Policy2: Allow UDP port 53",
        ),
    ]
    return ("policy1-single-rule", policy1_rules, "policy2-single-rule", policy2_rules)


def get_policy_5rules_initial():
    """Return initial policy with 5 rules for update testing."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 443)],
            description="Rule2: Allow TCP port 443",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8080)],
            description="Rule3: Allow TCP port 8080",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Rule4: Allow UDP port 53",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Rule5: Allow TCP port 22",
        ),
    ]


def get_policy_5rules_updated_rule2():
    """Return policy with 5 rules where rule2 is updated (port 443 -> 8443)."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8443)],
            description="Rule2: Allow TCP port 8443 (updated)",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8080)],
            description="Rule3: Allow TCP port 8080",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Rule4: Allow UDP port 53",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Rule5: Allow TCP port 22",
        ),
    ]


def get_policy_5rules_updated_rule4_rule5():
    """Return policy with 5 rules where rule4 and rule5 are updated."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8443)],
            description="Rule2: Allow TCP port 8443 (updated)",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8080)],
            description="Rule3: Allow TCP port 8080",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 5353)],
            description="Rule4: Allow UDP port 5353 (updated)",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 2222)],
            description="Rule5: Allow TCP port 2222 (updated)",
        ),
    ]


def get_two_policies_for_update():
    """Return two policies for update testing.

    Returns:
        tuple: (policy1_name, policy1_rules_initial, policy1_rules_updated,
                policy2_name, policy2_rules_initial, policy2_rules_updated)
    """
    policy1_initial = [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Policy1: Allow TCP port 80",
        ),
    ]
    policy1_updated = [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8080)],
            description="Policy1: Allow TCP port 8080 (updated)",
        ),
    ]
    policy2_initial = [
        create_rule(
            "172.16.0.0/16",
            "172.17.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Policy2: Allow UDP port 53",
        ),
    ]
    policy2_updated = [
        create_rule(
            "172.16.0.0/16",
            "172.17.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 5353)],
            description="Policy2: Allow UDP port 5353 (updated)",
        ),
    ]
    return (
        "policy1-update-test",
        policy1_initial,
        policy1_updated,
        "policy2-update-test",
        policy2_initial,
        policy2_updated,
    )


def get_policy_5rules_for_removal():
    """Return initial policy with 5 rules for removal testing."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 443)],
            description="Rule2: Allow TCP port 443",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 8080)],
            description="Rule3: Allow TCP port 8080",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Rule4: Allow UDP port 53",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Rule5: Allow TCP port 22",
        ),
    ]


def get_policy_5rules_without_rule3():
    """Return policy with 4 rules (rule3 removed)."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 443)],
            description="Rule2: Allow TCP port 443",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Rule4: Allow UDP port 53",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Rule5: Allow TCP port 22",
        ),
    ]


def get_policy_5rules_without_rule2_3_4():
    """Return policy with 2 rules (rule2, rule3, rule4 removed)."""
    return [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Rule1: Allow TCP port 80",
        ),
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Rule5: Allow TCP port 22",
        ),
    ]


def get_two_policies_for_removal():
    """Return two policies for removal testing.

    Returns:
        tuple: (policy1_name, policy1_rules, policy2_name, policy2_rules)
    """
    policy1_rules = [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Policy1: Allow TCP port 80",
        ),
    ]
    policy2_rules = [
        create_rule(
            "172.16.0.0/16",
            "172.17.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Policy2: Allow UDP port 53",
        ),
    ]
    return (
        "policy1-removal-test",
        policy1_rules,
        "policy2-removal-test",
        policy2_rules,
    )


def get_three_policies_for_clear():
    """Return three policies for clear testing.

    Returns:
        tuple: (policy1_name, policy1_rules, policy2_name, policy2_rules, policy3_name, policy3_rules)
    """
    policy1_rules = [
        create_rule(
            "10.1.0.0/16",
            "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
            description="Policy1: Allow TCP port 80",
        ),
    ]
    policy2_rules = [
        create_rule(
            "172.16.0.0/16",
            "172.17.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
            description="Policy2: Allow UDP port 53",
        ),
    ]
    policy3_rules = [
        create_rule(
            "192.168.0.0/16",
            "192.168.1.0/24",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
            description="Policy3: Allow TCP port 22",
        ),
    ]
    return (
        "policy1-clear-test",
        policy1_rules,
        "policy2-clear-test",
        policy2_rules,
        "policy3-clear-test",
        policy3_rules,
    )


def get_multi_cidr_policy_params():
    """Return parameters for multi-CIDR policy with port ranges.

    This policy contains:
    - 3 source CIDRs (some with VRF)
    - 3 destination CIDRs
    - 11 protoPorts (TCP and UDP with port ranges)

    Returns:
        tuple: (policy_name, rules, expected_rule_count)
    """
    source_ip_blocks = [
        {"cidr": "10.23.48.24/29"},
        {"cidr": "10.23.48.32/27"},
        {"cidr": "10.23.48.64/26", "vrf": "tims"},
    ]
    dest_ip_blocks = [
        {"cidr": "139.71.242.21/32"},
        {"cidr": "139.71.248.83/32"},
        {"cidr": "141.251.9.128/25"},
    ]
    dest_proto_ports = [
        ("TCP", 1344),
        ("TCP", 16016),
        ("TCP", 24345, 24347),
        ("TCP", 4445),
        ("TCP", 446),
        ("TCP", 9090, 9091),
        ("TCP", 9500),
        ("UDP", 123),
        ("UDP", 24345, 24347),
        ("UDP", 3269),
        ("UDP", 53),
    ]

    rules = [
        create_multi_cidr_rule(
            source_ip_blocks=source_ip_blocks,
            dest_ip_blocks=dest_ip_blocks,
            dest_proto_ports=dest_proto_ports,
            description="Converted from Aruba rule: AXP-SVCS-EX-OUT",
        )
    ]

    expected_rules = 9  # 3 source CIDRs × 3 dest CIDRs

    return ("multi-cidr-policy", rules, expected_rules)


def get_dual_policy_multi_cidr_params():
    """Return parameters for dual policies with multi-CIDR rules.

    Each policy contains:
    - 2 source CIDRs (one with VRF)
    - 2 destination CIDRs
    - 2 rules with different proto-ports (TCP single port, TCP port range, UDP single port, UDP port range)

    Returns:
        tuple: (policy1_name, policy1_rules, policy1_expected_count,
                policy2_name, policy2_rules, policy2_expected_count)
    """
    policy1_source_ip_blocks = [
        {"cidr": "10.1.0.0/24"},
        {"cidr": "10.2.0.0/24", "vrf": "tims"},
    ]
    policy1_dest_ip_blocks = [
        {"cidr": "192.168.1.0/24"},
        {"cidr": "192.168.2.0/24"},
    ]

    policy1_rules = [
        create_multi_cidr_rule(
            source_ip_blocks=policy1_source_ip_blocks,
            dest_ip_blocks=policy1_dest_ip_blocks,
            dest_proto_ports=[
                ("TCP", 443),
                ("TCP", 8000, 8080),
                ("UDP", 53),
                ("UDP", 10000, 10010),
            ],
            description="Rule 1",
        ),
        create_multi_cidr_rule(
            source_ip_blocks=policy1_source_ip_blocks,
            dest_ip_blocks=policy1_dest_ip_blocks,
            dest_proto_ports=[
                ("TCP", 80),
                ("TCP", 9000, 9080),
                ("UDP", 123),
                ("UDP", 20000, 20010),
            ],
            description="Rule 2",
        ),
    ]
    policy1_expected_rules = 8

    policy2_source_ip_blocks = [
        {"cidr": "10.3.0.0/24"},
        {"cidr": "10.4.0.0/24", "vrf": "tims"},
    ]
    policy2_dest_ip_blocks = [
        {"cidr": "172.16.1.0/24"},
        {"cidr": "172.16.2.0/24"},
    ]

    policy2_rules = [
        create_multi_cidr_rule(
            source_ip_blocks=policy2_source_ip_blocks,
            dest_ip_blocks=policy2_dest_ip_blocks,
            dest_proto_ports=[
                ("TCP", 443),
                ("TCP", 8000, 8080),
                ("UDP", 53),
                ("UDP", 10000, 10010),
            ],
            description="Rule 1",
        ),
        create_multi_cidr_rule(
            source_ip_blocks=policy2_source_ip_blocks,
            dest_ip_blocks=policy2_dest_ip_blocks,
            dest_proto_ports=[
                ("TCP", 80),
                ("TCP", 9000, 9080),
                ("UDP", 123),
                ("UDP", 20000, 20010),
            ],
            description="Rule 2",
        ),
    ]
    policy2_expected_rules = 8

    return (
        "multi-cidr-policy-1",
        policy1_rules,
        policy1_expected_rules,
        "multi-cidr-policy-2",
        policy2_rules,
        policy2_expected_rules,
    )


def get_vrf_policy_params():
    vrf_name = "tims"
    vrf_id = VRF_NAME_TO_ID[vrf_name]

    policy1_rules = [
        create_rule(
            "10.1.0.0/24",
            "192.168.1.0/24",
            source_vrf=vrf_name,
            dest_vrf=vrf_name,
            dest_proto_ports=[("TCP", 80)],
            description="Rule 1",
        )
    ]

    pkt = build_packet().tcp(
        src_ip="10.1.0.1",
        dst_ip="192.168.1.1",
        sport=80,
        dport=80,
        ip_version=4,
        vrf=vrf_id,
    )
    return [("vrf-policy", policy1_rules, pkt, vrf_id)]
