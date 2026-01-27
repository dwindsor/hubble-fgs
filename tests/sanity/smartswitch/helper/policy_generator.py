#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import logging
import os
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple
import yaml

from .policy_models import (
    Policy, PolicyRule, IpBlock, ProtoPort, NetworkEndpoint
)

logger = logging.getLogger(__name__)


def _write_policy_to_file(policy: Policy, output_path: Path) -> None:
    def represent_none(dumper, _):
        return dumper.represent_scalar('tag:yaml.org,2002:null', '')
    
    yaml.add_representer(type(None), represent_none)
    
    with open(output_path, 'w') as f:
        yaml.dump(policy.to_dict(), f, default_flow_style=False, sort_keys=False, indent=2)
    
    logger.info(f"✅ Generated: {output_path.name}")
    logger.info(f"Policy YAML ({output_path.name}):\n{policy.to_yaml()}")


def generate_policy_for_test(
    name: str,
    rules: List[PolicyRule],
    namespace: str = "hypershield"
) -> Tuple[Policy, Path]:
    policy = Policy(name=name, namespace=namespace, rules=rules)
    fd, temp_path = tempfile.mkstemp(suffix=".yaml", prefix=f"{name}_")
    os.close(fd)
    output_path = Path(temp_path)
    _write_policy_to_file(policy, output_path)
    return policy, output_path


def _parse_proto_port(item) -> ProtoPort:
    if len(item) == 2:
        return ProtoPort(protocol=item[0], port=item[1])
    elif len(item) == 3:
        return ProtoPort(protocol=item[0], port=item[1], end_port=item[2])
    else:
        raise ValueError(f"Invalid proto_port tuple: {item}")


def create_rule(
    source_cidr: str = "0.0.0.0/0",
    dest_cidr: str = "0.0.0.0/0",
    source_vrf: Optional[str] = None,
    dest_vrf: Optional[str] = None,
    source_vlan: Optional[int] = None,
    dest_vlan: Optional[int] = None,
    source_proto_ports: Optional[List] = None,
    dest_proto_ports: Optional[List] = None,
    description: str = ""
) -> PolicyRule:
    if dest_proto_ports is None:
        dest_proto_ports = [("TCP", None), ("UDP", None), ("ICMP", None)]
    
    source_pp_list = [_parse_proto_port(p) for p in source_proto_ports] if source_proto_ports else None
    dest_pp_list = [_parse_proto_port(p) for p in dest_proto_ports]
    
    source = NetworkEndpoint(
        ip_blocks=[IpBlock(cidr=source_cidr, vrf=source_vrf, vlan=source_vlan)],
        proto_ports=source_pp_list
    )
    destination = NetworkEndpoint(
        ip_blocks=[IpBlock(cidr=dest_cidr, vrf=dest_vrf, vlan=dest_vlan)],
        proto_ports=dest_pp_list
    )
    
    return PolicyRule(
        action="allow",
        source=source,
        destination=destination,
        description=description
    )


def generate_vrf_policy_for_test(
    name: str, 
    vrfs: Optional[List[str]] = None, 
    epbr_range: Optional[Tuple[int, int]] = None,
    trmvrf_range: Optional[Tuple[int, int]] = None,
    namespace: str = "hypershield"
) -> Tuple[Policy, Path]:
    rules = []
    
    def add_vrf_rules(vrf_name: str):
        rules.append(create_rule("0.0.0.0/0", "0.0.0.0/0", source_vrf=vrf_name,
                                 description="Allow L3 traffic for all IPV4 flows"))
        rules.append(create_rule("::/0", "::/0", source_vrf=vrf_name,
                                 description="Allow L3 traffic for all IPV6 flows"))
    
    if vrfs:
        for vrf in vrfs:
            add_vrf_rules(vrf)
    
    if epbr_range:
        for vrf_id in range(epbr_range[0], epbr_range[1] + 1):
            add_vrf_rules(f"epbr-{vrf_id}")
    
    if trmvrf_range:
        for vrf_id in range(trmvrf_range[0], trmvrf_range[1] + 1):
            add_vrf_rules(f"trmvrf-{vrf_id}")
    
    return generate_policy_for_test(name, rules, namespace)


def generate_vlan_policy_for_test(
    name: str,
    vlan_with_ip_range: Optional[Tuple[int, int]] = None,
    vlan_any_ip_range: Optional[Tuple[int, int]] = None,
    namespace: str = "hypershield"
) -> Tuple[Policy, Path]:
    rules = []
    
    def add_vlan_rules(vlan: int, specific_ip: bool):
        if specific_ip:
            subnet_id = vlan - 800
            ipv4_cidr = f"191.168.{subnet_id}.0/24"
            ipv6_cidr = f"1910:168:1:{hex(subnet_id)[2:]}::/64"
        else:
            ipv4_cidr = "0.0.0.0/0"
            ipv6_cidr = "::/0"
        
        rules.append(create_rule(ipv4_cidr, ipv4_cidr, source_vlan=vlan,
                                 description="Allow L2 traffic for all IPV4 flows"))
        rules.append(create_rule(ipv6_cidr, ipv6_cidr, source_vlan=vlan,
                                 description="Allow L2 traffic for all IPV6 flows"))
    
    if vlan_with_ip_range:
        for vlan_id in range(vlan_with_ip_range[0], vlan_with_ip_range[1] + 1):
            add_vlan_rules(vlan_id, specific_ip=True)
    
    if vlan_any_ip_range:
        for vlan_id in range(vlan_any_ip_range[0], vlan_any_ip_range[1] + 1):
            add_vlan_rules(vlan_id, specific_ip=False)
    
    return generate_policy_for_test(name, rules, namespace)


def generate_vrf_and_vlan_policy_for_test(
    name: str,
    vrf: str = "default",
    vlan: int = 100,
    namespace: str = "hypershield"
) -> Tuple[Policy, Path]:
    rules = [
        create_rule(
            source_cidr="10.0.0.0/8",
            dest_cidr="192.168.1.0/24",
            source_vrf=vrf,
            source_vlan=vlan,
            description="Invalid rule: both VRF and VLAN set on source"
        )
    ]
    return generate_policy_for_test(name, rules, namespace)
