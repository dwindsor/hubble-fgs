#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import ipaddress
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import yaml
from scapy.packet import Packet

from .packet_builder import PacketBuilder
from .policy_models import vrf_name_to_id

logger = logging.getLogger(__name__)

DEFAULT_SPORT_RANGE = (1024, 65535)


@dataclass
class GeneratedPacket:
    """A packet generated from a policy rule, with metadata for verification."""
    packet: Packet
    rule_index: int
    rule_description: str
    action: str
    src_ip: str
    dst_ip: str
    protocol: str
    sport: int
    dport: Optional[int]
    src_cidr: str
    dst_cidr: str
    src_vrf: Optional[str] = None
    dst_vrf: Optional[str] = None
    src_vlan: Optional[int] = None

    def summary(self) -> str:
        port_info = f":{self.dport}" if self.dport else ""
        vrf_info = f" vrf={self.src_vrf}" if self.src_vrf else ""
        vlan_info = f" vlan={self.src_vlan}" if self.src_vlan else ""
        return (
            f"Rule {self.rule_index} [{self.action}] "
            f"'{self.rule_description}': "
            f"{self.src_ip} ({self.src_cidr}) -> "
            f"{self.dst_ip} ({self.dst_cidr}) "
            f"{self.protocol}{port_info}"
            f"{vrf_info}{vlan_info}"
        )


def random_ip_from_cidr(cidr: str) -> str:
    """Generate a random IP address within a CIDR range."""
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses == 1:
        return str(network.network_address)
    # Exclude network and broadcast for ranges > 2
    if network.num_addresses > 2:
        offset = random.randint(1, network.num_addresses - 2)
    else:
        offset = random.randint(0, network.num_addresses - 1)
    return str(network.network_address + offset)


def random_port_from_range(port: Optional[int], end_port: Optional[int]) -> Optional[int]:
    """Generate a random port from a port/endPort specification."""
    if port is None:
        return random.randint(1, 65535)
    if end_port is None:
        return port
    return random.randint(port, end_port)


def _parse_rule_proto_ports(destination: dict) -> List[Tuple[str, Optional[int], Optional[int]]]:
    """Extract (protocol, port, endPort) tuples from a rule's destination protoPorts."""
    proto_ports_raw = destination.get("protoPorts", [])
    if not proto_ports_raw:
        return []
    result = []
    for pp in proto_ports_raw:
        protocol = pp.get("protocol", "TCP").upper()
        port = pp.get("port")
        end_port = pp.get("endPort")
        result.append((protocol, port, end_port))
    return result


def _pick_random_proto_port(
    proto_ports: List[Tuple[str, Optional[int], Optional[int]]]
) -> Tuple[str, int, int]:
    """Pick a random protocol/port from the list and return (protocol, sport, dport).

    Returns a tuple of (protocol, source_port, destination_port).
    """
    if not proto_ports:
        # No protoPorts specified — default to TCP with random ports
        protocol = random.choice(["TCP", "UDP"])
        sport = random.randint(*DEFAULT_SPORT_RANGE)
        dport = random.randint(1, 65535)
        return protocol, sport, dport

    protocol, port, end_port = random.choice(proto_ports)

    if protocol == "ICMP":
        return "ICMP", 0, 0

    dport = random_port_from_range(port, end_port)
    sport = random.randint(*DEFAULT_SPORT_RANGE)
    return protocol, sport, dport


def _parse_ip_blocks(endpoint: dict) -> List[dict]:
    """Parse ipBlock list from a source or destination endpoint."""
    return endpoint.get("ipBlock", [])


def _pick_random_cidr(ip_block: dict) -> str:
    """Pick a random CIDR from ip_block supporting both cidr and cidrs formats."""
    cidr = ip_block.get("cidr")
    if cidr:
        return cidr

    cidrs = ip_block.get("cidrs", [])
    if cidrs:
        return random.choice(cidrs)

    raise ValueError("ipBlock does not contain either 'cidr' or 'cidrs'")


def _parse_vrf(ip_block: dict) -> Optional[str]:
    """Parse VRF from legacy vrf or virtualNetwork.vrfs."""
    vrf = ip_block.get("vrf")
    if vrf:
        return vrf

    virtual_network = ip_block.get("virtualNetwork", {})
    vrfs = virtual_network.get("vrfs", [])
    if vrfs:
        return vrfs[0]

    return None


def _parse_vlan(ip_block: dict) -> Optional[int]:
    """Parse VLAN from legacy vlan or virtualNetwork.vlans."""
    vlan = ip_block.get("vlan")
    if vlan:
        return vlan

    virtual_network = ip_block.get("virtualNetwork", {})
    vlans = virtual_network.get("vlans", [])
    if vlans:
        return vlans[0]

    return None


def generate_packets_from_policy_file(
    policy_path: str,
    seed: Optional[int] = None,
    builder: Optional[PacketBuilder] = None,
) -> List[GeneratedPacket]:
    """Parse a SmartSwitchNetworkPolicy YAML and generate one random packet per rule.

    Args:
        policy_path: Path to the policy YAML file.
        seed: Optional random seed for reproducibility.
        builder: Optional PacketBuilder instance (uses default if not provided).

    Returns:
        List of GeneratedPacket, one per rule in the policy.
    """
    if seed is not None:
        random.seed(seed)

    if builder is None:
        builder = PacketBuilder()

    policy_path = Path(policy_path)
    with open(policy_path) as f:
        policy_data = yaml.safe_load(f)

    rules = policy_data.get("spec", {}).get("rules", [])
    if not rules:
        logger.warning(f"No rules found in policy file: {policy_path}")
        return []

    generated = []
    for idx, rule in enumerate(rules):
        try:
            pkt_info = _generate_packet_for_rule(idx, rule, builder)
            generated.append(pkt_info)
        except Exception as e:
            logger.error(f"Failed to generate packet for rule {idx}: {e}")
            continue

    logger.info(
        f"Generated {len(generated)} packets from {len(rules)} rules "
        f"in {policy_path.name}"
    )
    return generated


def _generate_packet_for_rule(
    rule_index: int,
    rule: dict,
    builder: PacketBuilder,
) -> GeneratedPacket:
    """Generate a single random packet that matches a given policy rule."""
    action = rule.get("action", "allow")
    description = rule.get("description", f"rule-{rule_index}")

    source = rule.get("source", {})
    destination = rule.get("destination", {})

    # Pick random source CIDR
    src_blocks = _parse_ip_blocks(source)
    if not src_blocks:
        raise ValueError(f"Rule {rule_index} has no source ipBlocks")
    src_block = random.choice(src_blocks)
    src_cidr = _pick_random_cidr(src_block)
    src_vrf = _parse_vrf(src_block)
    src_vlan = _parse_vlan(src_block)

    # Pick random destination CIDR
    dst_blocks = _parse_ip_blocks(destination)
    if not dst_blocks:
        raise ValueError(f"Rule {rule_index} has no destination ipBlocks")
    dst_block = random.choice(dst_blocks)
    dst_cidr = _pick_random_cidr(dst_block)
    dst_vrf = _parse_vrf(dst_block)

    # Generate random IPs
    src_ip = random_ip_from_cidr(src_cidr)
    dst_ip = random_ip_from_cidr(dst_cidr)

    # Pick random protocol/port
    proto_ports = _parse_rule_proto_ports(destination)
    protocol, sport, dport = _pick_random_proto_port(proto_ports)

    # Determine IP version
    ip_version = 6 if ":" in src_ip else 4

    # Build the scapy packet
    vlan = src_vlan or 0
    src_vrf_id = vrf_name_to_id(src_vrf) or 0
    if protocol == "TCP":
        pkt = builder.tcp(
            src_ip=src_ip, dst_ip=dst_ip,
            sport=sport, dport=dport,
            ip_version=ip_version, vlan=vlan, vrf=src_vrf_id,
        )
    elif protocol == "UDP":
        pkt = builder.udp(
            src_ip=src_ip, dst_ip=dst_ip,
            sport=sport, dport=dport,
            ip_version=ip_version, vlan=vlan, vrf=src_vrf_id,
        )
    elif protocol == "ICMP":
        pkt = builder.icmp(
            src_ip=src_ip, dst_ip=dst_ip,
            ip_version=ip_version, vlan=vlan, vrf=src_vrf_id,
        )
    else:
        # Fallback to TCP for unknown protocols
        logger.warning(f"Unknown protocol '{protocol}' in rule {rule_index}, using TCP")
        pkt = builder.tcp(
            src_ip=src_ip, dst_ip=dst_ip,
            sport=sport, dport=dport,
            ip_version=ip_version, vlan=vlan, vrf=src_vrf_id,
        )

    return GeneratedPacket(
        packet=pkt,
        rule_index=rule_index,
        rule_description=description,
        action=action,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        sport=sport,
        dport=dport if protocol != "ICMP" else None,
        src_cidr=src_cidr,
        dst_cidr=dst_cidr,
        src_vrf=src_vrf,
        dst_vrf=dst_vrf,
        src_vlan=src_vlan,
    )


def print_generated_packets(packets: List[GeneratedPacket]) -> None:
    """Log a summary of all generated packets."""
    for pkt in packets:
        logger.info(pkt.summary())
    logger.info(f"Total: {len(packets)} packets generated")
