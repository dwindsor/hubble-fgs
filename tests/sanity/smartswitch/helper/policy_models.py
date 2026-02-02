#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple

import yaml

logger = logging.getLogger(__name__)

VRF_NAME_TO_ID = {
    "default": 1,
    "tims": 2,
}

def vrf_name_to_id(vrf_name: Optional[str]) -> Optional[int]:
    if vrf_name is None:
        return None
    if vrf_name in VRF_NAME_TO_ID:
        return VRF_NAME_TO_ID[vrf_name]
    if vrf_name.startswith("epbr-"):
        return int(vrf_name.split("-")[1])
    if vrf_name.startswith("trmvrf-"):
        return int(vrf_name.split("-")[1])
    logger.warning(f"Unknown VRF name '{vrf_name}' - not in VRF_NAME_TO_ID and doesn't match epbr-/trmvrf- pattern")
    return 0


VRF_ID_TO_NAME = {v: k for k, v in VRF_NAME_TO_ID.items()}


def vrf_id_to_name(vrf_id: Optional[int]) -> Optional[str]:
    if vrf_id is None or vrf_id == 0:
        return None
    if vrf_id in VRF_ID_TO_NAME:
        return VRF_ID_TO_NAME[vrf_id]
    if 1001 <= vrf_id <= 1025:
        return f"epbr-{vrf_id}"
    if 3001 <= vrf_id <= 3075:
        return f"trmvrf-{vrf_id}"
    return f"unknown-vrf-{vrf_id}"


@dataclass
class IpBlock:
    cidr: str
    vrf: Optional[str] = None
    vlan: Optional[int] = None
    
    def to_dict(self) -> Dict:
        result = {"cidr": self.cidr}
        if self.vrf:
            result["vrf"] = self.vrf
        if self.vlan:
            result["vlan"] = self.vlan
        return result
    
    @property
    def vrf_id(self) -> Optional[int]:
        return vrf_name_to_id(self.vrf)
    
    def matches(self, other: 'IpBlock') -> Tuple[bool, Optional[str]]:
        self_cidr = self._normalize_cidr(self.cidr)
        other_cidr = self._normalize_cidr(other.cidr)
        
        if self_cidr != other_cidr:
            return False, f"CIDR mismatch: expected '{self.cidr}', got '{other.cidr}'"
        self_vrf_id = self.vrf_id
        other_vrf_id = other.vrf_id
        if self_vrf_id != other_vrf_id:
            return False, f"VRF mismatch: expected '{self.vrf}'(id={self_vrf_id}), got '{other.vrf}'(id={other_vrf_id})"
        if self.vlan != other.vlan:
            return False, f"VLAN mismatch: expected {self.vlan}, got {other.vlan}"
        
        return True, None
    
    @staticmethod
    def _normalize_cidr(cidr: str) -> str:
        if cidr.startswith("::0/"):
            return "::" + cidr[3:]
        return cidr
    
    def __repr__(self):
        parts = [self.cidr]
        if self.vrf:
            parts.append(f"vrf={self.vrf}")
        if self.vlan:
            parts.append(f"vlan={self.vlan}")
        return f"IpBlock({', '.join(parts)})"


@dataclass
class ProtoPort:
    protocol: str
    port: Optional[int] = None
    end_port: Optional[int] = None
    
    def to_dict(self) -> Dict:
        result = {"protocol": self.protocol.upper()}
        if self.port is not None:
            result["port"] = self.port
        if self.end_port is not None:
            result["endPort"] = self.end_port
        return result
    
    def get_port_tuple(self) -> Tuple[str, Optional[int], Optional[int]]:
        return (self.protocol.lower(), self.port, self.end_port)
    
    def __repr__(self):
        if self.port is None:
            return f"ProtoPort({self.protocol})"
        if self.end_port is None:
            return f"ProtoPort({self.protocol}:{self.port})"
        return f"ProtoPort({self.protocol}:{self.port}-{self.end_port})"


@dataclass
class NetworkEndpoint:
    ip_blocks: List[IpBlock] = field(default_factory=list)
    proto_ports: Optional[List[ProtoPort]] = None
    
    def to_dict(self) -> Dict:
        result = {
            "ipBlock": [ib.to_dict() for ib in self.ip_blocks]
        }
        if self.proto_ports:
            result["protoPorts"] = [pp.to_dict() for pp in self.proto_ports]
        return result
    
    def get_proto_port_tuples(self) -> Optional[Set[Tuple[str, Optional[int], Optional[int]]]]:
        if not self.proto_ports:
            return None
        result = set()
        for pp in self.proto_ports:
            result.add(pp.get_port_tuple())
        return result if result else None
    
    @staticmethod
    def normalize_proto_ports(proto_ports: Set[Tuple[str, Optional[int], Optional[int]]]) -> Set[Tuple[str, Optional[int], Optional[int]]]:
        result = set()
        for proto, port, end_port in proto_ports:
            proto_lower = proto.lower()
            if proto_lower == "any":
                result.add(("tcp", port, end_port))
                result.add(("udp", port, end_port))
                result.add(("icmp", port, end_port))
            elif "|" in proto_lower:
                # Handle combined protocols like "tcp|udp"
                for p in proto_lower.split("|"):
                    result.add((p.strip(), port, end_port))
            else:
                result.add((proto_lower, port, end_port))
        return result
    
    def matches_proto_ports(self, other: 'NetworkEndpoint') -> Tuple[bool, Optional[str]]:
        self_pp = self.get_proto_port_tuples()
        other_pp = other.get_proto_port_tuples()
        
        # Treat None (no protoPorts) as equivalent to "any" = TCP+UDP+ICMP with no port restriction
        default_any = {("tcp", None, None), ("udp", None, None), ("icmp", None, None)}
        
        if self_pp is None and other_pp is None:
            return True, None
        
        # If one side is None, treat it as default "any" for comparison
        if self_pp is None:
            self_pp = default_any
        if other_pp is None:
            other_pp = default_any
        
        self_normalized = self.normalize_proto_ports(self_pp)
        other_normalized = self.normalize_proto_ports(other_pp)
        
        if self_normalized != other_normalized:
            return False, f"ProtoPort mismatch: {sorted(self_normalized)} vs {sorted(other_normalized)}"
        
        return True, None
    
    def __repr__(self):
        parts = [f"ip_blocks={self.ip_blocks}"]
        if self.proto_ports:
            parts.append(f"proto_ports={self.proto_ports}")
        return f"NetworkEndpoint({', '.join(parts)})"


@dataclass
class PolicyRule:
    action: str
    source: NetworkEndpoint
    destination: NetworkEndpoint
    description: str = ""
    rule_hash: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "description": self.description,
            "source": self.source.to_dict(),
            "destination": self.destination.to_dict()
        }
    
    def matches(self, other: 'PolicyRule') -> Tuple[bool, Optional[str]]:
        self_action = self.action.lower()
        other_action = other.action.lower()
        if self_action == "permit":
            self_action = "allow"
        if other_action == "permit":
            other_action = "allow"
        
        if self_action != other_action:
            return False, f"Action mismatch: {self.action} vs {other.action}"
        if self.source.ip_blocks and other.source.ip_blocks:
            match, error = self.source.ip_blocks[0].matches(other.source.ip_blocks[0])
            if not match:
                return False, f"Source {error}"
        if self.destination.ip_blocks and other.destination.ip_blocks:
            match, error = self.destination.ip_blocks[0].matches(other.destination.ip_blocks[0])
            if not match:
                return False, f"Destination {error}"
        match, error = self.destination.matches_proto_ports(other.destination)
        if not match:
            return False, f"Destination {error}"
        match, error = self.source.matches_proto_ports(other.source)
        if not match:
            return False, f"Source {error}"
        
        return True, None
    
    def __hash__(self):
        if self.rule_hash:
            return hash(self.rule_hash)
        src_cidr = self.source.ip_blocks[0].cidr if self.source.ip_blocks else ""
        dst_cidr = self.destination.ip_blocks[0].cidr if self.destination.ip_blocks else ""
        return hash((src_cidr, dst_cidr, self.action))
    
    def __eq__(self, other):
        if not isinstance(other, PolicyRule):
            return False
        if self.rule_hash and other.rule_hash:
            return self.rule_hash == other.rule_hash
        return hash(self) == hash(other)
    
    def __repr__(self):
        src = self.source.ip_blocks[0].cidr if self.source.ip_blocks else "?"
        dst = self.destination.ip_blocks[0].cidr if self.destination.ip_blocks else "?"
        hash_info = f"[{self.rule_hash[:8]}...]" if self.rule_hash else ""
        return f"PolicyRule({self.action}: {src} -> {dst} {hash_info})"


@dataclass
class Policy:
    name: str
    namespace: str = "hypershield"
    rules: List[PolicyRule] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "apiVersion": "isovalent.com/v1alpha1",
            "kind": "SmartSwitchNetworkPolicy",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace
            },
            "spec": {
                "rules": [r.to_dict() for r in self.rules]
            }
        }
    
    def to_yaml(self) -> str:
        def represent_none(dumper, _):
            return dumper.represent_scalar('tag:yaml.org,2002:null', '')
        yaml.add_representer(type(None), represent_none)
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False, indent=2)
    
    def __repr__(self):
        return f"Policy({self.name}, {len(self.rules)} rules)"


@dataclass
class PolicyComparison:
    policy_name: str
    agw_rule_count: int
    dpu_rule_count: int
    matching_rules: int
    missing_in_dpu: List[str] = field(default_factory=list)
    extra_in_dpu: List[str] = field(default_factory=list)
    rule_detail_errors: List[str] = field(default_factory=list)
    
    @property
    def success(self) -> bool:
        return (
            self.agw_rule_count == self.dpu_rule_count and
            not self.missing_in_dpu and
            not self.extra_in_dpu and
            not self.rule_detail_errors
        )
    
    def get_summary(self) -> str:
        if self.success:
            return (
                f"✅ Policy '{self.policy_name}' verified successfully:\n"
                f"  - {self.matching_rules} rules match between AGW and DPU\n"
                f"  - All rule hashes match\n"
                f"  - All rule details (VRF, CIDR) match"
            )
        
        errors = []
        
        if self.agw_rule_count != self.dpu_rule_count:
            errors.append(
                f"Rule count mismatch: AGW has {self.agw_rule_count} rules, "
                f"DPU has {self.dpu_rule_count} rules"
            )
        
        if self.missing_in_dpu:
            errors.append(
                f"Rules missing in DPU ({len(self.missing_in_dpu)}): "
                f"{self.missing_in_dpu[:3]}..."
            )
        
        if self.extra_in_dpu:
            errors.append(
                f"Extra rules in DPU ({len(self.extra_in_dpu)}): "
                f"{self.extra_in_dpu[:3]}..."
            )
        
        if self.rule_detail_errors:
            errors.extend(self.rule_detail_errors[:5])
            if len(self.rule_detail_errors) > 5:
                errors.append(
                    f"... and {len(self.rule_detail_errors) - 5} more rule detail mismatches"
                )
        
        return (
            f"Policy '{self.policy_name}' verification failed:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )


def parse_agw_policies(agw_output: str, policy_name: Optional[str] = None) -> List[PolicyRule]:
    rules = []
    
    # If policy_name is specified, extract only that policy's section
    if policy_name:
        # Match any namespace: SmartSwitchNetworkPolicy/<namespace>/<policy_name>
        policy_header_pattern = re.compile(
            r"Policy:\s+SmartSwitchNetworkPolicy/(?P<namespace>[^/]+)/(?P<name>[^\s]+)",
            re.MULTILINE
        )
        target_section = None
        matches = list(policy_header_pattern.finditer(agw_output))
        for i, match in enumerate(matches):
            if match.group("name") == policy_name:
                start = match.end()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(agw_output)
                target_section = agw_output[start:end]
                break
        if target_section is None:
            logger.warning(f"Policy '{policy_name}' not found in AGW output")
            return []
        agw_output = target_section
    
    rule_blocks = re.split(r'┌─ Rule \d+', agw_output)
    
    for block in rule_blocks[1:]:
        try:
            hash_match = re.search(r'Rule Name:\s+([a-f0-9]{64})', block)
            if not hash_match:
                continue
            rule_hash = hash_match.group(1)
            
            action_match = re.search(r'Action:\s+(\w+)', block)
            action = action_match.group(1).lower() if action_match else "allow"
            
            source_section_match = re.search(r'Source:(.*?)(?:Destination:|$)', block, re.DOTALL)
            dest_section_match = re.search(r'Destination:(.*?)(?:└|$)', block, re.DOTALL)
            
            source_section = source_section_match.group(1) if source_section_match else ""
            dest_section = dest_section_match.group(1) if dest_section_match else ""
            
            source_cidr_match = re.search(r'CIDR:\s+([\da-fA-F:.]+/\d+)', source_section)
            source_cidr = source_cidr_match.group(1) if source_cidr_match else "0.0.0.0/0"
            
            source_vrf_match = re.search(r'VRF:\s+(\S+)', source_section)
            source_vrf = source_vrf_match.group(1) if source_vrf_match else None
            
            source_vlan_match = re.search(r'VLAN:\s+(\d+)', source_section)
            source_vlan = int(source_vlan_match.group(1)) if source_vlan_match else None
            if source_vlan == 0:
                source_vlan = None
            
            dest_cidr_match = re.search(r'CIDR:\s+([\da-fA-F:.]+/\d+)', dest_section)
            dest_cidr = dest_cidr_match.group(1) if dest_cidr_match else "0.0.0.0/0"
            
            dest_vrf_match = re.search(r'VRF:\s+(\S+)', dest_section)
            dest_vrf = dest_vrf_match.group(1) if dest_vrf_match else None
            
            dest_vlan_match = re.search(r'VLAN:\s+(\d+)', dest_section)
            dest_vlan = int(dest_vlan_match.group(1)) if dest_vlan_match else None
            if dest_vlan == 0:
                dest_vlan = None
            
            source_proto_ports = []
            source_proto_matches = re.findall(r'Protocol:\s+([\w_]+)', source_section)
            source_port_matches = re.findall(r'Port:\s+(\d+)', source_section)
            
            for i, proto_raw in enumerate(source_proto_matches):
                proto = proto_raw.upper().replace("POLICY_PROTOCOL_", "")
                port = int(source_port_matches[i]) if i < len(source_port_matches) else None
                source_proto_ports.append(ProtoPort(protocol=proto, port=port))
            
            dest_proto_ports = []
            dest_proto_matches = re.findall(r'Protocol:\s+([\w_]+)', dest_section)
            dest_port_matches = re.findall(r'Ports?:\s+(\d+)(?:\s*-\s*(\d+))?', dest_section)
            
            for i, proto_raw in enumerate(dest_proto_matches):
                proto = proto_raw.upper().replace("POLICY_PROTOCOL_", "")
                if i < len(dest_port_matches):
                    port_match = dest_port_matches[i]
                    port = int(port_match[0])
                    end_port = int(port_match[1]) if port_match[1] else None
                else:
                    port = None
                    end_port = None
                dest_proto_ports.append(ProtoPort(protocol=proto, port=port, end_port=end_port))
            
            source_ip_block = IpBlock(cidr=source_cidr, vrf=source_vrf, vlan=source_vlan)
            source = NetworkEndpoint(
                ip_blocks=[source_ip_block],
                proto_ports=source_proto_ports if source_proto_ports else None
            )
            
            dest_ip_block = IpBlock(cidr=dest_cidr, vrf=dest_vrf, vlan=dest_vlan)
            destination = NetworkEndpoint(
                ip_blocks=[dest_ip_block],
                proto_ports=dest_proto_ports if dest_proto_ports else None
            )
            
            rule = PolicyRule(
                action=action,
                source=source,
                destination=destination,
                rule_hash=rule_hash
            )
            rules.append(rule)
            
        except Exception as e:
            logger.warning(f"Failed to parse AGW rule block: {e}")
            continue
    
    logger.info(f"Parsed {len(rules)} rules from AGW output")
    return rules


def parse_dpu_policies(dpu_output: str, policy_name: Optional[str] = None) -> List[PolicyRule]:
    rules = []
    
    try:
        data = json.loads(dpu_output)
        # Support both old format (p_policy.policies) and new format (data)
        policies = data.get("data", []) or data.get("p_policy", {}).get("policies", [])
        
        # Filter by policy name if specified
        # DPU name format: SmartSwitchNetworkPolicy/<namespace>/<policy_name>/<hash>/<id>
        if policy_name:
            policies = [p for p in policies if p.get("name", "").split("/")[2] == policy_name]
        
        rules_by_hash: Dict[str, Dict] = {}
        
        for policy in policies:
            name = policy.get("name", "")
            policy_id = policy.get("id", "")
            # Try to find hash in name first, then in id field
            hash_match = re.search(r'/([a-f0-9]{64})/', name)
            if not hash_match:
                # Hash might be in the id field: "::...:<hash>/<number>"
                hash_match = re.search(r':([a-f0-9]{64})/', policy_id)
            if not hash_match:
                logger.warning(f"No hash found in DPU policy name: {name}, id: {policy_id}")
                continue
            
            rule_hash = hash_match.group(1)
            source = policy.get("source", {})
            dest = policy.get("destination", {})
            # Effect can be string ("permit"/"deny") or integer (0=allow, 1=deny)
            effect = policy.get("effect", "permit")
            if isinstance(effect, str):
                action = "allow" if effect == "permit" else "deny"
            else:
                action = "allow" if effect == 0 else "deny"
            
            source_vlan = source.get("vlan")
            if source_vlan == 0:
                source_vlan = None
            source_vrf = vrf_id_to_name(source.get("vrf"))
            
            dest_vrf = vrf_id_to_name(dest.get("vrf"))
            
            dest_vlan = dest.get("vlan")
            if dest_vlan == 0:
                dest_vlan = None
            
            def extract_proto_ports(port_list):
                proto_ports = []
                for port_entry in port_list:
                    port_low = port_entry.get("port_low")
                    port_high = port_entry.get("port_high")
                    entry_protocols = port_entry.get("protocol", [])
                    
                    if port_low == 0 and port_high == 65535:
                        # Full port range (0-65535) means no port restriction
                        # Expand "any" to TCP, UDP, ICMP for proper comparison
                        if entry_protocols == ["any"]:
                            proto_ports.append(ProtoPort(protocol="TCP", port=None))
                            proto_ports.append(ProtoPort(protocol="UDP", port=None))
                            proto_ports.append(ProtoPort(protocol="ICMP", port=None))
                        else:
                            for proto in entry_protocols:
                                proto_ports.append(ProtoPort(protocol=proto.upper(), port=None))
                    elif port_low is not None and port_low > 0:
                        if port_low == port_high:
                            for proto in entry_protocols:
                                proto_ports.append(ProtoPort(protocol=proto.upper(), port=port_low))
                        else:
                            for proto in entry_protocols:
                                proto_ports.append(ProtoPort(
                                    protocol=proto.upper(), port=port_low, end_port=port_high
                                ))
                return proto_ports
            
            source_proto_ports = extract_proto_ports(source.get("port", []))
            dest_proto_ports = extract_proto_ports(dest.get("port", []))
            
            if rule_hash not in rules_by_hash:
                rules_by_hash[rule_hash] = {
                    "rule_hash": rule_hash,
                    "action": action,
                    "source_cidr": source.get("ip", "0.0.0.0/0"),
                    "source_vrf": source_vrf,
                    "source_vlan": source_vlan,
                    "source_proto_ports": [],
                    "dest_cidr": dest.get("ip", "0.0.0.0/0"),
                    "dest_vrf": dest_vrf,
                    "dest_vlan": dest_vlan,
                    "dest_proto_ports": []
                }
            
            rules_by_hash[rule_hash]["source_proto_ports"].extend(source_proto_ports)
            rules_by_hash[rule_hash]["dest_proto_ports"].extend(dest_proto_ports)
        
        for rule_data in rules_by_hash.values():
            source_ip_block = IpBlock(
                cidr=rule_data["source_cidr"],
                vrf=rule_data["source_vrf"],
                vlan=rule_data["source_vlan"]
            )
            source_proto_ports = rule_data["source_proto_ports"] if rule_data["source_proto_ports"] else None
            source = NetworkEndpoint(ip_blocks=[source_ip_block], proto_ports=source_proto_ports)
            
            dest_ip_block = IpBlock(
                cidr=rule_data["dest_cidr"],
                vrf=rule_data["dest_vrf"],
                vlan=rule_data["dest_vlan"]
            )
            dest_proto_ports = rule_data["dest_proto_ports"] if rule_data["dest_proto_ports"] else None
            destination = NetworkEndpoint(ip_blocks=[dest_ip_block], proto_ports=dest_proto_ports)
            
            rule = PolicyRule(
                action=rule_data["action"],
                source=source,
                destination=destination,
                rule_hash=rule_data["rule_hash"]
            )
            rules.append(rule)
        
        logger.info(f"Parsed {len(rules)} rules from DPU output (from {len(policies)} policy entries)")
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse DPU JSON output: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to parse DPU policies: {e}")
        raise
    
    return rules


def compare_policy_rules(
    agw_rules: List[PolicyRule],
    dpu_rules: List[PolicyRule],
    policy_name: str,
    expected_rules: Optional[List[PolicyRule]] = None
) -> PolicyComparison:
    agw_hashes = {rule.rule_hash for rule in agw_rules if rule.rule_hash}
    dpu_hashes = {rule.rule_hash for rule in dpu_rules if rule.rule_hash}
    
    missing_in_dpu = list(agw_hashes - dpu_hashes)
    extra_in_dpu = list(dpu_hashes - agw_hashes)
    common_hashes = agw_hashes & dpu_hashes
    
    agw_by_hash = {rule.rule_hash: rule for rule in agw_rules if rule.rule_hash}
    dpu_by_hash = {rule.rule_hash: rule for rule in dpu_rules if rule.rule_hash}
    
    rule_detail_errors = []
    for rule_hash in common_hashes:
        agw_rule = agw_by_hash[rule_hash]
        dpu_rule = dpu_by_hash[rule_hash]
        matches, error_msg = agw_rule.matches(dpu_rule)
        if not matches:
            rule_detail_errors.append(f"Rule {rule_hash[:8]}...: {error_msg}")
    
    return PolicyComparison(
        policy_name=policy_name,
        agw_rule_count=len(agw_rules),
        dpu_rule_count=len(dpu_rules),
        matching_rules=len(common_hashes),
        missing_in_dpu=missing_in_dpu,
        extra_in_dpu=extra_in_dpu,
        rule_detail_errors=rule_detail_errors
    )
