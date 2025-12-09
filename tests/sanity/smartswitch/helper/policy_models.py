import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    action: str = "allow"
    source_cidr: str = "0.0.0.0/0"
    dest_cidr: str = "0.0.0.0/0"
    protocols: List[str] = field(default_factory=lambda: ["TCP", "UDP", "ICMP"])
    description: str = ""
    vrf_name: Optional[str] = None
    vlan: Optional[int] = None
    rule_hash: Optional[str] = None
    source_vrf_id: Optional[int] = None
    dest_vrf_id: Optional[int] = None
    source_vlan: Optional[int] = None
    
    @staticmethod
    def normalize_cidr(cidr: str) -> str:
        if cidr.startswith("::0/"):
            return "::" + cidr[3:]
        return cidr
    
    def to_dict(self) -> Dict:
        rule = {
            "action": self.action,
            "description": self.description,
            "source": {
                "ipBlock": [{"cidr": self.source_cidr}]
            },
            "destination": {
                "ipBlock": [{"cidr": self.dest_cidr}],
                "protoPorts": [{"protocol": p} for p in self.protocols]
            }
        }
        
        if self.vrf_name:
            rule["source"]["ipBlock"][0]["vrf"] = self.vrf_name
        elif self.vlan:
            rule["source"]["ipBlock"][0]["vlan"] = self.vlan
        
        return rule
    
    def matches(self, other: 'PolicyRule', strict_protocol_check: bool = False) -> tuple[bool, Optional[str]]:
        if not isinstance(other, PolicyRule):
            return False, "Not a PolicyRule instance"
        
        if self.source_vrf_id != other.source_vrf_id:
            return False, (
                f"Source VRF mismatch: "
                f"{self.source_vrf_id} vs {other.source_vrf_id}"
            )
        
        if self.dest_vrf_id != other.dest_vrf_id:
            return False, (
                f"Dest VRF mismatch: "
                f"{self.dest_vrf_id} vs {other.dest_vrf_id}"
            )
        
        if self.source_vlan != other.source_vlan:
            return False, (
                f"Source VLAN mismatch: "
                f"{self.source_vlan} vs {other.source_vlan}"
            )
        
        self_src = self.normalize_cidr(self.source_cidr)
        other_src = self.normalize_cidr(other.source_cidr)
        if self_src != other_src:
            return False, (
                f"Source CIDR mismatch: "
                f"{self.source_cidr} vs {other.source_cidr}"
            )
        
        self_dest = self.normalize_cidr(self.dest_cidr)
        other_dest = self.normalize_cidr(other.dest_cidr)
        if self_dest != other_dest:
            return False, (
                f"Dest CIDR mismatch: "
                f"{self.dest_cidr} vs {other.dest_cidr}"
            )
        
        if strict_protocol_check:
            self_protocols = set(p.lower() for p in self.protocols)
            other_protocols = set(p.lower() for p in other.protocols)
            if self_protocols != other_protocols:
                return False, (
                    f"Protocol mismatch: "
                    f"{self_protocols} vs {other_protocols}"
                )
        
        return True, None
    
    def __hash__(self):
        if self.rule_hash:
            return hash(self.rule_hash)
        return hash((self.source_cidr, self.dest_cidr, self.source_vrf_id, self.dest_vrf_id, self.source_vlan))
    
    def __eq__(self, other):
        if not isinstance(other, PolicyRule):
            return False
        if self.rule_hash and other.rule_hash:
            return self.rule_hash == other.rule_hash
        return (
            self.source_cidr == other.source_cidr and
            self.dest_cidr == other.dest_cidr and
            self.source_vrf_id == other.source_vrf_id and
            self.dest_vrf_id == other.dest_vrf_id and
            self.source_vlan == other.source_vlan
        )
    
    def __repr__(self):
        vrf_info = f"VRF:{self.source_vrf_id}" if self.source_vrf_id else ""
        vlan_info = f"VLAN:{self.source_vlan}" if self.source_vlan else ""
        hash_info = f"[{self.rule_hash[:8]}...]" if self.rule_hash else ""
        return f"PolicyRule({self.source_cidr} {vrf_info}{vlan_info} → {self.dest_cidr} {hash_info})"


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


def _parse_vrf_string(vrf_str: str) -> int:
    if vrf_str.startswith(("epbr-", "trmvrf-")):
        return int(vrf_str.split("-")[1])
    if vrf_str == "default":
        return 1
    return 0


def parse_agw_policies(agw_output: str) -> List[PolicyRule]:
    rules = []
    rule_blocks = re.split(r'┌─ Rule \d+', agw_output)
    
    for block in rule_blocks[1:]:
        try:
            hash_match = re.search(r'Rule Name:\s+([a-f0-9]{64})', block)
            if not hash_match:
                continue
            rule_hash = hash_match.group(1)
            action_match = re.search(r'Action:\s+(\w+)', block)
            action = action_match.group(1) if action_match else "Allow"
            source_cidr_match = re.search(r'Source:.*?CIDR:\s+([\da-fA-F:.]+/\d+)', block, re.DOTALL)
            source_cidr = source_cidr_match.group(1) if source_cidr_match else "0.0.0.0/0"
            
            source_vrf_match = re.search(r'Source:.*?VRF:\s+(\S+)', block, re.DOTALL)
            source_vrf = _parse_vrf_string(source_vrf_match.group(1)) if source_vrf_match else 0
            
            source_vlan_match = re.search(r'Source:.*?VLAN:\s+(\d+)', block, re.DOTALL)
            source_vlan = int(source_vlan_match.group(1)) if source_vlan_match else None
            if source_vlan == 0:
                source_vlan = None
            
            dest_cidr_match = re.search(r'Destination:.*?CIDR:\s+([\da-fA-F:.]+/\d+)', block, re.DOTALL)
            dest_cidr = dest_cidr_match.group(1) if dest_cidr_match else "0.0.0.0/0"
            
            dest_vrf_match = re.search(r'Destination:.*?VRF:\s+(\S+)', block, re.DOTALL)
            dest_vrf = _parse_vrf_string(dest_vrf_match.group(1)) if dest_vrf_match else 0
            
            protocols_raw = re.findall(r'Protocol:\s+([\w_]+)', block)
            protocols = []
            for p in protocols_raw:
                proto = p.lower().replace("policy_protocol_", "")
                if proto not in protocols:
                    protocols.append(proto)
            
            rule = PolicyRule(
                rule_hash=rule_hash,
                action=action,
                source_cidr=source_cidr,
                source_vrf_id=source_vrf,
                source_vlan=source_vlan,
                dest_cidr=dest_cidr,
                dest_vrf_id=dest_vrf,
                protocols=protocols
            )
            rules.append(rule)
            
        except Exception as e:
            logger.warning(f"Failed to parse AGW rule block: {e}")
            continue
    
    logger.info(f"Parsed {len(rules)} rules from AGW output")
    return rules


def parse_dpu_policies(dpu_output: str) -> List[PolicyRule]:
    rules = []
    
    try:
        data = json.loads(dpu_output)
        policies = data.get("p_policy", {}).get("policies", [])
        rules_by_hash: Dict[str, Dict] = {}
        
        for policy in policies:
            name = policy.get("name", "")
            hash_match = re.search(r'/([a-f0-9]{64})/', name)
            if not hash_match:
                logger.warning(f"No hash found in DPU policy name: {name}")
                continue
            
            rule_hash = hash_match.group(1)
            source = policy.get("source", {})
            dest = policy.get("destination", {})
            action = policy.get("effect", "permit")
            
            protocols = []
            for port_entry in dest.get("port", []):
                for proto in port_entry.get("protocol", []):
                    if proto:
                        proto_lower = proto.lower()
                        if proto_lower == "any":
                            protocols = ["tcp", "udp", "icmp"]
                            break
                        if proto_lower not in protocols:
                            protocols.append(proto_lower)
                if "any" in [p.lower() for p in port_entry.get("protocol", [])]:
                    break
            
            source_vlan = source.get("vlan")
            if source_vlan == 0:
                source_vlan = None
            
            if rule_hash not in rules_by_hash:
                rules_by_hash[rule_hash] = {
                    "rule_hash": rule_hash,
                    "action": action,
                    "source_cidr": source.get("ip", "0.0.0.0/0"),
                    "source_vrf_id": source.get("vrf"),
                    "source_vlan": source_vlan,
                    "dest_cidr": dest.get("ip", "0.0.0.0/0"),
                    "dest_vrf_id": dest.get("vrf"),
                    "protocols": []
                }
            
            for proto in protocols:
                if proto not in rules_by_hash[rule_hash]["protocols"]:
                    rules_by_hash[rule_hash]["protocols"].append(proto)
        
        for rule_data in rules_by_hash.values():
            rule = PolicyRule(**rule_data)
            rules.append(rule)
        
        logger.info(f"Parsed {len(rules)} rules from DPU output (from {len(policies)} individual policy entries)")
        
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
    strict_protocol_check: bool = False
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
        matches, error_msg = agw_rule.matches(dpu_rule, strict_protocol_check)
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
