import tempfile
from pathlib import Path
from typing import List, Dict, Literal
import yaml

from .policy_models import PolicyRule


class PolicyGenerator:
    @staticmethod
    def generate_l3_vrf_rules(
        vrf: str,
        ip_version: Literal["ipv4", "ipv6"] = "ipv4"
    ) -> PolicyRule:
        if ip_version == "ipv4":
            cidr = "0.0.0.0/0"
            desc = "Allow L3 traffic for all IPV4 flows"
        else:
            cidr = "::/0"
            desc = "Allow L3 traffic for all IPV6 flows"
        
        return PolicyRule(
            description=desc,
            source_cidr=cidr,
            dest_cidr=cidr,
            vrf_name=vrf
        )
    
    @staticmethod
    def generate_l2_vlan_rules_with_ip(
        vlan: int,
        ip_version: Literal["ipv4", "ipv6"] = "ipv4"
    ) -> PolicyRule:
        if ip_version == "ipv4":
            subnet_id = vlan - 800
            cidr = f"191.168.{subnet_id}.0/24"
            desc = "Allow L2 traffic for all IPV4 flows"
        else:
            subnet_id_hex = hex(vlan - 800)[2:]
            cidr = f"1910:168:1:{subnet_id_hex}::/64"
            desc = "Allow L2 traffic for all IPV6 flows"
        
        return PolicyRule(
            description=desc,
            source_cidr=cidr,
            dest_cidr=cidr,
            vlan=vlan
        )
    
    @staticmethod
    def generate_l2_vlan_rules_any_ip(
        vlan: int,
        ip_version: Literal["ipv4", "ipv6"] = "ipv4"
    ) -> PolicyRule:
        if ip_version == "ipv4":
            cidr = "0.0.0.0/0"
            desc = "Allow L2 traffic for all IPV4 flows"
        else:
            cidr = "::/0"
            desc = "Allow L2 traffic for all IPV6 flows"
        
        return PolicyRule(
            description=desc,
            source_cidr=cidr,
            dest_cidr=cidr,
            vlan=vlan
        )
    
    @staticmethod
    def create_policy(
        name: str,
        namespace: str,
        rules: List[PolicyRule]
    ) -> Dict:
        return {
            "apiVersion": "isovalent.com/v1alpha1",
            "kind": "SmartSwitchNetworkPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace
            },
            "spec": {
                "rules": [rule.to_dict() for rule in rules]
            }
        }
    
    @staticmethod
    def write_policy(policy: Dict, output_path: Path) -> None:
        def represent_none(self, _):
            return self.represent_scalar('tag:yaml.org,2002:null', '')
        
        yaml.add_representer(type(None), represent_none)
        
        with open(output_path, 'w') as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False, indent=2)
        
        print(f"✅ Generated: {output_path.name}")


def generate_epbr_vrf_policy_for_test(
    name: str, 
    vrfs: List[str] = None, 
    epbr_range: tuple = None,
    trmvrf_range: tuple = None
) -> Path:
    rules = []
    
    if vrfs:
        for vrf in vrfs:
            rules.append(PolicyGenerator.generate_l3_vrf_rules(vrf, "ipv4"))
            rules.append(PolicyGenerator.generate_l3_vrf_rules(vrf, "ipv6"))
    
    if epbr_range:
        start, end = epbr_range
        for vrf_id in range(start, end + 1):
            vrf_name = f"epbr-{vrf_id}"
            rules.append(PolicyGenerator.generate_l3_vrf_rules(vrf_name, "ipv4"))
            rules.append(PolicyGenerator.generate_l3_vrf_rules(vrf_name, "ipv6"))
    
    if trmvrf_range:
        start, end = trmvrf_range
        for vrf_id in range(start, end + 1):
            vrf_name = f"trmvrf-{vrf_id}"
            rules.append(PolicyGenerator.generate_l3_vrf_rules(vrf_name, "ipv4"))
            rules.append(PolicyGenerator.generate_l3_vrf_rules(vrf_name, "ipv6"))
    
    policy = PolicyGenerator.create_policy(name, "default", rules)
    fd, temp_path = tempfile.mkstemp(suffix=".yaml", prefix=f"{name}_")
    output_path = Path(temp_path)
    PolicyGenerator.write_policy(policy, output_path)
    
    return output_path


def generate_vlan_policy_for_test(
    name: str,
    vlan_with_ip_range: tuple = None,
    vlan_any_ip_range: tuple = None
) -> Path:
    rules = []
    
    if vlan_with_ip_range:
        start, end = vlan_with_ip_range
        for vlan_id in range(start, end + 1):
            rules.append(PolicyGenerator.generate_l2_vlan_rules_with_ip(vlan_id, "ipv4"))
            rules.append(PolicyGenerator.generate_l2_vlan_rules_with_ip(vlan_id, "ipv6"))
    
    if vlan_any_ip_range:
        start, end = vlan_any_ip_range
        for vlan_id in range(start, end + 1):
            rules.append(PolicyGenerator.generate_l2_vlan_rules_any_ip(vlan_id, "ipv4"))
            rules.append(PolicyGenerator.generate_l2_vlan_rules_any_ip(vlan_id, "ipv6"))
    
    policy = PolicyGenerator.create_policy(name, "default", rules)
    fd, temp_path = tempfile.mkstemp(suffix=".yaml", prefix=f"{name}_")
    output_path = Path(temp_path)
    PolicyGenerator.write_policy(policy, output_path)
    
    return output_path
