#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet

DEFAULT_SRC_MAC = "00:02:00:00:01:01"
DEFAULT_DST_MAC = "00:02:00:00:01:02"
DEFAULT_SRC_IP4 = "12.0.1.2"
DEFAULT_DST_IP4 = "12.0.1.4"
DEFAULT_SRC_IP6 = "2001:db8:0:1:207:3fff:fe68:df44"
DEFAULT_DST_IP6 = "2001:db8:0:1:207:3fff:fe68:f1dd"
DEFAULT_SPORT = 7024
DEFAULT_DPORT = 9048


class PacketBuilder:
    def __init__(self, src_mac: str = DEFAULT_SRC_MAC, dst_mac: str = DEFAULT_DST_MAC):
        self.src_mac = src_mac
        self.dst_mac = dst_mac

    def _ether(self) -> Ether:
        return Ether(src=self.src_mac, dst=self.dst_mac)

    def _add_vlan(self, packet: Packet, vlan_id: int) -> Packet:
        ether = packet.getlayer(Ether)
        payload = ether.payload
        return Ether(src=ether.src, dst=ether.dst) / Dot1Q(vlan=vlan_id) / payload

    def _get_ip_defaults(self, ip_version: int) -> tuple:
        if ip_version == 6:
            return DEFAULT_SRC_IP6, DEFAULT_DST_IP6
        return DEFAULT_SRC_IP4, DEFAULT_DST_IP4

    def tcp(self, src_ip: str = None, dst_ip: str = None, sport: int = DEFAULT_SPORT,
            dport: int = DEFAULT_DPORT, flags: str = "", seq: int = None, ack: int = None,
            ip_version: int = 4, vlan: int = None) -> Packet:
        default_src, default_dst = self._get_ip_defaults(ip_version)
        src_ip = src_ip or default_src
        dst_ip = dst_ip or default_dst
        tcp_args = {"sport": sport, "dport": dport}
        if flags:
            tcp_args["flags"] = flags
        if seq is not None:
            tcp_args["seq"] = seq
        if ack is not None:
            tcp_args["ack"] = ack
        if ip_version == 6:
            pkt = self._ether() / IPv6(src=src_ip, dst=dst_ip) / TCP(**tcp_args)
        else:
            pkt = self._ether() / IP(src=src_ip, dst=dst_ip) / TCP(**tcp_args)
        return self._add_vlan(pkt, vlan) if vlan else pkt

    def udp(self, src_ip: str = None, dst_ip: str = None, sport: int = DEFAULT_SPORT,
            dport: int = DEFAULT_DPORT, ip_version: int = 4, vlan: int = None) -> Packet:
        default_src, default_dst = self._get_ip_defaults(ip_version)
        src_ip = src_ip or default_src
        dst_ip = dst_ip or default_dst
        if ip_version == 6:
            pkt = self._ether() / IPv6(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
        else:
            pkt = self._ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
        return self._add_vlan(pkt, vlan) if vlan else pkt

    def icmp(self, src_ip: str = None, dst_ip: str = None, ip_version: int = 4,
             vlan: int = None) -> Packet:
        default_src, default_dst = self._get_ip_defaults(ip_version)
        src_ip = src_ip or default_src
        dst_ip = dst_ip or default_dst
        if ip_version == 6:
            pkt = self._ether() / IPv6(src=src_ip, dst=dst_ip) / ICMPv6EchoRequest()
        else:
            pkt = self._ether() / IP(src=src_ip, dst=dst_ip) / ICMP()
        return self._add_vlan(pkt, vlan) if vlan else pkt


def build_packet() -> PacketBuilder:
    return PacketBuilder()
