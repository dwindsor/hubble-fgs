from scapy.fields import BitField, XShortField
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q
from scapy.packet import Packet, bind_layers


class DPUHeaderV2(Packet):
    name="dpu_header_v2"
    fields_desc=[ BitField("opaque", 0, 8),
                 BitField("pass_bit", 0, 1),
                 BitField("dir", 0, 1),
                 BitField("l2_l3", 0, 1),
                 BitField("opaque1", 0, 5),
                 BitField("opaque2", 0, 64),
                 XShortField("etherType", 0)]

bind_layers(Dot1Q, DPUHeaderV2, type=0x8989)
bind_layers(DPUHeaderV2, IP, etherType=0x0800)
bind_layers(DPUHeaderV2, IPv6, etherType=0x86DD)