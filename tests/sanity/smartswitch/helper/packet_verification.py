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
from typing import List

from scapy.packet import Packet, Padding
from scapy.sendrecv import AsyncSniffer

logger = logging.getLogger(__name__)


def layer_count_no_padding(packet: Packet) -> int:
    if packet.haslayer(Padding):
        return len(packet.layers()) - 1
    return len(packet.layers())


def packets_match(sniffed: Packet, expected: Packet) -> bool:
    if layer_count_no_padding(expected) != layer_count_no_padding(sniffed):
        return False
    for index, layer in enumerate(expected.layers()):
        if layer != sniffed.layers()[index]:
            return False
    for field in expected.fields:
        if expected.getfieldval(field) != sniffed.getfieldval(field):
            return False
    return True


def find_matching_packets(sniffers: List[AsyncSniffer], expected: Packet) -> List[Packet]:
    matches = []
    for sniffer in sniffers:
        if sniffer.results is not None:
            matches.extend(sniffer.results.filter(lambda sniffed: packets_match(sniffed, expected)))
    return matches


def verify_packet_processed(sniffers: List[AsyncSniffer], expected: Packet, is_transmitted: bool) -> bool:
    matches = find_matching_packets(sniffers, expected)
    if is_transmitted:
        logger.info(f"Found {len(matches)} matching packets (expected: 2 for forwarded)")
        return len(matches) == 2
    else:
        logger.info(f"Found {len(matches)} matching packets (expected: 0 or 1 for dropped)")
        return len(matches) <= 1
