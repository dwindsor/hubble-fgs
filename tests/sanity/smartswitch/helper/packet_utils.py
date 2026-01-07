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
from time import sleep
from typing import List

from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer, sendp

logger = logging.getLogger(__name__)

DEFAULT_SNIFF_TIMEOUT = 1


def start_sniffers(sniffers: List[AsyncSniffer], timeout: float = DEFAULT_SNIFF_TIMEOUT) -> List[AsyncSniffer]:
    for sniffer in sniffers:
        sniffer.start()
        sleep(timeout)
    return sniffers


def stop_sniffers(sniffers: List[AsyncSniffer], timeout: float = DEFAULT_SNIFF_TIMEOUT) -> List:
    results = []
    for sniffer in sniffers:
        results.append(sniffer.stop())
        sleep(timeout)
    return results


def get_sniffer_iface(sniffer: AsyncSniffer) -> str:
    args = dict(sniffer.kwargs)
    return args.get("iface", "unknown")


def dump_sniffed_packets(sniffers: List[AsyncSniffer]):
    for sniffer in sniffers:
        iface = get_sniffer_iface(sniffer)
        logger.info(f"Sniffer on {iface} results:")
        if sniffer.results:
            logger.info(sniffer.results)


def send_packet_and_sniff(packet: Packet, sniffers: List[AsyncSniffer], send_iface: str, description: str = ""):
    start_sniffers(sniffers)
    logger.info(f"Sending packet: {description}")
    sendp(packet, iface=send_iface, verbose=False)
    stop_sniffers(sniffers)
    dump_sniffed_packets(sniffers)


def create_sniffers(ports: List[str]) -> List[AsyncSniffer]:
    if len(ports) == 1 or (len(ports) > 1 and ports[0] == ports[1]):
        return [AsyncSniffer(iface=ports[0])]
    return [AsyncSniffer(iface=port) for port in ports]
