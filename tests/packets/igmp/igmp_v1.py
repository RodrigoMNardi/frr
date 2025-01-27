#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  igmp_v1.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

"""
IGMPv1 Packet Class

This module defines the IGMPv1 class, which represents an IGMPv1 packet. The class is built using the Scapy library and allows for the creation and manipulation of IGMPv1 packets, including the optional addition of a Router Alert field.

Classes:
    IGMPv1: Represents an IGMPv1 packet.

Usage Example:
    from scapy.all import sendp
    from igmp_v1 import IGMPv1

    # Create an IGMPv1 packet without Router Alert
    igmp_packet = IGMPv1(gaddr="224.0.0.1")
    igmp_packet.show()
"""
import struct
import argparse

from scapy.all import Packet, ByteField, IPField
from scapy.fields import XShortField, ByteEnumField, BitField
from scapy.layers.inet import IP, ICMP, IPOption, IPOption_Router_Alert
from scapy.layers.l2 import Ether
from scapy.packet import bind_layers
from scapy.sendrecv import sendp, sr1


def calculate_checksum(packet):
    if len(packet) % 2 == 1:
        packet += b'\0'
    s = sum(struct.unpack("!%dH" % (len(packet) // 2), packet))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class IGMPv1(Packet):
    """
    Represents an IGMPv1 packet.

    Attributes:
        version (4-bits): IGMP version (default is 0x1).
        type (4-bits): The type of the IGMP message (default is 0x11).
        unused (8-bits): The maximum response time (default is 0).
        checksum (int): The checksum of the packet (default is None).
        gaddr (str): The group address (default is "0.0.0.0").
        router_alert (int): The Router Alert field (default is 0x0, conditional).

    Methods:

    """

    name = "IGMPv1"
    fields_desc = [
        BitField("version", 1, 4),
        BitField("type", 0x11, 4),
        ByteField("unused", 0),
        XShortField("chksum", None),
        IPField("gaddr", "0.0.0.0")
    ]

    def __init__(self, version=1, type=0x11, unused=0, chksum=None, gaddr="0.0.0.0", src_ip="192.168.100.1", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = version
        self.type = type
        self.unused = unused
        self.chksum = chksum
        self.gaddr = gaddr
        self.src_ip = src_ip
        self.options = []

    def enable_router_alert(self):
        router_alert = IPOption_Router_Alert()
        self.options.append(router_alert)

    def post_build(self, p, pay):
        if self.chksum is None:
            chksum = calculate_checksum(p)
            p = p[:2] + struct.pack("!H", chksum) + p[4:]
        return p + pay

    def send(self, interval=0, count=1, iface="eth0"):
        bind_layers(IP, IGMPv1)

        if self.options:
            packet = Ether() / IP(dst=self.gaddr, tos=0xc0, id=0, ttl=1, src=self.src_ip, options=self.options, proto=2, frag=0) / self
        else:
            packet = Ether() / IP(dst=self.gaddr, tos=0xc0, id=0, ttl=1, src=self.src_ip, proto=2, frag=0) / self

        sendp(packet, inter=int(interval), iface=iface, count=int(count))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send an IGMPv1 packet")
    parser.add_argument("--gaddr", type=str, default="224.0.0.1", help="Group address")
    parser.add_argument("--src_ip", type=str, default="192.168.1.10", help="Source IP address")
    parser.add_argument("--type", type=lambda x: int(x, 0), default=0x11, help="Type of IGMP message")
    parser.add_argument("--enable_router_alert", action="store_true", help="Enable Router Alert option")
    parser.add_argument("--iface", type=str, default="eth0", help="Network interface to send the packet")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--interval", type=int, default=0, help="Interval between packets")

    args = parser.parse_args()

    igmp_packet = IGMPv1(gaddr=args.gaddr, src_ip=args.src_ip, type=args.type)
    if args.enable_router_alert:
        igmp_packet.enable_router_alert()
    igmp_packet.send(iface=args.iface, count=args.count, interval=args.interval)