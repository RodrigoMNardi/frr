#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  igmp_v1_without_router_alert.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

import os
import sys
from itertools import count
from time import sleep

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../packets/igmp"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger, get_test_logdir
from igmp_v1 import IGMPv1

#####################################################
##
##   Network Topology Definition
##
#####################################################

HOST_IP = "192.168.1.10"

def build_topo(tgen):
    router = tgen.add_router("r1")

    tgen.add_host("h1", f"{HOST_IP}/24", "via 192.168.1.1")

    router.add_link(tgen.gears["h1"])

#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    """Setup topology"""
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    tgen.start_router()

def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def test_send_igmp_v1():
    """Send IGMPv1 packet without Router Alert"""

    # Create an IGMPv1 packet without Router Alert

    tgen = get_topogen()

    tgen.gears['r1'].vtysh_cmd("debug igmp")
    tgen.gears['r1'].vtysh_cmd("debug pim")

    host_obj, interface_name = tgen.gears["r1"].links['r1-eth0']

    logger.info(tgen.gears['r1'].vtysh_cmd("show interfaces"))
    logger.info(get_test_logdir())

    logger.info("Sending IGMPv1 packet without Router Alert")
    igmp_packet = IGMPv1(gaddr="224.1.3.2", type=0x12, src_ip=HOST_IP)
    igmp_packet.enable_router_alert()

    sleep(40)

    igmp_packet.send(iface=interface_name.split("-")[1], count=5)
    logger.info("IGMPv1 packet sent successfully")

    logger.info(tgen.gears['r1'].vtysh_cmd("show ip igmp groups"))
    logger.info(tgen.gears['r1'].vtysh_cmd("show ip igmp join"))

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))