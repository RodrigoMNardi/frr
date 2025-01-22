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

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../packets/igmp"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from igmp_v1 import IGMPv1

# Global variables
topo = None
intf1 = None

#####################################################
##
##   Network Topology Definition
##
#####################################################

def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, intf1

    print("----------------------------------------------")
    print("Setting up the topology...")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ospf_gr_helper.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    topo = tgen.json_topo

def build_topo(tgen):
    tgen.add_router("r1")

    # On main router
    # First switch is for a dummy interface (for local network)
    switch = tgen.add_switch("sw1")
    tgen.add_host("h1", "192.168.100.100/24", "via 192.168.100.1")

    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

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
    igmp_packet = IGMPv1(gaddr="224.0.0.1")
    igmp_packet.send(iface=intf1)

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))