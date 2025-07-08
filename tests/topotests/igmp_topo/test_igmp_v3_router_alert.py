#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  igmp_v3_router_alert.py
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
from igmp_v3 import IGMPv3

#####################################################
##
##   Network Topology Definition
##
#####################################################

HOST_IP = "192.168.1.10"
GADDR = '224.3.2.1'
GADDR_RA = '224.6.5.4'
GADDR_RA_ENABLED = "224.9.8.7"
GADDR_A = '224.9.0.1'
GADDR_B = '224.9.0.2'
MADDR = '224.0.1.24'
MADDR_A = '224.0.1.25'

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

def test_send_igmp_v3_without_router_alert():
    """Send IGMPv3 packet without Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    assert GADDR not in output, f"Expected {GADDR} to be in the output"

    logger.info("Sending IGMPv3 packet without Router Alert")
    cmd = f"--src_ip {HOST_IP} --record {GADDR} --maddr {MADDR} --type 0x22 --rtype 5 --iface 'h1-eth0' --count 3 "

    logger.info(f"python {CWD}/../../packets/igmp/igmp_v3.py {cmd}")

    tgen.gears["h1"].run(f"python {CWD}/../../packets/igmp/igmp_v3.py {cmd}")

    sleep(3)

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    logger.info(output)
    logger.info(tgen.gears['r1'].vtysh_cmd("show ip igmp groups"))

    assert GADDR in output, f"Expected {GADDR} to be in the output"

def test_send_igmp_v3_with_router_alert():
    """Send IGMPv3 packet with Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    assert GADDR_RA not in output, f"Expected {GADDR_RA} to be in the output"

    logger.info("Sending IGMPv3 packet without Router Alert")
    cmd = (f"--src_ip {HOST_IP} --record {GADDR_RA} --iface 'h1-eth0' --maddr {MADDR} "
           f"--count 3 --type 0x22 --rtype 1 --enable_router_alert")
    tgen.gears["h1"].run(f"python {CWD}/../../packets/igmp/igmp_v3.py {cmd}")

    sleep(3)

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    assert GADDR_RA in output, f"Expected {GADDR_RA} to be in the output"

def test_igmp_v3_interface_router_alert_packet_without_router_alert():
    """Send IGMPv3 packet without Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    enable_ra = "ip igmp require-router-alert"

    output = tgen.gears['r1'].vtysh_cmd (f"conf t\ninterface r1-eth0\n{enable_ra}")

    assert GADDR_RA_ENABLED not in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

    output = tgen.gears['r1'].vtysh_cmd("show run")

    assert enable_ra in output, f"Expected 'ip igmp require-router-alert' to be in the output"

    logger.info("Sending IGMPv3 packet without Router Alert")
    cmd = (f"--src_ip {HOST_IP} --record {GADDR_RA_ENABLED}  --maddr {MADDR} "
           f"--iface 'h1-eth0' --count 3 --type 0x22 --rtype 1")
    tgen.gears["h1"].run(f"python {CWD}/../../packets/igmp/igmp_v3.py {cmd}")

    sleep(3)

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    assert GADDR_RA_ENABLED not in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

def test_igmp_v3_interface_router_alert_packet_with_router_alert():
    """Send IGMPv3 packet without Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    enable_ra = "ip igmp require-router-alert"

    output = tgen.gears['r1'].vtysh_cmd (f"conf t\ninterface r1-eth0\n{enable_ra}")

    assert GADDR_RA_ENABLED not in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

    output = tgen.gears['r1'].vtysh_cmd("show run")

    assert enable_ra in output, f"Expected 'ip igmp require-router-alert' to be in the output"

    logger.info("Sending IGMPv3 packet without Router Alert")
    cmd = (f"--src_ip {HOST_IP} --record {GADDR_RA_ENABLED} --maddr {MADDR} "
           f"--iface 'h1-eth0' --count 3 --type 0x22 --rtype 1 --enable_router_alert")
    tgen.gears["h1"].run(f"python {CWD}/../../packets/igmp/igmp_v3.py {cmd}")

    sleep(3)

    logger.info("IGMPv3 packet sent successfully")

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    assert GADDR_RA_ENABLED in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

def test_igmp_v3_interface_router_alert_packet_with_router_alert_and_multiple_groups():
    """Send IGMPv3 packet with Router Alert and multiple groups"""

    tgen = get_topogen()

    enable_debugging()

    enable_ra = "ip igmp require-router-alert"

    output = tgen.gears['r1'].vtysh_cmd (f"conf t\ninterface r1-eth0\n{enable_ra}")

    assert GADDR_A not in output, f"Expected {GADDR_A} to be in the output"
    assert GADDR_B not in output, f"Expected {GADDR_B} to be in the output"

    output = tgen.gears['r1'].vtysh_cmd("show run")

    assert enable_ra in output, f"Expected 'ip igmp require-router-alert' to be in the output"

    logger.info("Sending IGMPv3 packet without Router Alert")
    cmd = (f"--src_ip {HOST_IP} --record {GADDR_A} --record {GADDR_B} --maddr {MADDR} --maddr {MADDR_A} "
           f"--iface 'h1-eth0' --count 3 --type 0x22 --rtype 1 --enable_router_alert")
    tgen.gears["h1"].run(f"python {CWD}/../../packets/igmp/igmp_v3.py {cmd}")

    sleep(3)

    logger.info("IGMPv3 packet sent successfully")

    output = tgen.gears['r1'].vtysh_cmd("show ip igmp sources")

    assert GADDR_RA_ENABLED in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

def enable_debugging():
    tgen = get_topogen()
    tgen.gears['r1'].vtysh_cmd("debug igmp")
    tgen.gears['r1'].vtysh_cmd("debug pim")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))