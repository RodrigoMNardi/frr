#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  mld_v1_router_alert.py
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
sys.path.append(os.path.join(CWD, "../../packets/mld"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger, get_test_logdir

#####################################################
##
##   Network Topology Definition
##
#####################################################

HOST_IP = "2001:db8::abc"
GADDR = 'ff02::a1'
GADDR_RA = 'ff02::b2'
GADDR_RA_ENABLED = "ff02::c3"

def build_topo(tgen):
    router = tgen.add_router("r1")

    tgen.add_host("h1", f"{HOST_IP}/64", "via 2001:db8::1")

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

def test_send_mld_v1_without_router_alert():
    """Send MLDv1 packet without Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    output = tgen.gears['r1'].vtysh_cmd("show ipv6 mld groups")

    assert GADDR not in output, f"Expected {GADDR} to be in the output"

    link_local = fetch_link_local('r1-eth0', 1)

    logger.info("Sending MLDv1 packet without Router Alert")
    cmd = f"--src_ip {link_local} --dst_ip {link_local} --gaddr {GADDR} --iface 'h1-eth0' --count 3 --type 0x83"

    logger.info(cmd)

    tgen.gears["h1"].run(f"python {CWD}/../../packets/mld/mld_v1.py {cmd}")

    sleep(1)

    logger.info(tgen.gears['r1'].vtysh_cmd("show run"))

    output = tgen.gears['r1'].vtysh_cmd("show ipv6 mld groups")

    logger.info(output)

    assert GADDR in output, f"Expected {GADDR} to be in the output"

    logger.info(output)

def test_send_mld_v1_with_router_alert():
    """Send MLDv1 packet with Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    output = tgen.gears['r1'].vtysh_cmd("show ipv6 mld groups")

    assert GADDR_RA not in output, f"Expected {GADDR_RA} to be in the output"

    link_local = fetch_link_local('r1-eth0', 1)

    logger.info("Sending MLDv1 packet without Router Alert")

    cmd = (f"--src_ip {link_local} --dst_ip {link_local} --gaddr {GADDR_RA} "
           f"--iface 'h1-eth0' --count 3 --type 0x83 --enable_router_alert")

    tgen.gears["h1"].run(f"python {CWD}/../../packets/mld/mld_v1.py {cmd}")

    sleep(3)

    output = tgen.gears['r1'].vtysh_cmd("show ipv6 mld groups")

    assert GADDR_RA in output, f"Expected {GADDR_RA} to be in the output"

    logger.info(output)

def test_mld_v1_interface_router_alert_packet_without_router_alert():
    """Send MLDv1 packet without Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    enable_ra = " ipv6 mld require-router-alert"

    output = tgen.gears['r1'].vtysh_cmd (f"conf t\ninterface r1-eth0\n{enable_ra}")

    assert GADDR_RA_ENABLED not in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

    output = tgen.gears['r1'].vtysh_cmd("show run")

    assert enable_ra in output, f"Expected ' ipv6 mld require-router-alert' to be in the output"

    link_local = fetch_link_local('r1-eth0', 1)

    logger.info("Sending MLDv1 packet without Router Alert")
    cmd = (f"--src_ip {link_local} --dst_ip {link_local} --gaddr {GADDR_RA_ENABLED} "
           f"--iface 'h1-eth0' --count 3 --type 0x83")
    tgen.gears["h1"].run(f"python {CWD}/../../packets/mld/mld_v1.py {cmd}")

    sleep(3)

    output = tgen.gears['r1'].vtysh_cmd("show ipv6 mld groups")

    assert GADDR_RA_ENABLED not in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

    logger.info(output)

def test_mld_v1_interface_router_alert_packet_with_router_alert():
    """Send MLDv1 packet without Router Alert"""

    tgen = get_topogen()

    enable_debugging()

    enable_ra = " ipv6 mld require-router-alert"

    output = tgen.gears['r1'].vtysh_cmd (f"conf t\ninterface r1-eth0\n{enable_ra}")

    assert GADDR_RA_ENABLED not in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

    output = tgen.gears['r1'].vtysh_cmd("show run")

    assert enable_ra in output, f"Expected ' ipv6 mld require-router-alert' to be in the output"

    link_local = fetch_link_local('r1-eth0', 1)

    logger.info("Sending MLDv1 packet without Router Alert")
    cmd = (f"--src_ip {link_local} --dst_ip {link_local} --gaddr {GADDR_RA_ENABLED} "
           f"--iface 'h1-eth0' --count 3 --type 0x83 --enable_router_alert")
    tgen.gears["h1"].run(f"python {CWD}/../../packets/mld/mld_v1.py {cmd}")

    sleep(3)

    logger.info("MLDv1 packet sent successfully")

    output = tgen.gears['r1'].vtysh_cmd("show ipv6 mld groups")

    assert GADDR_RA_ENABLED in output, f"Expected {GADDR_RA_ENABLED} to be in the output"

    logger.info(output)

def enable_debugging():
    tgen = get_topogen()
    tgen.gears['r1'].vtysh_cmd("debug mld")
    tgen.gears['r1'].vtysh_cmd("debug pim")

def fetch_link_local(interface, index):
    tgen = get_topogen()

    sleep(5) # Without this sleep the interface does not appear during the test flow

    output = tgen.gears['r1'].vtysh_cmd(f"show interface {interface} json", True)
    addresses = output[interface]['ipAddresses']

    link_local_address = next((addr['address'] for addr in addresses if addr['address'].startswith('fe80')), None)

    return link_local_address.split("/")[0]


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))