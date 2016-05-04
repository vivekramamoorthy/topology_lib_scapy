# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Test suite for module topology_lib_scapy.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division
from .helpers import wait_until_interface_up


TOPOLOGY = """
# +-------+                    +-------+
# |       |     +--------+     |       |
# |scapy1 <----->  ops1  <----->scapy2 |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
[type=openswitch name="Switch 1"] ops1
# [type=host name="Host 1" image="openswitch/ubuntuscapy:latest"] scp1
# [type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] scp2
[type=host name="Host 1" image="Ubuntu"] scp1
[type=host name="Host 2" image="Ubuntu"] scp2

# Links
scp1:1 -- ops1:1
ops1:2 -- scp2:1
"""


def test_scapy(topology, step):
    ops1 = topology.get('ops1')
    scp1 = topology.get('scp1')
    scp2 = topology.get('scp2')

    assert ops1 is not None
    assert scp1 is not None
    assert scp2 is not None

    with ops1.libs.vtysh.ConfigVlan('7') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterfaceVlan('7') as ctx:
        ctx.ip_address('10.10.7.1/24')
        ctx.no_shutdown()

    step('Configure IP and bring UP switch 1 interface')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.vlan_access(7)
        ctx.no_shutdown()

    step('Configure IP and bring UP switch 2 interface')
    with ops1.libs.vtysh.ConfigInterface('2'):
        ctx.no_routing()
        ctx.vlan_access(7)
        ctx.no_shutdown()

    step('Configure host interfaces')
    scp1.libs.ip.interface('1', up=False)
    scp2.libs.ip.interface('1', up=False)
    scp1.libs.ip.interface('1', addr='10.10.7.101/24', up=True)
    scp2.libs.ip.interface('1', addr='10.10.7.102/24', up=True)

    step('Wait until interfaces are up')
    for portlbl in ['1', '2']:
        wait_until_interface_up(ops1, portlbl)

    step('Set gateway for hosts')
    scp1.libs.ip.add_route('default', '10.10.7.1')
    scp2.libs.ip.add_route('default', '10.10.7.1')

    step('Send ping')
    ping = scp1.libs.ping.ping(5, '10.10.7.1')
    assert ping['received'] >= 1

    step('Start scapy on host workstations')
    scp1.libs.scapy.start_scapy()
    scp2.libs.scapy.start_scapy()

    step('Create packets')
    ip_packet = scp1.libs.scapy.ip("dst='10.10.7.102', src='10.10.7.101'")
    icmp_packet = scp1.libs.scapy.icmp()
    arp_packet = scp1.libs.scapy.arp("pdst='10.10.7.101'")
    ether_packet = scp1.libs.scapy.ether()
    dot1qpack = scp1.libs.scapy.dot1q()

    dot1qpack['vlan'] = 10
    dot1qpack['prio'] = 1

    ether_packet['dst'] = '00:50:56:96:fa:f3'

    step('Send the packet')
    output = scp1.libs.scapy.sr1('IP/ICMP', [ip_packet, icmp_packet])
    output1 = scp1.libs.scapy.summary()
    output2 = scp2.libs.scapy.sr1('ARP', [arp_packet])
    output = scp1.libs.scapy.sr1('IP/ICMP', [ip_packet, icmp_packet])
    output3 = scp1.libs.scapy.sendp('Eth/Dot1Q', [ether_packet, dot1qpack])

    step('Exit Scapy')
    scp1.libs.scapy.exit_scapy()
    scp2.libs.scapy.exit_scapy()

    # A parser is yet to be implemented to return a dictionary for results
    step('Just printing out the results.show() for now.')
    print(output)
    step('Just printing out the results.summary() for now.')
    print(output1)
    print(output2)
    print(output3)

    step('Send ping again')
    ping = scp1.libs.ping.ping(5, '10.10.7.1')
    assert ping['received'] >= 1
