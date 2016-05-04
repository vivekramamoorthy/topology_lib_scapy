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
topology_lib_scapy communication library implementation.

"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division
import re


# Returns a protocol dictionary with fields as keys. Values can be populated.
def protocol(result, key_values=None):
    prot = {}
    for line in result.splitlines():
        re_protocol = r'\s*###\[\s+(.+)\s+\]###'
        re_info = r'(\s*)(.+)(\s*=\s*)(.*)'
        # Match first line for protocol. eg: ###[ IP ]###
        result = re.match(re_protocol, line)
        if result:
            prot['prot'] = result.group(1)
        # Match packet info. eg: src='some value'
        result = re.match(re_info, line)
        if result:
            prot[result.group(2)] = None

    if key_values is None:
        return prot
    else:
        key_val = key_values.split(", ")
        for item in key_val:
            # If value is a string eg: src='1.1.1.1'
            result = re.match(r'(\s*)(\w+)(=\s*\')(.*)(\')', item)
            if result:
                if result.group(2) in prot.keys():
                    prot[result.group(2)] = result.group(4)
            # If value is int or hex eg: dport=179
            result = re.match(r'(\s*)(\w+)(=)([^\'\s\[]().*)', item)
            if result:
                if result.group(2) in prot.keys():
                    # If value is hex eg: type=0x9000
                    if re.match(r'0[xX][0-9a-fA-F]+', result.group(4)):
                        prot[result.group(2)] = int(result.group(4), 16)
                    else:
                        prot[result.group(2)] = int(result.group(4))
            # If value is list eg: dport=[1,2,3,(5,10)]
            result = re.match(r'(\s*)(\w+)(=)(\[.*\])', item)
            if result:
                if result.group(2) in prot.keys():
                    prot[result.group(2)] = eval(result.group(4))

        return prot


# Generates command line string to send to scapy prompt
def createcdmline(packet, packet_struct, packet_list, options):

    pkt_struct = packet_struct.split("/")
    for pkt_type in pkt_struct:
        # Match ethernet packet
        if re.match(r'\s*eth\w*', pkt_type, re.IGNORECASE):
            packet = packet + "Ether("
            packet = get_pkt_optns(r'\s*eth\w*', packet, packet_list)
        # Match IP packet
        elif re.match(r'\s*ip', pkt_type, re.IGNORECASE):
            packet = packet + "IP("
            packet = get_pkt_optns(r'\s*ip\w*', packet, packet_list)
        # Match TCP packet
        elif re.match(r'\s*tcp', pkt_type, re.IGNORECASE):
            packet = packet + "TCP("
            packet = get_pkt_optns(r'\s*tcp\w*', packet, packet_list)
        # Match ARP packet
        elif re.match(r'\s*arp', pkt_type, re.IGNORECASE):
            packet = packet + "ARP("
            packet = get_pkt_optns(r'\s*arp\w*', packet, packet_list)
        # Match UDP packet
        elif re.match(r'\s*udp', pkt_type, re.IGNORECASE):
            packet = packet + "UDP("
            packet = get_pkt_optns(r'\s*udp\w*', packet, packet_list)
        # Match ICMP packet
        elif re.match(r'\s*icmp', pkt_type, re.IGNORECASE):
            packet = packet + "ICMP("
            packet = get_pkt_optns(r'\s*icmp\w*', packet, packet_list)
        # Match DOT1Q packet
        elif re.match(r'\s*dot1q', pkt_type, re.IGNORECASE):
            packet = packet + "Dot1Q("
            packet = get_pkt_optns(r'\s*802.1Q\w*', packet, packet_list)

    # If options are provided, include them.
    if options is None:
        cmdline = packet[:-1] + ")"
        return cmdline
    else:
        cmdline = packet[:-1] + ", " + options + ")"
        return cmdline


# Read list of packet protocols and populate the options
def get_pkt_optns(proto_re, packet, packet_list):
    test_packet = packet[:]
    for protocol in packet_list:
        # For each protocol in list, match the prot type
        if re.match(proto_re, protocol['prot'], re.IGNORECASE):
            for key, val in protocol.items():
                # Create packet string from key, value pair.
                if key == 'prot':
                    continue
                elif val is None:
                    continue
                else:
                    if type(val) == int:
                        packet = packet + key + "=" + str(val) + ", "
                    elif type(val) == list:
                        packet = packet + key + "=" + str(val) + ", "
                    else:
                        packet = packet + key + "=" + "'" + str(val) + "', "
            # Trim last two characters and concatenate ")/"
            if test_packet == packet:
                packet = packet + ")/"
            else:
                packet = packet[:-2] + ")/"
    return packet
