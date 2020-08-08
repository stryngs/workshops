#!/usr/bin/python

"""
Sniff a packet at layer 3
Modify the packet
Inject the packet

View in wireshark by:
    wireshark(newPkt)
"""

from scapy.all import *

## Sniff a packet
p = sniff(iface = 'wlan0', count = 1, lfilter = lambda x: x.haslayer(TCP))

## Make a copy of the original packet
newPkt = p[0].copy()

## Change what you wish
newPkt[IP].src = '8.8.8.8'
newPkt[IP].dst = '192.168.10.100'

## Delete some checksums
del newPkt[IP].chksum
del newPkt[TCP].chksum

## Regenerate and send
newPkt = newPkt.__class__(str(newPkt))
send(newPkt)
