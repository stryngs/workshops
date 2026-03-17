#!/usr/bin/python3

import binascii
from scapy.all import *

"""
bssid  aa:bb:cc:dd:ee:ff
src    11:22:33:44:55:66
dst    00:11:22:33:44:55
"""

## Load a PCAP
pkts = rdpcap('demo.pcap')
initLoadA = pkts[0].copy()

## String and verify
theLoad = hexstr(initLoadA, onlyhex = 1).replace(' ', '')

## Not because we had to, but because we could; hex is our friend
initLoad = '000038002F4040A0200800A020080000C1C5F8CA0000000000168509A000E8000000000000000000C1C5F8CA0000000000000101DE00E8018801D500AABBCCDDEEFFFFEEDDCCBBAA001122334455F02E0000AAAA030000000800450000549BC440004001C69BC0A82B8EC0A82B6A0800B4FE0005000123A8AF6900000000A4160D0000000000101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637'
print(theLoad == initLoad)

## Back to a scapy object you go
x = RadioTap(binascii.unhexlify(initLoad))

## From
x.FCfield = 2
x.dst = '192.168.43.103'
x.src = '192.168.43.146'
x.addr1 = '00:11:22:33:44:55'
x.addr2 = 'aa:bb:cc:dd:ee:ff'
x.addr3 = '11:22:33:44:55:66'
x.load = b'    From-DS'
del x[IP].chksum
del x[IP].len
del x[ICMP].chksum

## To
y = x.copy()
y.FCfield = 1
y.addr1 = 'aa:bb:cc:dd:ee:ff'
y.addr2 = '11:22:33:44:55:66'
y.addr3 = '00:11:22:33:44:55'
y.load = b'    To-DS'
del y[IP].chksum
del y[IP].len
del y[ICMP].chksum

## Pass the tests
fPkt = x.__class__(binascii.unhexlify(hexstr(x, onlyhex = 1).replace(' ', '')))
tPkt = y.__class__(binascii.unhexlify(hexstr(y, onlyhex = 1).replace(' ', '')))

## Send it
sendp(tPkt, iface = 'wlan1mon')
sendp(fPkt, iface = 'wlan1mon')
