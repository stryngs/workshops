#!/usr/bin/python2

"""
3. Modify solution-two.pcap and encrypt back to the same encryption used by two.pcap
   * Modify all packets so that the "IEEE 802.11 RSSI" column in Wireshark displays as -40 dBm
"""

import binascii
from pyDot11 import *
from scapy.all import *

# 3. Modify #2 pcap solution and encrypt back to the same WEP

encPkts = rdpcap('../../PCAPs/two.pcap')
pkts = rdpcap('../2/solution-two.pcap')

## mod RSSI (31st byte for this capture) ~~~> d8
f = hexstr(str(pkts[0]), onlyhex = 1).split(' ')
f[36] = 'd8'
pkts[0] = RadioTap(binascii.unhexlify(''.join(f)))
f = hexstr(str(pkts[1]), onlyhex = 1).split(' ')
f[36] = 'd8'
pkts[1] = RadioTap(binascii.unhexlify(''.join(f)))

## encrypt
iVals = []

## (decPkt, iVal)
for pkt in encPkts:
    iVals.append(wepDecrypt(pkt, keyText = '0123456789')[1])

## use the previous ivals
wList = []
for r in range(len(pkts)):

    # wList.append(wepEncrypt(pkts[r], keyText = '0123456789', iVal = iVals[r]))
    wList.append(wepEncrypt(pkts[r], keyText = '0123456789'))

wrpcap('solution-three.pcap', wList)
