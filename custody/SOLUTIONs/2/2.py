#!/usr/bin/python2

"""
2. Import two.pcap and decrypt the contents, creating solution-two.pcap
"""

# 2. Import a WEP pcap and decrypt the contents

import binascii
from pyDot11 import *
from scapy.all import *

def makeRssi(hexByte):
    return -(256 - int(hexByte, 16))

encPkts = rdpcap('../../PCAPs/two.pcap')
decPkts = []

tList = []
for enc in encPkts:
    tList.append(enc.time)

## (decPkt, iVal)
for pkt in encPkts:
    decPkts.append(wepDecrypt(pkt, keyText = '0123456789')[0])

## fix timestamp, patch into pyDot11?
finalRip = []
for i in range(len(decPkts)):
    f = decPkts[i].copy()
    f.time = tList[i]
    finalRip.append(f)

wrpcap('solution-two.pcap', finalRip)
