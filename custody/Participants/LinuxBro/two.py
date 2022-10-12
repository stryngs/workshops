#!/usr/bin/python2

from pyDot11 import *
from scapy.all import *
encPkts = rdpcap('two.pcap')
for i in range(0,2):
    encPkts[i].summary()
    decPkt, iVal = wepDecrypt(encPkts[i], keyText='0123456789')
    decPkt.summary()
    del decPkt[Dot11].fcs
    decPkt.show2() #show2() is best show
    wrpcap("solution-two.pcap", decPkt, append=True)

print(sys.version_info)
