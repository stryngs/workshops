#!/usr/bin/python3

import binascii
from scapy.all import *

allPkts = rdpcap('../../PCAPs/seven.pcap')
decPkt = rdpcap('final.pcap')
dec = decPkt[0].payload

hdr = allPkts[4]
del hdr.payload

ourObj = hdr/dec
del ourObj[IP].chksum
del ourObj[IP].len
del ourObj[TCP].chksum
# del ourObj[Padding] << This is the FCS prob, visible in bytes after accept
finalPkt = ourObj.__class__(binascii.unhexlify(hexstr(ourObj, onlyhex = 1).replace(' ', '')))
wrpcap('solution-seven.pcap', finalPkt)

os.remove('final.pcap')
os.remove('handshakes.sqlite')
