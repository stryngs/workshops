#!/usr/bin/python3

from scapy.all import *

allPkts = rdpcap('final.pcap')
og = rdpcap('og.pcap')
eapols = allPkts[0:4]
modPkt = allPkts[4]
mod = modPkt.payload
o = og[0]
del o.payload
wrpcap('final2.pcap', o/mod)

allPkts = rdpcap('final.pcap')
modPkts = rdpcap('final2.pcap')
og = rdpcap('og.pcap')
eapols = allPkts[0:4]
subs = eapols + modPkts
# subs = modPkts

os.remove('final.pcap')
os.remove('final2.pcap')
os.remove('og.pcap')
os.remove('handshakes.sqlite')

wrpcap('solution-eight.pcap', subs)
