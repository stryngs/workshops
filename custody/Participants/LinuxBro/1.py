from scapy.all import *
#import antigravity
scapy_cap = rdpcap('one.pcap')
packet = scapy_cap[0]
packet[IP].src = "192.168.100.137"
packet[Dot11].addr3="4e:40:cd:16:5a:1e"
del packet.chksum
packet.show2()
packet[Dot11].fcs = 0x5b04f068
packet1 = scapy_cap[1]
packet1[IP].dst = "192.168.100.137"
packet1[Dot11].addr3="4e:40:cd:16:5a:1e"
del packet1.chksum
packet1.show2()
packet1[Dot11].fcs = 0xd9f07cec
wrpcap("solution-one.pcap",packet,append=True)
wrpcap("solution-one.pcap",scapy_cap[1],append=True)
