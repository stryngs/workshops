from scapy.all import *
from scapy.utils import PcapWriter

cap_orig = PcapWriter("one.pcap", append=True, sync=True)
cap_mod = PcapWriter("solution-one.pcap", append=True)

packets = rdpcap('one.pcap')

# and modify each packet
for p in packets:
	#p.show2()
	# modify any packet field, e.g. IP's dst
	p[IP].src = '192.168.100.137'
	p[Dot11].addr3 = '4e:40:cd:16:5a:1e'
	# write new packets in the new pcap file
	cap_mod.write(p)
