from scapy.all import *
from scapy.utils import PcapWriter
packets = rdpcap('one.pcap')
solution = PcapWriter("solution-one.pcap", append=False)
packets[0]["IP"].src = '192.168.100.137'
packets[0]["IP"].chksum = 61498
packets[0]["Dot11FCS"].addr3 = '4e:40:cd:16:5a:1e'
packets[0]["Dot11FCS"].fcs = 1527050344
packets[1]["IP"].dst = '192.168.100.137'
packets[1]["IP"].chksum = 49492
packets[1]["Dot11FCS"].addr3 = '4e:40:cd:16:5a:1e'
packets[1]["Dot11FCS"].fcs = 3656416492
solution.write(packets)
