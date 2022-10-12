#!/usr/bin/python2

"""
5. Import five.pcap and decrypt the content, creating solution-five.pcap
   * Only include the decrypted packet within solution-five.pcap

Run as a paste via ipython in pyDot11
%run ../4/pyDot11 -r ../../PCAPs/five.pcap -p password -b AA:BB:CC:DD:EE:FC -t wpa -e AES

Copy below here, use above so an editor reads this as good Python
"""

from scapy.all import *
wrpcap('final.pcap', mn.rDict.get(4)[1])
