#!/usr/bin/python2

"""
4. Import four.pcap and decrypt the content, creating solution-four.pcap
   * Only include the decrypted packet within solution-four.pcap

Run as a paste via ipython in pyDot11
%run pyDot11 -r ../../PCAPs/four.pcap -p password -b AA:BB:CC:DD:EE:FC -t wpa -e TKIP

Copy below here, use above so an editor reads this as good Python
"""

from scapy.all import *
wrpcap('final.pcap', mn.rDict.get(4)[1])
