#!/usr/bin/python2

"""
6. Import six.pcap and decrypt the content, creating solution-six.pcap
   * Only include the decrypted packet within solution-six.pcap

Run as a paste via ipython in pyDot11
%run ../4/pyDot11 -r ../../PCAPs/six.pcap -p password -b AA:BB:CC:DD:EE:FC -t wpa -e TKIP

Copy below here, use above so an editor reads this as good Python
"""

from scapy.all import *
wrpcap('final.pcap', mn.rDict.get(4)[1])
