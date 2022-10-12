#!/usr/bin/python3

mn = None
"""
9. Modify solution-seven.pcap and encrypt back to the same encryption used by seven.pcap

Run as a paste via ipython in pyDot11
%run ../4/pyDot11 -r ../../PCAPs/seven.pcap -p password -b AA:BB:CC:DD:EE:FC -t wpa -e AES

Copy below here, use above so an editor reads this as good Python
"""

from scapy.all import *

### Encryption shortcut
hList = []

for k, v in mn.rDict.items():
    if v[1] is not None:

        ourObj = v[1]
        del ourObj[IP].chksum
        del ourObj[IP].len
        del ourObj[TCP].chksum
        ourObj = ourObj.__class__(str(v[1]))

        encPkt = wpaEncrypt(mn.shake.tgtInfo.get('00:c0:ca:83:1c:0b')[1], v[0], ourObj, v[2], False)

        ## Revert timestamps here
        xOrig = v[0].copy()
        del xOrig.payload

        cPkt = encPkt.copy()

        modCopy = xOrig/cPkt.payload

        wrpcap('c.pcap', modCopy)
        pkts = rdpcap('c.pcap')
        modCopy2 = pkts[0]



        finalCopy = modCopy2.__class__(str(modCopy2))


        wrpcap('og.pcap', v[0])
        hList.append((v[0], finalCopy))

x = []
x.append(mn.rDict.get(0)[0])
x.append(mn.rDict.get(1)[0])
x.append(mn.rDict.get(2)[0])
x.append(mn.rDict.get(3)[0])
x.append(hList[0][1])

wrpcap('a.pcap', x[0:4])
wrpcap('b.pcap', x[4])

p1 = rdpcap('a.pcap')
p2 = rdpcap('b.pcap')
p3 = p1 + p2

os.remove('a.pcap')
os.remove('b.pcap')
os.remove('c.pcap')

wrpcap('final.pcap', p3)
"""
Scapy interprets our work as Raw.  The __class__ mod doesn't fix it.  Only workaround is to rdpcap()
"""

"""
https://www.wireshark.org/lists/wireshark-users/200805/msg00206.html
When downloading a big file from the server, initially the info in the list column of wireshark sound reasonable. However, as the downloading process ends(using totally about 60 secs), the time stamp in wireshark console just passed 30 secs. And in the next 60-30=30 secs, only "TCP segment of a reassembled PDU" is shown in the list column, while the detail info of each these packets are still reasonable. Then 2 questions:
1.what does "TCP segment of a reassembled PDU" mean?
It means that Wireshark thinks the packet in question contains part of a packet (PDU - "Protocol Data Unit") for a protocol that runs on top of TCP.
If the reassembly is successful, the TCP segment containing the last part of the packet will show the packet.
The reassembly might fail if some TCP segments are missing.

2.If i do not want to see "TCP segment of a reassembled PDU", how can i view the correct info just as those in the first "30 secs"?
Turn off TCP reassembly in the preferences for TCP.


This should absolutely be a conditional for this challenge
"""


# os.system('mergecap -w c.pcap a.pcap b.pcap')
# pkts = rdpcap('c.pcap')
## bah use scapy as a workaround for right now.

## was tcp......
