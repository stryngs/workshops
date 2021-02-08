#!/usr/bin/python3

"""
The point of this module will be to detect potentially malicious ARP traffic

For our initial detects, we will go with anything below, not hashed
In [13]: f.show()
###[ Ethernet ]### 
#  dst       = aa:bb:cc:dd:ee:ff
#  src       = 11:22:33:44:55:66
#  type      = ARP
###[ ARP ]### 
#     hwtype    = 0x1
     ptype     = IPv4
#     hwlen     = 6
     plen      = 4
     op        = is-at
#     hwsrc     = 11:22:33:44:55:66
#     psrc      = 192.168.200.1
#     hwdst     = aa:bb:cc:dd:ee:ff
#     pdst      = 192.168.200.254
"""

from scapy.all import *

class Arper(object):

    def __init__(self, pHandler):
        print("Arper module loaded and running")
        
        self.pHandler = pHandler


    def sniffer(self):
        self.p = sniff(iface = 'wlan0', prn = self.pHandler, filter = 'arp')


def pFilter():
    """
    prn in sniff()

    Runs if lfilter non-existent || lfilter returns True.
    
    
     ptype     = IPv4
     plen      = 4
     op        = is-at
    """
    def snarf(packet):
        
        ## filter 1
        if packet[ARP].ptype == 2048:
            
            ## filter 2
            if packet[ARP].plen == 4:
                
                ## filter 3
                if packet[ARP].op == 2:
                    
                    ## Inform the user
                    attacker = packet[Ether].src
                    attackerIP = packet[Ether].psrc
                    print('{0} - {1}'.format(attacker, attackerIP))
    return snarf


if __name__ == '__main__':
    
    ## get our packet handler
    pHandler = pFilter()
    
    ## Instantiate Arper and throw our handler into the mix
    aa = Arper(pHandler)
    
    ## All the things
    aa.sniffer()
