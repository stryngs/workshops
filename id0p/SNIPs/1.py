#!/usr/bin/python

from scapy.all import *

"""
This lesson is an intro into the sniff method.  Using the below framework,
modify the following three parameters:
    - prn
    - lfilter
    - filter

When experimenting, play with line 48 and include||exclude them.  Ensure you
have a good grasp on how they interact before moving to the next module.
"""

def lFilter(ourFilter):
    """
    lfilter in sniff()

    Runs if filter non-existent || filter matches.
    lfilter iruns prior to prn for each packet/frame.
    Same functionalities as prn.
    Acts as a gatekeeper to prn.
    return True for prn to run.
    """
    def snarf(packet):
        print('\n lFilter fired')
        if packet.haslayer(ourFilter):
            print(' ## {0}'.format(ourFilter))
            return True
    return snarf

def pFilter(ourFilter):
    """
    prn in sniff()

    Runs if lfilter non-existent || lfilter returns True.
    """
    def snarf(packet):
        print('\n pFilter fired')
        print(packet.summary())
    return snarf

if __name__ == '__main__':
    LFILTER = lFilter('ICMP')
    PRN = pFilter('ICMP')
    bpF = 'icmp'
    p = sniff(iface = 'wlan0', prn = PRN, lfilter = LFILTER, filter = bpF)
