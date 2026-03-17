#!/usr/bin/python3

import sys
import time
from scapy.all import *
import subprocess
from queue import Queue, Empty
from threading import Thread

"""
This lesson is an example of how to use a queue with a single worker to gauge
backpressure and how fast your given logic is working under a certain set of
circumstances; giving you a benchmark in the process.

Ideally the logic you have created allows for scapy to keep up with a 1:1 ratio.
Depending on the medium you are sniffing results will vary.

As this logic adds cycles to a loop, do not add this to your logic without
accounting for the fact that something like this adds to the time it can take to
process a frame or packet; monitoring then becomes a tradeoff, but very useful.

To envision where you would use something like this take a look at sniffQueue(),
under the while loop you see a q.get(); q is the frame or packet from the sniff.

As root set off a couple of shells where you run a ping flood against lo:
ping 127.0.0.1 -f
"""

## Numbers chosen based upon an average backpressure for the given node on a
## given nic, etc, etc, etc, etcera; with the engineer thinking ICMP flooding.
infoLevel = 10
warnLevel = infoLevel + 10
guess = 'ICMP'

def foo(bar):
    """The parent logic where you want to benchmark your code.  In this instance
    we are using ICMP as our final filter on the guess that it is our chokepoint
    """
    if bar.haslayer(guess):
        print(' !! ' + bar.summary())
    else:
        print(' -- ' + bar.summary())

def snarf(q):
    """Our sniff function"""
    sniff(iface = 'lo', prn = lambda x: q.put(x), store = 0)


def sniffQueue():
    q = Queue()
    sniffer = Thread(target = snarf, args = (q,))
    sniffer.daemon = True
    sniffer.start()
    while True:
        try:
            y = q.qsize()
            x = q.get()
            if y >= infoLevel:
                print(y)
            if y >= warnLevel:
                foo(x)
            q.task_done()
        except Empty:
            pass

if __name__ == '__main__':
    sniffQueue()
