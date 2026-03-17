#!/usr/bin/python3

import sys
import time
from scapy.all import *
import subprocess
from queue import Queue, Empty
from threading import Thread

"""
This lesson is an example of how to use a queue with multiple workers to gauge
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

## Namespace setup
## Numbers chosen based upon an average backpressure for the given node on a
## given nic, etc, etc, etc, etcera; with the engineer thinking ICMP flooding.
infoLevel = 30
warnLevel = infoLevel + 10
guess = 'ICMP'
threads = 10
threadSleep = .000001

def foo(bar, count, guess):
    """The parent logic where you want to benchmark your code.  In this instance
    we are using ICMP as our final filter on the guess that it is our chokepoint
    """
    if bar.haslayer(guess):
        print(' !! {0} - {1}'.format(count, bar.summary()))
    else:
        print(' -- {0} - {1}'.format(count, bar.summary()))


def snarf(q):
    """Our sniff function"""
    sniff(iface = 'lo', prn = lambda x: q.put(x), store = 0)


def sniffQueue(guess):
    q = Queue()
    sniffer = Thread(target = snarf, args = (q,))
    sniffer.daemon = True
    sniffer.start()
    spoolLaunch(q)


def spoolLaunch(q, nThread = threads):
    """Launches a spool of threads with size nThread"""
    print('spun')
    for i in range(nThread):
        worker = threading.Thread(target = threadedTask, args = (q, i))
        worker.start()
    q.join()


def threadedTask(q, i):
    """Messy printing, but somewhat we want to know its running verbose"""
    while True:
        try:
            x = q.get()
            y = q.qsize()
            if y >= infoLevel and y < warnLevel:
                print('infoLevel - Thread {0} - {1}\n'.format(i, y))
                # pass
            if y >= warnLevel:
                foo(x, y, guess)
            time.sleep(threadSleep)
        except Empty:
            pass

if __name__ == '__main__':
    sniffQueue(guess)
