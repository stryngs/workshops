#!/usr/bin/python2

"""
Grab bluetooth packets from an ubertooth, drop into scapy and do something...

mkfifo is SLOW! >> dont do this prior to running ubettooth-btle:
    mkfifo /tmp/bluesPipe

ubertooth-btle -f -q /tmp/bluesPipe
"""
import time
s = time.time() ## stupid timer
import sqlite3 as lite
from scapy.all import *

def dbPrep():
    """Connect and prep the db"""
    sqlName ='teeth.sqlite3'
    dbName = 'bt'
    # con = lite.connect(sqlName, isolation_level = None)     ## Isolate == AutoCommit >> May cause speed issue ##
    con = lite.connect(sqlName)     ## Isolate == AutoCommit >> May cause speed issue
    db = con.cursor()

    ## sqlite3 table create
    db.execute("""
               CREATE TABLE IF NOT EXISTS {0}(tstamp TEXT,
                                              mac TEXT,
                                              signal INTEGER,
                                              noise INTEGER);
               """.format(dbName))
    return (con, db, dbName)


def onlyCare():
    """Only load parser for what we care about"""
    q=[scapy.layers.bluetooth4LE.BTLE,
       scapy.layers.bluetooth4LE.BTLE_RF,
       scapy.layers.bluetooth4LE.BTLE_ADV,
       scapy.layers.bluetooth4LE.EIR_Hdr,
       scapy.layers.bluetooth4LE.BTLE_ADV_NONCONN_IND]
    conf.layers.filter(q)


def pFilter(dbName):
    def snarf(packet):
        global count
        if packet.haslayer(BTLE_ADV_NONCONN_IND):
            tNow = time.localtime()
            lDate = time.strftime('%Y-%m-%d', tNow)
            lTime = time.strftime('%H:%M:%S', tNow)
            tStamp = str(lDate) + ' ' + str(lTime) + '-05'
            try:
                tMac = packet[BTLE_ADV_NONCONN_IND].AdvA
                pSignal = packet[BTLE_RF].signal
                pNoise = packet[BTLE_RF].noise

                ## sqlite3 table INSERT
                print(tStamp,tMac,pSignal,pNoise)
                db.execute("""
                           INSERT INTO `{0}` VALUES(?,
                                                    ?,
                                                    ?,
                                                    ?);
                           """.format(dbName), (str(lDate) + ' ' + str(lTime) + '-05',
                                                tMac,
                                                pSignal,
                                                pNoise))
            except Exception as E:
                print(E)
        count += 1
    return snarf

if __name__ == '__main__':
    ## Do some filtering to ignore parsing we don't need
    onlyCare()

    ## Connect to the db
    con, db, dbName = dbPrep()

    ## Sniff!
    count = 0
    PRN = pFilter(dbName)
    p = sniff(offline = '/tmp/bluesPipe', prn = PRN)
    t = time.time() - s
    con.commit()
    con.close()

    ## stats
    print('Total time: {0}'.format(t))
    print('Packets processed: {0}'.format(count))
    print('Packets per second: {0}'.format(count / t))
