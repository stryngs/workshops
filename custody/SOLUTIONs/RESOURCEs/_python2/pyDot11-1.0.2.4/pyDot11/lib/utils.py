from scapy.utils import hexstr, rdpcap, wrpcap
from scapy.plist import PacketList
from zlib import crc32
import binascii, pyDot11

class Pcap(object):
    """Class to deal with pcap specific tasks"""

    def crypt2plain(self, pcapFile, key):
        """Converts an encrypted pcap to unencrypted pcap
        Returns the unencrypted pcap input as a scapy PacketList object
        """
        pcapList = []
        pObj = rdpcap(pcapFile)
        for i in range(len(pObj)):
            try:
                pkt, iv = pyDot11.wepDecrypt(pObj[i], key)
            except:
                pkt = pObj[i].copy()

            pcapList.append(pkt)

        title = pcapFile.replace('.pcap', '_decrypted.pcap')
        wrpcap(title, pcapList)
        print 'Decrypted pcap written to: %s' % title

        packetList = PacketList(res = pcapList)
        return packetList


class Packet(object):
    """Class to deal with packet specific tasks"""

    def __init__(self):
        self.nonceDict = {'8a': 'a1',
                          '0a': 'a2',
                          'ca': 'a3',
                          '89': 't1',
                          '09': 't2',
                          'c9': 't3'}


    def byteRip(self, stream, chop = False, compress = False, order = 'first', output = 'hex', qty = 1):
        """Take a scapy hexstr(str(pkt), onlyhex = 1) and grab based on what you want

        chop is the concept of removing the qty based upon the order
        compress is the concept of removing unwanted spaces
        order is concept of give me first <qty> bytes or gives me last <qty> bytes
        output deals with how the user wishes the stream to be returned
        qty is how many nibbles to deal with

        QTY IS DOUBLE THE NUMBER OF BYTES
        THINK OF QTY AS A NIBBLE
        2 NIBBLES FOR EVERY BYTE

        Important to note that moving to a pure string versus a list,
        will probably help with memory consumption

        Eventually, need to add a kwarg that allows us to specify,
        which bytes we want, i.e. first and last based on order
        """
        def pktFlow(pkt, output):
            if output == 'hex':
                return pkt
            if output == 'str':
                return binascii.unhexlify(str(pkt).replace(' ', ''))

        stream = hexstr(str(stream), onlyhex = 1)
        streamList = stream.split(' ')
        streamLen = len(streamList)

        ## Deal with first bytes
        if order == 'first':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[0:qty]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[qty:]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[0:qty]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[qty:]).replace(' ', ''), output)

        ## Deal with last bytes
        if order == 'last':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[streamLen - qty:]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[:-qty]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[streamLen - qty:]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[:-qty]).replace(' ', ''), output)


    def endSwap(self, value):
        """Takes an object and reverse Endians the bytes

        Useful for crc32 within 802.11:
        Autodetection logic built in for the following situations:
        Will take the stryng '0xaabbcc' and return string '0xccbbaa'
        Will take the integer 12345 and return integer 14640
        Will take the bytestream string of 'aabbcc' and return string 'ccbbaa'
        """
        try:
            value = hex(value).replace('0x', '')
            sType = 'int'
        except:
            if '0x' in value:
                sType = 'hStr'
            else:
                sType = 'bStr'
            value = value.replace('0x', '')

        start = 0
        end = 2
        swapList = []
        for i in range(len(value)/2):
            swapList.append(value[start:end])
            start += 2
            end += 2
        swapList.reverse()
        s = ''
        for i in swapList:
            s += i

        if sType == 'int':
            s = int(s, 16)
        elif sType == 'hStr':
            s = '0x' + s
        return s


    def fcsGen(self, frame, start = None, end = None, mLength = 0, output = 'bytes'):
        """Return the FCS for a given frame"""
        frame = str(frame)
        frame = frame[start:end]
        frame = crc32(frame) & 0xffffffff
        fcs = hex(frame).replace('0x', '')
        while len(fcs) < mLength:
            fcs = '0' + fcs
        fcs = self.endSwap(fcs)
        if output == 'bytes':
            return fcs
        elif output == 'str':
            return binascii.unhexlify(fcs)
        else:
            return fcs
