import binascii
from rc4 import rc4
from scapy.layers.dot11 import Dot11, Dot11WEP, RadioTap
from scapy.layers.l2 import LLC
from scapy.packet import Padding
from scapy.utils import hexstr
from utils import Packet
from zlib import crc32

class Wep(object):
    """All things WEP related"""
    
    def __init__(self):
        self.pt = Packet()


    def seedGen(self, iv, keyText):
        """Currently works with 40-bit and 104-bit"""
        keyLen = len(keyText)
        
        ## 40-bit
        if keyLen == 5:
            key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
        elif keyLen == 10:
            key = binascii.unhexlify(keyText)
        
        ## 104-bit
        elif keyLen == 13:
            key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
        elif keyLen == 26:
            key = binascii.unhexlify(keyText)

        return iv + key
    
    
    def deBuilder(self, packet, stream, genFCS):
        """Take the pkt object and apply stream to [LLC]"""

        ## Remove the FCS from the old packet body
        postPkt = RadioTap(self.pt.byteRip(packet.copy(),
                                           chop = True,
                                           order = 'last',
                                           output = 'str',
                                           qty = 4))
        
        ## Remove RadioTap() info if required
        if genFCS is False:
            postPkt = RadioTap()/postPkt[RadioTap].payload

        ## Rip off the Dot11WEP layer
        del postPkt[Dot11WEP]

        ## Add the stream to LLC
        decodedPkt = postPkt/LLC(str(stream))
        
        ## Flip FCField bits accordingly
        if decodedPkt[Dot11].FCfield == 65L:
            decodedPkt[Dot11].FCfield = 1L
        elif decodedPkt[Dot11].FCfield == 66L:
            decodedPkt[Dot11].FCfield = 2L

        ## Return the decoded packet with or without FCS
        if genFCS is False:
            return decodedPkt
        else:
            return decodedPkt/Padding(load = binascii.unhexlify(self.pt.endSwap(hex(crc32(str(decodedPkt[Dot11])) & 0xffffffff)).replace('0x', '')))


    def decoder(self, pkt, keyText):
        """Take a packet with [Dot11WEP] and apply RC4 to get the [LLC]"""
        ## Re-use the IV for comparative purposes
        iVal = pkt[Dot11WEP].iv
        seed = self.seedGen(iVal, keyText)
        
        ## Remove the FCS so that we maintain packet size
        pload = self.pt.byteRip(pkt[Dot11WEP],
                                order = 'last',
                                qty = 4,
                                chop = True,
                                output = 'str')
        
        ## Return the stream, iv and seed
        return rc4(Dot11WEP(pload).wepdata, seed), iVal, seed


    def encoder(self, pkt, iVal, keyText):
        ## Calculate the WEP Integrity Check Value (ICV)
        wepICV = self.pt.endSwap(hex(crc32(str(pkt[LLC])) & 0xffffffff))
        
        ## Concatenate ICV to the [LLC]
        stream = str(pkt[LLC]) + binascii.unhexlify(wepICV.replace('0x', ''))
        
        ## Return the encrypted data
        return rc4(stream, self.seedGen(iVal, keyText))


    def enBuilder(self, pkt, stream, iVal):

        ## Remove the LLC layer
        del pkt[LLC]

        ## Add the Dot11WEP layer
        encodedPacket = pkt/Dot11WEP(iv = iVal, keyid = 0, wepdata = stream)

        ## Flip FCField bits accordingly
        if encodedPacket[Dot11].FCfield == 1L:
            encodedPacket[Dot11].FCfield = 65L
        elif encodedPacket[Dot11].FCfield == 2L:
            encodedPacket[Dot11].FCfield = 66L

        ## Add the ICV
        #encodedPacket[Dot11WEP].icv = int(self.pt.endSwap(hex(crc32(str(encodedPacket[Dot11])[0:-4]) & 0xffffffff)), 16)
        encodedPacket[Dot11WEP].icv = int(self.pt.fcsGen(encodedPacket[Dot11], end = -4), 16)
        return encodedPacket
