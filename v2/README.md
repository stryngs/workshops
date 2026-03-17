## Useful links
- [Wiretap thoughts](https://www.law.cornell.edu/uscode/text/18/2511)
- [I am not a lawyer](https://www.law.cornell.edu/cfr/text/47/95.313)
- [Here](https://mrncciew.com/wp-content/uploads/2014/10/ieee-802-11-2012.pdf) and [here](https://github.com/FCAE/WLAN/blob/master/doc/802.11-2012.pdf)
- [2.5.0](https://github.com/secdev/scapy/releases/tag/v2.5.0) and [2.7.0](https://github.com/secdev/scapy/releases/tag/v2.7.0)

## List of repositories covered in the talk
- [airpwn-ng](https://github.com/stryngs/airpwn-ng)
    - Has a known bug I have yet to squish, only appears sometimes (line 83 in airpwn-ng/SRC/airpwn_ng/lib/sniffer.py)
        - The bug is likely due to not accounting for Dot11FCS
        - Tentative solution would be to wrap in a try/except and wrpcap on the except for later analysis
        - Solutions welcomed!
    - Original bash poc is airpwn-ng/_archive/INFOs/bash_PoC
- [edgeDressing](https://github.com/stryngs/edgeDressing)
    - Leverages the NCSI probes in Windows and forces a target browser to open on demand
    - When the browser opens it will be directed to a website of the user's choice
- [foxHunter](https://github.com/stryngs/foxHunter)
    - Track a given MAC address with the RSSI
- [frameTracer](https://github.com/stryngs/frameTracer)
    - Store packet captures for a singular MAC or a pair of MACs which interact
    - Logs to a PCAP based on the presence of the MAC(s) in any of the addr slots for a given frame
- [packetEssentials](https://github.com/stryngs/packetEssentials)
    - A set of modules designed to shortcut the work involved with packet crafting and injection
    - Heavily geared around 802.11 but plays well with 802.3 and others depending on the situation
- [pyDot11](https://github.com/stryngs/pyDot11)
    - 802.11 Encryption and Decryption on-the-fly
- [piCopilot](https://github.com/stryngs/piCopilot)
    - I took [kSnarf](https://github.com/stryngs/kSnarf) and ported it to something bootable
    - A [Companion Computer](https://ardupilot.org/dev/docs/companion-computers.html) for drones
- [pmkid2hashcat](https://github.com/stryngs/pmkid2hashcat)
    - A different way of grabbing the pmkid
    - I should probably add optional repeats on the inject
    