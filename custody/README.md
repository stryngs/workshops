# The gist
Code is required to meet the requirements of this challenge and the human participant is not allowed to submit a solution that requires interactive usage beyond the normal entry of user input for starting a program such as ./foo.bar.  The code is meant to be ran as mostly stand alone and not have a human looking at something such as Wireshark while figuring out what to do next.  The less human interaction past inception, the better.  Solutions of more than one piece of code are acceptable.  If it requires Bash and then Python, so be it.  Pipes are preferred if chaining is needed, but what matters in the end is the code.

## Challenges
1. Modify one.pcap and then create solution-one.pcap
   * Change the IP and MAC of the device sending a ping (ICMP Request) to
     ```
     192.168.100.137
     4e:40:cd:16:5a:1e
     ```

2. Import two.pcap and decrypt the content, creating solution-two.pcap

3. Modify solution-two.pcap and encrypt back to the same encryption used by two.pcap
   * Modify all packets so that the "IEEE 802.11 RSSI" column in Wireshark displays as -40 dBm

4. Import four.pcap and decrypt the content, creating solution-four.pcap

5. Import five.pcap and decrypt the content, creating solution-five.pcap

6. Import six.pcap and decrypt the content, creating solution-six.pcap

7. Import seven.pcap and decrypt the content, creating solution-seven.pcap

8. Modify solution-five.pcap and encrypt back to the same encryption used by five.pcap

9. Modify solution-seven.pcap and encrypt back to the same encryption used by seven.pcap

10. Modify solution-four.pcap and encrypt back to the same encryption used by four.pcap

11. Modify solution-six.pcap and encrypt back to the same encryption used by six.pcap

## House rules
* 42
* All checksums must match
* Ask if you are unsure
* Challenges 4-7 require a detailed description of the encryption type used
* Challenges 8-11 require the submission encryption to work with the original encryption session
* Do not be shy, ask questions
* Ensure timestamps match the original
* Only include the decrypted packet within solution-four.pcap, solution-five.pcap, solution-six.pcap, solution-seven.pcap
* Radiotap headers ought match
* Speed matters if that is a question
* Wireshark with all checks turned on will most likely settle any disagreements

## Quote log
* Challenge
  * Has been known to supercede the house in terms of rule
* Checksums
  * The calculated hash of something based upon other things which yields math and a signature.
* Decrypted content
  * The act of taking something such as a Alice, converting it to Bob and then creating an object or pcap which can be opened in something such as Wireshark, where the content is presented without the need for any Wireshark decrypting; made to order and ready to consume.
* Horses
  * 299792458; anything else and this measures the tie.
* Radiotap headers
  * Defined as per IEEE and whatever other source you find.  Inspect what you expect and compare across whatever programs you can find.  Some say tomato while others hear tomato; the splats are what matter, we will splat.
* Time
  * Use it all to your advantage and don't be shy; go out and learn something!
