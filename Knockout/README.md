# Challenge Name: Knockout
## Description:
> I’ve Ceen Many Pictures of Knocking-out in my career
# Solution:
* On Analysing the PCAP file, we are able to see tha there is TCP connection established betweenn ```10.10.0.3``` and ```10.10.0.4``` through the port ```58832```
* On following the TCP stream, there was an conversation having hints about the challenge.
* Another Vital Clue was in the Description, the change of **"Ceen"** from **"Seen"** was doubtfull 
![image](https://user-images.githubusercontent.com/100958162/212252905-d0758ba2-1e6f-44e2-8675-5f2ea7c66442.png)
* They were mentioning about some images and therefore I tried to extract the images from the PCAP files.
![image](https://user-images.githubusercontent.com/100958162/212253094-13878f22-ff7f-459a-a5c3-f9185f065f92.png)
* Tried Stegenography on the images captured.
![image](https://user-images.githubusercontent.com/100958162/212253855-7ced9007-39d8-4396-87c8-11ee2b3f02a0.png)
* But it was not leading anywhere until I figured out that the pictures were meant to re-route us.
![image](https://user-images.githubusercontent.com/100958162/212268443-3070e3ae-4ac9-498d-ab39-ae6b39bc046a.png)
![image](https://user-images.githubusercontent.com/100958162/212269264-44da0bb6-b3c9-445a-a3ca-1e84a6a123a7.png)
![image](https://user-images.githubusercontent.com/100958162/212269395-2fadf767-f2de-442f-a151-338d97f28909.png)
![image](https://user-images.githubusercontent.com/100958162/212268821-39717661-424a-41c1-9d61-d317955e5245.png)
![image](https://user-images.githubusercontent.com/100958162/212268997-9266b6bc-badc-4a3d-9cb7-138ed0de376e.png)

* So this lead to dead end.
* But my doubts regarding the challenge being named "Knocking out" and the intentional vocabulary error in the Descripion still persisted.
* I took a look at all the vital protocols inside the PCAP.
![image](https://user-images.githubusercontent.com/100958162/212256026-e2ea6187-b015-451b-b9bb-5e6f1a3cdcfc.png)
* And I came across "ICMP Port Knocking" methord where a client tried to connect to a particular server through a port where it has to parse a firewall.
> In computer networking, port knocking is a method of externally opening ports on a firewall by generating a connection attempt on a set of prespecified closed ports. Once a correct sequence of connection attempts is received, the firewall rules are dynamically modified to allow the host which sent the connection attempts to connect over specific port.
>
> -Wiki
 * This made me check the ICMP packets (Now this makes sense to the vocab mistake in discription "**I** have **C**een **m**any **K**nocking out in....).
 * For a while I was not able to figure out any methord to get the flag or to get any data beneficial for my challenge.
 * Other than somerandome packets to that have:
 ![image](https://user-images.githubusercontent.com/100958162/212259238-0895ea87-db48-4d1d-81ef-9eddd2533c6a.png)
 ![image](https://user-images.githubusercontent.com/100958162/212259256-e05f088a-2c9c-4828-9625-1b968e41f5c6.png)
 * All other ICMP packets where just randome data.
 * SO after really trying to look at the PCAP i found a strange pattern in the length of these packets. 
 * Normally ICMP echo requests or reply are not this long.That too with a sense less data.
 * I came across a strange inference that the length of these packets are in the range of ASCII characters. 
 Just out of curiosity I collected all the length of the packets using a scapy script and tried to convert them to character/string
 ```py
 from scapy.all import *
import os 
packets = rdpcap("Knockout.pcap")
k = []
for i in packets:
        if ICMP in i and i[ICMP].id == int("0x1ee7", 16):
                if i[ICMP].type == 8:
                        k.append(len(i[Raw]))

#print(k)
for i in range(len(k)):
        print(chr(k[(i)]))
```
this gave me the flag as the output
# Flag:
> noxCTF{kn0ck1n6_my_1cmp}
