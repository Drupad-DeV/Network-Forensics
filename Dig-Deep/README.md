# Challenge Name: Dig Deep
> I have intercepted one of my friend's chat. Can you help me in analyzing it?

## Solution:
* On Traversing throough the pcap, the first packet captured the initialisation of tcp connection between ```192.168.43.178``` and ```192.168.43.242```
* Setting the filter to tcp and specifyng the soruce and desitination ip. 
* Their conversation says that they are transfering some file that contain some secret. (probably our flag)
* The conversation was extracted using this script (chsnging the source and destination IP would give the conversation from both Rohit and Shyam's PC
```py
from scapy.all import *
import os
z = bytes()
packets = rdpcap("Dig_deep.pcapng")
output = open('output2.bin','wb')
for i in packets:
	if IP in i and i[IP].src == "192.168.43.242" and i[IP].dst == "192.168.43.178" and TCP in i:
		print(i[TCP].payload)
		i = bytes(i[TCP].payload)
		z += i
	output.write(z)
		#print(i)
		#if DATA in i:
			#print(i)
  ```
 
* Soon after the "Transferring files message", there was a series of tcp packets destined to a specific port and having a specific length
![image](https://user-images.githubusercontent.com/100958162/211206165-808dfc81-11ae-4b8f-a5a4-95d70d80ed84.png)

* The tcp packets transferred a zip file.
![image](https://user-images.githubusercontent.com/100958162/211205976-e274b745-0080-4ac9-9a3c-4deb96a05c39.png)

* So i used this scappy code to extract the zip file.

```py
from scapy.all import *
import os
k = bytes()
file = rdpcap("Dig_deep.pcapng")
output = open('fIles','wb')
for i in file:
	if TCP in i and IP in i and i[IP].src == "192.168.43.242" and i[IP].dst == "192.168.43.178":
		if i[TCP].dport == 81 and len(i)== 854:
			i = bytes(i)
			k += i[54:]
print(k)
output.write(k)
```
```py
file = open("fIles","rb").read()
k = bytes()
for i in file:
	k += bytes(([(i-5)%256]))
print(k)
open("fIles.zip","wb").write(k) 
```
* The zip file was password protected, and had flag.png inside it.
![image](https://user-images.githubusercontent.com/100958162/211207312-5807b454-3922-4099-b3e6-d2dcc5aedf5a.png)
* The password was bruteforced using John.
* That would give flag.png
![image](https://user-images.githubusercontent.com/100958162/211207418-543d57ec-9f83-4a0a-950e-06acc24d6917.png)
**Password :** ```johnjandroveclarkmichaelkent```
* The image had an payload in it Using Zsteg would give you the payload type
![image](https://user-images.githubusercontent.com/100958162/211207666-7fd9a8bc-27f0-4925-90b8-b7e23d573b5b.png)
* The ```b1,bgr,lsb,xy``` had dummy text inside it. That caught my attention
![image](https://user-images.githubusercontent.com/100958162/211208016-3d195978-4449-4df8-bf29-c648745610e4.png)

> Flag ```inctf{3ach_4nd_3v3ry_s3cre7_inf0rm4t10n_w1ll_b3_kn0wn_by_wir3shark!!!!!_:)}```
