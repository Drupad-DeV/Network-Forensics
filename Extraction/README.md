# Challenge Name: Extraction 
## Chllenge Description:
> Found this packet capture. Pretty sure there’s a flag in here. Can you find it!?
# Solution:
* This time the number of packets were less
* And hence it was easy to traverse through them.
* There was a jpeg image being transmitted through them.
* Extracted it using Scapy script
```py
from scapy.all import *
import os
file = rdpcap("Extraction.pcapng")
k = bytes()
count = 0
#print(hexdump(file[12]))
for i in file:
	if TCP in i and len(i)>1000:
		a = bytes(i)
		a = a[66:]
		k += bytes(a)
open('flag.jpg', 'wb').write(k)
```
* Image Extracted
![image](https://user-images.githubusercontent.com/100958162/211208549-341b3e10-cdb4-4e54-81d0-9a2216e6aac7.png)

* Which had a zip file inside it 

![image](https://user-images.githubusercontent.com/100958162/211208639-92c39b9f-e340-4047-8dc9-9ae926386237.png)

* bruteforced and unzipped 
![image](https://user-images.githubusercontent.com/100958162/211085106-be8158b3-f326-44c7-b17d-bc075aa4dc5e.png)

the zip file contained flag.pdf that gives the flag.

![image](https://user-images.githubusercontent.com/100958162/211085293-9dc38c80-1b06-4348-a4c5-ed08bf2a4ae9.png)
```shaktictf{h0p3_y0u_ar3_enj0ying_thi5}```
