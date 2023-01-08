# Challenge Name: Decrypt
## Challenge Description:
> Bob and Charlie were sending some messages among themselves,and I planned to intercept their secrecy and get something out of it, however they are clever enough 	that no one gets anything. Please help me out to get the secret!!

### Solution:
* While analysing a PCAP file in general I look for any extractable objects, Here I could get an .txt file that was transmitted using http protocol.
![image](https://user-images.githubusercontent.com/100958162/211198507-7513f2de-db41-4487-802c-416db9163175.png)
* Therefore I strted traversing through all the http packets, but there were only 2 of then one had the ```success.txt``` and the other had an PGP message
* Extracted and saved the PGP message using an scapy script
```py
from scapy.all import *
import os
packets = rdpcap("Decrypt.pcap")
b = bytes()
k = str()
for i in packets:
	if IP in i and i[IP].src == '49.44.177.154' and i[IP].dst == '192.168.42.51' and len(i)>1000:
		b = bytes(i)
		b = b[512:]
		k += str(b)
print(k)
```
```
-----BEGIN PGP MESSAGE-----
Version: OpenPGP v2.0.8
Comment: https://sela.io/pgp/

wcBMA8fXP+32fyviAQf/T+NzsOgQ+ejW16GeK6h9WS9IDelAN9GLY5x5o9ilBlEL
G4IPati4/zqd+kyV5mmA7k2eKnNByRnxElpp0PoGULX0ykjBTcXuLtNXzGWcDsFF
xAkH8PduoPCcnNGWrCU6D8ZuWNtp7oeZ1krUZP+Kg9sfjjKfx0aUFhWs9SQH6mif
AlbJQwxKi2xXv0UsHvg4Mz4TpVstoO5XcN9d4V+gygc+wx0K61JwAFw96xptNi9y
hdMz/c7yW56JwBfwyiHvYmgLdWYJW9OEoQIj7Rwh1v8mD846vbvEDmagQ0Ra/K6q
lnxa37gBFE+4kYpSXP7yqr8QMhmGDpMROJoJqxYyY9JxAe6317HZ+UUEOmNR+0tB
EmPl/VVaoPc5q6RQ/cxwY4VhR4DtPsG9Gw237Sx+xSTAG5JbmtBf4KfQdVbeaXn1
PYPYBeCVL6nb6uPz6ZHBJ2SODWg9+Ssas+Gd5P7Q0zSA/35qYdamnAqUM/ujM2nN
k2U=
=+x+V
-----END PGP MESSAGE-----

```
* Inorder to decrypt a pgp message we need **PGP private KEY**, password.
* On traversing through the packets i found that a DNS data packet has the header of an PNG image inside it
![image](https://user-images.githubusercontent.com/100958162/211202236-c9901af3-4eca-4aeb-9f2c-fea0aac32ddc.png)

* Using an scapy sript i was able to extract the hex data of the image and then write it to an .img file to retrive the image.
```py
import os
from scapy.all import * 
file = rdpcap("Decrypt.pcap") 
a = bytes() 
with open('png_dns.png', 'wb') as img:
    for i in file:
        if DNS in i:
            k = bytes(i)
            if len(k) > 400:
                k = k[224:]
                a+= k
    img.write(a)
```
* Tried Using diffrent kinds of stegtools on the image obtained.
![image](https://user-images.githubusercontent.com/100958162/211202617-ccf503ac-6241-463a-ad71-8352f3c452f0.png)
* Scanning the QR code or any other steg tools didn't give any beneficial info.
* But on using [zbarimg](https://manpages.ubuntu.com/manpages/xenial/man1/zbarimg.1.html) i was able to get the PGP private key. 
![image](https://user-images.githubusercontent.com/100958162/211202785-7b60175a-74a5-4ea3-affd-4309abb2e2f5.png)

* Lucikly the img description "helloworld" turns out to be the password.

![image](https://user-images.githubusercontent.com/100958162/211202919-d4afaf07-5cd1-453e-836c-ce18aa09a7a8.png)

![image](https://user-images.githubusercontent.com/100958162/211203263-3a7f7f9f-b763-46bc-b68f-9f3a2c7dd0d7.png)

# Flag:
```flag{eNcryP7!ng_t0_PgP_1s_r34LLy_Pre3tY_g00D_pr1V4cY}```
