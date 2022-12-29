#Challenge Name: Decrypt
On opening the PCAP file Particularly 2 HTTP packets caught my attention in which one had a .txt file named sucessed and the other packet had an PGP message
On Researching about PGP encryptions, I got to know that this encryption needs an private PGP key and an Passphrase to decode the PGP message, thereafter traversing through the PCAP files, I came across an DNS packet that had the begining hex bits of an PNG image.
While applying the DNS filter, I got to know that all the DNS packets having length more than 400 had hex bits of the same image and the last bit had the end header
THerefore used an Python script with scrapy module to extract the HEX bits and convert it to the PNG image which turns out to be an QR code that doesn't give any valueable results on Scanning 
but using an tool for decoding qr code "zbarimg" gives the private PGP key,
for the passohrase tried success as the key but it was wrong. Then when viewing the meta data of the image using exiftool Found out that the image had a discription "helloworld" which turns out to  be the passphrase of the PGP cypher.
which gives the flag as a result
