# Dig Deep
Conversation was extracted using scapy
vingere cypher (NOV 5)
extracted the bytes of zip file
embedded the files extracted to zip file
used john to bruteforce the password 
password found ```johnjandroveclarkmichaelkent```
used zsteg to get the payload type 
and then used zsteg to get the flag
```zsteg -E b1,bgr,lsb,xy flag.png | strings | grep {```
inctf{3ach_4nd_3v3ry_s3cre7_inf0rm4t10n_w1ll_b3_kn0wn_by_wir3shark!!!!!_:)}
