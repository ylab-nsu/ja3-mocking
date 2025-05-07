# ja3-mocking
A tool for getting JA3 fingerprint from pyshark files with known domain.
# Installation
```commandline
git clone https://github.com/ylab-nsu/ja3-mocking.git
```
Also you should install [pyshark](https://github.com/KimiNewt/pyshark) python package to use our tool: 
```commandline
pip install pyshark
```
# Usage
```commandline
python hello.py <name-of-your-pcap-file> <domain [-hs|--hashing]
```
For example:
```commandline
$ python3.11 hello.py test3.pcap google.com

JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: prod-dynamite-prod-05-us-signaler-pa.clients6.google.com 

JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: chat.google.com 

JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: ogads-pa.clients6.google.com 

JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: mail-ads.google.com 

JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: mail.google.com 
```

Or if you want to know hash of JA3 fingerprint, you can add ```-hs``` flag
Usage example:
```commandline
python3.11 hello.py test3.pcap google.com -hs

JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: prod-dynamite-prod-05-us-signaler-pa.clients6.google.com 
   hash: 15c05a8cb13cf1f061986b7969c89a3c
JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: chat.google.com 
   hash: 15c05a8cb13cf1f061986b7969c89a3c
JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: ogads-pa.clients6.google.com 
   hash: 15c05a8cb13cf1f061986b7969c89a3c
JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: mail-ads.google.com 
   hash: 15c05a8cb13cf1f061986b7969c89a3c
JA3-fingerprint without hashing: 
   771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,,29-23-24-25,0 
   with given domain: mail.google.com 
   hash: 15c05a8cb13cf1f061986b7969c89a3c
```


