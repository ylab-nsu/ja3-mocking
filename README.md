# ja3-mocking
A tool for getting JA3 fingerprint from pyshark files with known domain. Initial goal was to not just get JA3 fingerprint, but to mock this fingerprint.
# Goals
The main goals were to:
 - ✅  Get main parameters of ClientHello request such as TLS version, supported ciphers, elliptic curves and e.t.c using pyshark 
 - ✅  Solve direct task: get JA3 fingerprint from basic parameters using MD5 hashing
 - ❌  Implement bruteforce solution for reversed task and then optimize it 
 - ❌  Try to behave like browser mocking someones fingerprint

# JA3 fingerprint in a nutshell

**JA3 fingerprint** is a method for identifying 
TLS clients by creating a hash (fingerprint) of the 
fields in the TLS Client Hello message. It includes 
parameters like the TLS version, supported cipher suites, 
extensions, elliptic curves, and more. Since different applications
and libraries construct their TLS Client Hello messages in unique ways, 
the resulting JA3 fingerprint can help distinguish between browsers,
apps, bots, or malware—even if they use the same IP address. 
It's widely used in network security for traffic analysis, threat detection, and anomaly spotting.



# Installation
First of all clone repository:
```commandline
git clone https://github.com/ylab-nsu/ja3-mocking.git
```

Then install dependencies:
```commandline
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Usage
```commandline
python hello.py <name-of-your-pcap-file> <domain> [-hs|--hashing]
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


