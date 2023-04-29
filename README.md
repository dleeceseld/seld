# seld
Deidentify sensitive cyber log data prior to sharing, testing, training, tooling, ML alchemy or any other reason that requires deidentification at scale

## TLDR
Your log data goes in, private fields like IPs, hostnames, accounts etc are converted in flight to data values that still work like IPs, hostnames ... just not your sensitive data, so share with those that can help you. 

Caveat: *A little discretion goes a long way with data sharing, but with 128 bit block cipher encryption behind the scenes even the bad apples will be busy for a while.*

## Use Cases
- Cyber defenders: Train like you fight or train to fight using realistic data from an industry you support without the overhead of a lab.
- Cyber tool forgers:  Work on the tools not the data to validate the tools, industry is a friend if we respect their privacy.
- ML & AI explorer: Did your model memorise the field data or the behavoiur? Change the keys and change the critical details.

## 101 Summary
Currently built on top of the great work done by the folks at Elastic,  SELD is a collection of log parsers, Ruby modules and a REST API implementing format preserving encryption, here are the basic steps:

- Stand up a Logstash collector and send it security logs, 
- create some encryption keys, 
- create a sensitive terms list: suggesting all your users (sure 200 is fine but more should work, your domain names and internal ip ranges 
- start the deidentification appliance (also built on Logstash),
- double check nothing is leaking out with the testdeident script and your sensitive terms list
- share the deidentified data, not your keys
- data outputs are currently Syslog RFC3124, RFC5424 and JSON Lines, Logstash codecs gobble it up but so should products like Splunk and QRadar
- keep the keys just in case you need to reidentify in the future, no big token database to maintain


**Disclaimer**

Given enough time and effort almost any data can be reidentified, the extremely high bar for "anonymized" makes the data so generic it is consistently unusable for cyber security and digital observability uses. The SELD project followed GDPR guidelines on pseudonymization which is considered a valid data protection mechanism but not a guarantee. 

