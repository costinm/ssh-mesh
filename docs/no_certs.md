# Using public key instead of certs for workload identity.

- each workload (or host) has a private key, in-memory (not saved)
- DANE and K8S hold the SPKI hash - RFC7671

```

_25._tcp.example.com IN TLSA 3 1 1 $DATA

3 - DANE-EE (end entity), i.e. the actual cert ( not a root CA). Alternatives are 0,1 - system roots used, 2 DANE-TA - a private CA

1 - SPKI (alterntive 0 - has of the cert)

1 - SHA256 of SPKI (0 = full data, good for ec25519)

```

https://dane.sys4.de/common_mistakes

