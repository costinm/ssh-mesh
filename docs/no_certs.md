# Using public key instead of certs for workload identity.

TLS and SSH certs are very useful and important, but they are complex and 
in some cases not required. Using ssh without certs is extremely common,
and uploading public key in configs for git is considered secure enough.

- each host - or VM/Pod/Container - has a private key
- DNS publishes the SPKI hash, relying on DNS-SEC to sign it - RFC7671 
- control plane/discovery publishes the same key - it is trusted anyways.
- config files or discovery documents are signed - and may include the same hash.



```

_25._tcp.example.com IN TLSA 3 1 1 $DATA

3 - DANE-EE (end entity), i.e. the actual cert ( not a root CA). Alternatives are 0,1 - system roots used, 2 DANE-TA - a private CA

1 - SPKI (alterntive 0 - has of the cert)

1 - SHA256 of SPKI (0 = full data, good for ec25519)

```

https://dane.sys4.de/common_mistakes

