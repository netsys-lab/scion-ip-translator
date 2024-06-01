scion2ip
--------

Converts between SCION and SCION-mapped IPv6 addresses.

SCION addresses are given as whitespace separated tuple of ISD-ASN, local
prefix, subnet, and interface address. Local prefix, subnet, and IPv6 interface
identifiers are in hexadecimal. IPv4 interface must be given in dotted decimal
form with prefix and subnet set to zero.

Examples:
```bash
$ ./scion2ip 1-64512 0 0 1
fc00:10fc::1
$ ./scion2ip 1-2:0:0 0 0 10.0.0.1
fc00:1800::ffff:a00:1
$ ./ip2scion fc00:10fc:200::1
1-64514 0 0 1
$ ./ip2scion fc00:10fc::ffff:a80:1
1-64512 0 0 10.128.0.1
```
