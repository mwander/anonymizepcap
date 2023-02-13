---
title: "Anonymize PCAP"
date: 2021-05-16T21:58:38+02:00
aliases:
    - /projects/traffic-analysis/anonymize-pcap
---

**anonymizepcap is a Python tool for anonymization of MAC addresses and pseudonymization of IP addresses from \*.pcap files. MAC addresses are substituted with zeros, while IP addresses are substituted either with a password-based HMAC or a first-time-seen mapping.**

## Features

* Works on \*.pcap files in filesystem or on-the-fly on piped PCAP input.
* Anonymization: MAC addresses are overwritten with zeros.
* Pseudonymization: IP addresses are rewritten with a 1:1 map function. Traffic analysis of cohesive IP packets remains possible.
    * Affects either all IP addresses or only those from a list of given IP subnets.
    * IPv4 addresses are rewritten to 238.0.0.0/8 (with default offset 238).
    * IPv6 addresses are rewritten to ee::/64 (with default offset 238=0xee).
    * IP, TCP and UDP checksums are rewritten after packet alteration to correct value.

### IP Address Pseudonymization

The following mapping algorithms are implemented:

**1. Keyed-hashing**  
If you set `--secret "foobar"` on command line, IP addresses will be mapped to 238.xx.yy.zz, where xxyyzz are the last 24 bit (64 bit for IPv6) of a keyed-hash value (HMAC-SHA256) with `foobar` as secret key. The mapping is deterministic, which means it will be fixed for every input file, as long as the same secret key is used. With knowledge of the key, the mapping can be reversed with moderate effort.

**2. First-time-seen**  
Without a secret key, the first IP address seen is mapped to 238.0.0.1, the second to 238.0.0.2 etc. The mapping is unique to the order of IP addresses seen from the input file, which means it will be different for every input file. The order is *not* saved and thus not easily reversible.

### Limitations

UDP/TCP payload is not rewritten. IP addresses in application data reveal the original senders. Application data may contain Personally Identifiable Information. Even without private data, correlation analysis may give clues that allows mapping traffic flows to individual persons.

## Usage

### Offline Mode

```
tcpdump -i eth0 -w private.pcap -v
python3 anonymizepcap.py -s somePassword private.pcap anon-out.pcap
```

### On-the-fly Mode

```
tcpdump -i eth0 -w - -v | python3 anonymizepcap.py -i -s somePassword anon-out.pcap
```

### Tcpdump Rotation Mode

```
# Rotate pcap files hourly, call anonymization script each time
tcpdump -i eth0 -w "dns_%Y-%m-%d_%H_%M_%S.pcap" -n -G 3600 -z "./post-anon.sh"
```

post-anon.sh may look like this:
```
# Read from file $1 and write output to anon_$1
python3 anonymizepcap.py -s somePassword $1 anon_$1 && rm $1
```

You may get the following error message, even if you `chmod` the .sh file to 755:
```
compress_savefile: execlp(./post-anon.sh, dns-2021-05-31-22_44_24.pcap) failed: Permission denied
```

In this case you have to install `apparmor-utils` and call the following command:
```
aa-complain /usr/sbin/tcpdump
```

## Installation

### Prerequisites

* [Python 3](https://www.python.org)
* [dpkt](https://github.com/kbandla/dpkt)

### Download

* [anonymizepcap-0.2.tar.gz](anonymizepcap-0.2.tar.gz)

*Old version for Python 2.7*: [anonymize-pcap.tar.gz](anonymize-pcap.tar.gz)
---
title: "Anonymize PCAP"
date: 2021-05-16T21:58:38+02:00
aliases:
    - /projects/traffic-analysis/anonymize-pcap
---

**anonymizepcap is a Python tool for anonymization of MAC addresses and pseudonymization of IP addresses from \*.pcap files. MAC addresses are substituted with zeros, while IP addresses are substituted either with a password-based HMAC or a first-time-seen mapping.**

## Features

* Works on \*.pcap files in filesystem or on-the-fly on piped PCAP input.
* Anonymization: MAC addresses are overwritten with zeros.
* Pseudonymization: IP addresses are rewritten with a 1:1 map function. Traffic analysis of cohesive IP packets remains possible.
    * Affects either all IP addresses or only those from a list of given IP subnets.
    * IPv4 addresses are rewritten to 238.0.0.0/8 (with default offset 238).
    * IPv6 addresses are rewritten to ee::/64 (with default offset 238=0xee).
    * IP, TCP and UDP checksums are rewritten after packet alteration to correct value.

### IP Address Pseudonymization

The following mapping algorithms are implemented:

**1. Keyed-hashing**  
If you set `--secret "foobar"` on command line, IP addresses will be mapped to 238.xx.yy.zz, where xxyyzz are the last 24 bit (64 bit for IPv6) of a keyed-hash value (HMAC-SHA256) with `foobar` as secret key. The mapping is deterministic, which means it will be fixed for every input file, as long as the same secret key is used. With knowledge of the key, the mapping can be reversed with moderate effort.

**2. First-time-seen**  
Without a secret key, the first IP address seen is mapped to 238.0.0.1, the second to 238.0.0.2 etc. The mapping is unique to the order of IP addresses seen from the input file, which means it will be different for every input file. The order is *not* saved and thus not easily reversible.

### Limitations

UDP/TCP payload is not rewritten. IP addresses in application data reveal the original senders. Application data may contain Personally Identifiable Information. Even without private data, correlation analysis may give clues that allows mapping traffic flows to individual persons.

## Usage

### Offline Mode

```
tcpdump -i eth0 -w private.pcap -v
python3 anonymizepcap.py -s somePassword private.pcap anon-out.pcap
```

### On-the-fly Mode

```
tcpdump -i eth0 -w - -v | python3 anonymizepcap.py -i -s somePassword anon-out.pcap
```

### Tcpdump Rotation Mode

```
# Rotate pcap files hourly, call anonymization script each time
tcpdump -i eth0 -w "dns_%Y-%m-%d_%H_%M_%S.pcap" -n -G 3600 -z "./post-anon.sh"
```

post-anon.sh may look like this:
```
# Read from file $1 and write output to anon_$1
python3 anonymizepcap.py -s somePassword $1 anon_$1 && rm $1
```

You may get the following error message, even if you `chmod` the .sh file to 755:
```
compress_savefile: execlp(./post-anon.sh, dns-2021-05-31-22_44_24.pcap) failed: Permission denied
```

In this case you have to install `apparmor-utils` and call the following command:
```
aa-complain /usr/sbin/tcpdump
```

## Installation

### Prerequisites

* [Python 3](https://www.python.org)
* [dpkt](https://github.com/kbandla/dpkt)

### Download

* [anonymizepcap-0.2.tar.gz](anonymizepcap-0.2.tar.gz)

*Old version for Python 2.7*: [anonymize-pcap.tar.gz](anonymize-pcap.tar.gz)
