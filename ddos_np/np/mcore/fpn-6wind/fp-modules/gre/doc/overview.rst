.. Copyright 2014 6WIND S.A.

.. title:: |fp-gre|

About |fp-gre|
==============

|fp-gre| provides IPvX and Ethernet over GRE support in the |fp|.

Features
--------

- Supported features:

  - IPv4 over IPv4 GRE tunnelling (L3 tunnel)
  - IPv6 over IPv4 GRE tunnelling (L3 tunnel)
  - IPv6 over IPv6 GRE tunnelling (L3 tunnel)
  - IPv4 over IPv6 GRE tunnelling (L3 tunnel)
  - IPV4 over Ether GRE tunnelling (L2 tunnel)
  - IPV6 over Ether GRE tunnelling (L2 tunnel)

- Manage GRE interfaces with or without |linux-fp-sync|.

- Ethernet GRE can be encapsulated on IPv4 (gretap) or IPv6 (ip6gretap)

- Cross-|vrf| processing (the encapsulated and plaintext traffic may be in different
  VRFs, the GRE interface performs the |vrf| transition).

Dependencies
------------

|6wg| modules
~~~~~~~~~~~~~

- |fpbase|
- |fpforw4|
- |fpforw6|

Linux
~~~~~

- Full Linux synchronization is a kernel patch (upstream 2.6.28).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c19e654ddbe3

- Support of Ether GRE (L2 tunnelling) is a kernel patch (upstream 2.6.28).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=e1a8000228e1

- GRE over IPv6 support is a kernel patch (upstream v3.7).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c12b395a4664

- Add x-netns support for IPv4 GRE is a kernel patch (upstream v3.16).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b57708add314

- Add x-netns support for IPv6 GRE is a kernel patch (upstream v3.16).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=22f08069e8b4

Installation
------------

See the |qsg|.
