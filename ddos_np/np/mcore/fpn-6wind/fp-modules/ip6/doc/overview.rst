.. Copyright 2013 6WIND S.A.

.. title:: |fpforw6|

About |fpforw6|
===============

|fpforw6| provides IPv6 forwarding in the |fp|.

Features
--------

Fast path forwarding IPv6 features:

- IP forwarding
- IP fragmentation
- ECMP (Equal Multipath) with priority per route type
- |vrf| support
- IPv6 reverse path forwarding check
- TCPmss clamping per interface
- Next hop marking (if the |fp| filter module is present)

Dependencies
------------

Modules
~~~~~~~

- |fpforw4|

Linux
~~~~~

- Synchronization of interface flag status *forwarding* is a kernel patch (upstream 3.8).

  Without this patch, the |fp| starts with forwarding enabled.

  rtnl/ipv6: use netconf msg to advertise forwarding status
  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=f3a1bfb

- ECMP IPv6 appeared in Linux 3.8

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=51ebd31

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=52bd4c0

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b3ce5ae

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1a72418

- Optimization of synchronization of *NDP entries* is a kernel patch (upstream 3.13).

  Without this patch, the NDP entries stand in state STALE and the |fp|
  continuously sends hitflags for them.

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=53385d2d1de84f4036a0919ec46964c4e81b83f5

Installation
------------

See the |qsg|.
