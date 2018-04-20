.. Copyright 2013 6WIND S.A.

.. title:: |fpbase|

About |fpbase|
==============

|fpbase| is the foundation of the |fp| packet processing
framework.

Features
--------

- Physical port detection
- Logical interface abstraction
- Statistics
- Internal debugging
- Plugins
- |macvlan| devices support in the |fp|

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpn-sdk-baseline|

Linux
~~~~~

MACVLAN feature:

- Netlink notifications for MACVLAN mode is a kernel patch (upstream 2.6.33).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=27c0b1a850cd

- Netlink notifications to put the lower interface in *promiscuous* and
  *allmulticast* modes is a kernel patch (upstream 3.13).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=991fb3f74c14


Installation
------------

See the |qsg|.
