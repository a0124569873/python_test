.. Copyright 2014 6WIND S.A.

.. title:: |mcast6|

About |mcast6|
==============

|mcast6| provides IPv6 multicasting in the |fp|.

IPv6 multicasting is part of the IPv6 specification:

:rfc:`2460`

Features
--------

- (S,G) support
- (\*,G) support
- (\*,\*) support
- multicast group filtering

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|
- |fpforw6|

Linux
~~~~~

- Synchronization of multicasting in the |fp| depends on a kernel patch
  (upstream 3.8):

http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8cd3ac9f9b7b

Installation
------------

See the |qsg|.
