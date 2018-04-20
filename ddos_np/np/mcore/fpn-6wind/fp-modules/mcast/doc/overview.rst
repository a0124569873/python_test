.. Copyright 2014 6WIND S.A.

.. title:: |mcast|

About |mcast|
=============

|mcast| provides IPv4 multicasting in the |fp|.

IP multicasting is defined following :rfc:`1112`.

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
- |fpforw4|

Linux
~~~~~

- Synchronization of multicasting in the |fp| depends on a kernel patch
  (upstream 3.8):

 http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=8cd3ac9f9b7b

Installation
------------

See the |qsg|.
