.. Copyright 2013 6WIND S.A.

.. title:: |fp-tunnel|

About |fp-tunnel|
=================

|fp-tunnel| provides IPinIP tunnelling in the |fp|.

Features
--------

- IPv4 in IPv4 tunnelling
- IPv6 in IPv4 tunnelling

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpforw4|
- |fpforw6|

Linux
~~~~~

- IPv4 over IPv4 and IPv6 over IPv4 on the same interface is a kernel patch (upstream 3.11).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=32b8a8e59c9c

- Full Linux synchronization is a kernel patch (upstream 3.8).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0974658da47c

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ba3e3f50a0e5

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c075b13098b3

- X-vrf support for IPv4/IPv6 over IPv4 is a kernel patch (upstream 3.11).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=5e6700b3bf98

- X-vrf support for IPv4/IPv6 over IPv6 is a kernel patch (upstream 3.12).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0bd8762824e7

Installation
------------

See the |qsg|.
