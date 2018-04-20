.. Copyright 2013 6WIND S.A.

.. title:: |vnb-baseline|

About |vnb-baseline|
====================

|vnb-baseline| is the foundation of the Virtual Network
Blocks framework, a modular and flexible framework to build networking
protocols.

Features
--------

List of supported nodes:

- ng_div
- ng_eiface
- ng_ether
- ng_gen
- ng_iface
- ng_ksocket
- ng_mux
- ng_one2many
- ng_socket
- ng_split
- ng_tee
- ng_ppp

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|

Linux
~~~~~

- The hook in the networking stack requires *rx_handler patches* (upstream
  2.6.36).

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ab95bfe01f98

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=93e2c32b5cb2

  Without these patches, you can re-use the *macvlan hook* (upstream 2.6.23),
  that can be enabled by setting *USE_MACVLAN_HOOK* in *ng_rxhandler.h*.
  *USE_MACVLAN_HOOK* is set for Red Hat >= 6.5 and < 7.0.

- To enable synchronization with the |fp|, the *IFLA_AF_SPEC* attribute is
  used to store VNB node ids; this requires the following patch (upstream 2.6.38
  or Red Hat 6.5):

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=f8ff182c716c

Installation
------------

See the |qsg|.
