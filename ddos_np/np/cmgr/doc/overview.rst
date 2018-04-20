.. Copyright 2013 6WIND S.A.

.. title:: |linux-fp-sync|

About |linux-fp-sync|
=====================

|linux-fp-sync| provides transparent synchronization of |fp|
protocols with Linux.

It provides the |cmgr|, which is responsible for listening to Linux events and
transmitting them to the |fpm| (provided as part of |fpbase|) to configure the
|fp|.

Statistics are synchronized through the |fps| feature (provided as part of
|fpbase|).

Entry aging (to prevent the expiration of dynamic entries such as ARP, NDP,
conntrack, etc. when they are used in the |fp|) is handled by the |hitflags|
feature (provided as part of |fpbase|).

Features
--------

- Queuing mechanism to cope with frequent changes
- Graceful restart
- Monitoring console access via a UNIX socket
- Plugins support

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|

Before starting |linux-fp-sync|, you must start the |fp|.

Linux
~~~~~

- iptables-devel

Plugins
=======

To monitor additional modules, the |linux-fp-sync| daemon
can be extended with plugins (shared libraries loaded at startup.)

By default, the daemon loads all shared libraries that match the pattern
*/usr/local/lib/cmgr/\*.so*.
You can set the CMGR_PLUGINS environment variable to change the
default plugin location pattern.

Available plugins:

   - **VNB**

   - **OVS acceleration**

   - **IPsec output delegation and SA migration**

Installation
------------

See the |qsg|.
