.. Copyright 2013 6WIND S.A.

.. title:: |fp-svti|

About |fp-svti|
===============

|fp-svti| provides |svti| support in the |fp|.

|svti| interfaces are logical point-to-point network interfaces, that perform
IP-in-|ipsec| tunneling between 2 |ipsec| gateways.

|svti| interfaces handle their own |spd|. Traffic routed through an |svti|
interface is automatically submitted to a security policy check against the
|svti| interface's own |spd| and, when a matching |sp| is found, encrypted using
an |sa| matching the |sp|.

Incoming |ipsec|-encrypted traffic matching the tunnel endpoints of an |svti|
interface is first decrypted with the right SA, then submitted to a security
policy check against the |svti| interface's own |spd|. If the packet is granted
access, the decrypted traffic is received via the |svti| interface.

Features
--------

- |ipsec| security policy check against the: |svti| interface's |spd| for outbound
  traffic routed via an |svti| interface.
- |ipsec| security policy check against the |svti| interface's |spd| for inbound |ipsec|
  decrypted packets whose |ipsec| outer headers match an |svti|'s tunnel parameters.
- Compatibility with |vrf| processing
  (the encrypted and plaintext traffic may be in a |vrf| other than *vrf0*).
- Cross-|vrf| processing (the encrypted and plaintext traffic may be in different
  VRFs, the |svti| interface performs the |vrf| transition).

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpipsec4|

Installation
------------

See the |qsg|.
