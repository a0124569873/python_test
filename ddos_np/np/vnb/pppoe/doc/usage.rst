Usage
=====

PPPoE support in |vnb| is active by
default as long as the |vnb-pppoe| module is detected.

To avoid loading the |vnb-pppoe| module, specify only the VNB modules you want
to load in the MODULES variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

.. code-block:: console

   : ${MODULES:=ether ppp}

.. seealso::

   For more information, see the |vnb-baseline| documentation.

PPPoE nodes usage
-----------------

PPPoE nodes can be managed manually with a tool like `ngctl`, or, more
frequently, through a userland daemon (for instance: MPD), with a basic setup
definition and dynamic nodes management.

.. seealso::

   For more information on how to configure MPD, see the relevant documentation.

PPPoE client MAC address filtering
----------------------------------

As some NICs do not implement RSS for PPPoE packets, a new feature
is needed to spread the input connections on multiple ports, based
on information sent by the clients (using the least-signifcant bits
from the client MAC address).

The broadcast PADI packets are sent to some ports grouped in a configuration.
On each port, a MAC filter for broadcast packets is implemented:

- the MAC filter has a bit width (len) and a matching pattern,
- the MAC filter extracts the "len" lsb bits from the src MAC address,
- if the "len" lsb bits match the configured pattern, the packet is
  forwarded to mpd,
- if the packet does not match, the packet is dropped.

The MAC filter can be used to spread input packets on multiple cores.
example configuration, with 4 ports:

- port0: len=2, pattern=0 (procesed by core0),
- port1: len=2, pattern=1 (procesed by core1),
- port2: len=2, pattern=2 (procesed by core2),
- port3: len=2, pattern=3 (procesed by core3).

One assumption for this function is that broadcast packets are duplicated
and received on all ports configured for MAC address filtering (for example
if the ports using a MAC filter are connected to the clients via a
typical Ethernet switch).

With this configuration each client will be served by one port, and
if the incoming MAC addresses are randomly distributed, a similar
number of clients will be handled on each port.

A typical use case is when the input ports for a server are VF (Virtual
Functions / SRIO-V) attached to a single PF (physical port). The VF can
be used both in a host setup, where 6WINDGate is run directly on a
machine, or in a virtualized guest setup, where 6WINDGate is run in a VM
attached to the VF.
