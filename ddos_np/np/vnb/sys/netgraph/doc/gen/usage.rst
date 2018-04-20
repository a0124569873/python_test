Usage
=====

To use traffic generator support in :ABBR:`VNB (VIRTUAL NETWORKING BLOCKS
TECHNOLOGY)`, load the kernel modules below, in the following order:

.. code-block:: console

   # modprobe vnb-linux
   # modprobe vnb
   # modprobe vnb_gen

Additional modules must be loaded before loading modules from the VNB base
package.

.. seealso::

   For more information, see the VNB base documentation.

Available commands
------------------

This node can be configured with the following **ngctl** commands:

setrate
   Assign new rate (bursts per second) to each traffic source (input hooks and
   locally-generated packets). Also set the default value for future sources.
getrate
   Retrieve setrate value.
setburst
   Assign new burst size (number of packets) to each traffic source (input
   hooks and locally-generated packets). Also set the default value for future
   sources.
getburst
   Retrieve setburst value.
sethookrate
   Like setrate but only for a given hook. Doesn't affect the default value.
gethookrate
   Retrieve sethookrate value.
sethookburst
   Like setburst but only for a given hook. Doesn't affect the default value.
gethookburst
   Retrieve sethookburst value.
setpacket
   Provide a packet template for locally-generated packets. A zero-sized
   packet disables this.
getpacket
   Retrieve packet template.

Usage
-----

The following examples refer to a ng_gen node named **foo** with an input hook
named **in_foo**.

Configuring rate and burst size to generate 1 pps from all hooks at once.
This also sets the default for future hooks and setpacket command:

.. code-block:: console

   # ngctl msg foo: setrate 1
   # ngctl msg foo: setburst 1

Setting per-hook rate to 42 bursts of 100 packets per second (4200 pps):

.. code-block:: console

   # ngctl msg foo: sethookrate '{ hook="in_foo" value=42 }'
   # ngctl msg foo: sethookburst '{ hook="in_foo" value=100 }'

Configuring and enabling spontaneous generation of 64-bytes packets, four of
which are defined (first three bytes and the last one), the rest is
zero-filled:

.. code-block:: console

   # ngctl msg foo: setpacket '{ size=64 data=[ 0x2a 0x2b 0x2c 63=0x2d ] }'

A string can also be specified. Note that the trailing NUL character must be
taken into account:

.. code-block:: console

   # ngctl msg foo: setpacket '{ size=4 data="foo" }'

Disabling spontaneous packet generation:

.. code-block:: console

   # ngctl msg foo: setpacket '{ size=0 }'

Traffic generation
------------------

This example describes how to generate traffic on an interface (**eth0_0**)
using packets coming from another (**eth1_0**) as input and a local template
at the same time (two input sources).

Creating ng_gen instance and connecting it to both interfaces:

.. code-block:: console

   # ngctl mkpeer eth1_0 gen lower in_foo
   # ngctl name eth1_0:lower foo
   # ngctl connect foo: eth0_0: out lower

Configuring **in_foo** hook to retransmit packets coming from **eth1_0** at 1
pps:

.. code-block:: console

   # ngctl msg foo: sethookrate '{ hook="in_foo" value=1 }'
   # ngctl msg foo: sethookburst '{ hook="in_foo" value=1 }'
   # ngctl msg foo: gethookburst '"in_foo"'
   Rec'd response "gethookburst" (8) from "foo:":
   Args:   { hook="in_foo" value=1 }

Configuring **foo** to additionally generate 64 byte packets:

.. code-block:: console

   # ngctl msg foo: getpacket
   Rec'd response "getpacket" (10) from "foo:":
   Args:   { size=0 data=[] }
   # ngctl msg foo: setpacket '{ size=64 data=[ 0x2a 0x2b 0x2c 63=0x2d ] }'
   # ngctl msg foo: getpacket
   Rec'd response "getpacket" (10) from "foo:":
   Args: { size=64 data=[ 0x2a 0x2b 0x2c 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
    0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
    0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
    0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x2d ] }
   # ngctl msg foo: getrate
   Rec'd response "getrate" (2) from "foo:":
   Args:   0
   # ngctl msg foo: getburst
   Rec'd response "getburst" (4) from "foo:":
   Args:   0
   # ngctl msg foo: setburst 1
   # ngctl msg foo: setrate 1

After this, both the last packet received on **eth1_0** and the packet defined
by the above setpacket command are sent to **eth0_0** at rates of 1 pps each
(2 pps total).

Shutting down **foo**:

.. code-block:: console

   # ngctl msg foo: shutdown
