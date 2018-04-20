.. Copyright 2014 6WIND S.A.

.. title:: |fp-qos-tc-erl|

About |fp-qos-tc-erl|
=====================

|fp-qos-tc-erl| is a feature of |fp-qos| that limits the rate of packets sent as
exceptions from the |fp| to Linux.

Features
--------

- Exception Rate Limitation to limit the rate of packets sent as exceptions
  from the |fp| to Linux

When the MCORE_TC_ERL option is enabled, the |fp| uses the TRTCM id 0 to limit
the rate of exceptions sent to the slow path.

A priority is associated with each exception: low, medium and high. The pass or
drop action depends on this priority and the packet color, as marked by the
TRTCM:

- If exception priority is low, green packets pass and yellow or red packets are
  dropped,

- If exception priority is medium, green and yellow packets pass, and red
  packets are dropped,

- If exception priority is high, packets pass,

- If exception priority is unknown, packets are dropped.

Whenever a packet is found to be an exception, a class value (8 bits) is
associated with it:

- The two most significant bits define the priority of the exception (3 for high
  priority, 2 for medium, 1 for low, and 0 for unknown),

- The six last significant bits define the type of the exception (ARP is
  required; IKE negotiation is needed, etc.).

The default setting is low priority for all exceptions type, so that a simple
token bucket is used to let packets go through or to drop them.

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fp-qos-tc|

Installation
------------

See the |qsg|.
