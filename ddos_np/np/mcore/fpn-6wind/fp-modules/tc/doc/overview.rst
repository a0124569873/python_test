.. Copyright 2014 6WIND S.A.

.. title:: |fp-qos-tc|

About |fp-qos-tc|
=================

|fp-qos-tc| is a feature of |fp-qos| that provides traffic conditioning.

It implements a token bucket or a two-rate three-color marker used to color the
packet in green, yellow or red depending on the packet flow rate. Packet rate
limitation can be done by dropping packets marked red for example.

Features
--------

- :rfc:`4115` two-rate three-color marker
- Color-aware and color-blind support
- Per packets or per bytes accounting
- FPN-SDK |tc| API
- Exception Rate Limitation to limit the rate of packets sent as exceptions
  from |fp| to Linux

The implementation is based on :rfc:`4115`. The operation of the marker is
described by two rate values.  The Committed Information Rate (CIR) and the
Excess Information Rate (EIR).  CIR and EIR define the token generation rate of
a token bucket with size that is equal to Committed Burst Size (CBS) and Excess
Burst Size (EBS), respectively.

In addition to CIR, EIR, CBS and EBS, the API proposes to count either per-bytes
or per-packets, and to rely or not on current packet color (color-aware or
color-blind).

The algorithm is as follows, with Tc(t) and Te(t) the current number of tokens
for the CIR and EIR respectively:

- When a green packet of size B (B = 1 in case of per-packets counting) arrives
  at time t, then

  - if Tc(t)- B > 0, the packet is green, and Tc(t) is decremented by B

  - else if Te(t)- B > 0, the packet is yellow, and Te(t) is decremented by B

  - else the packet is red.

- When a yellow packet of size B arrives at time t, then

  - if Te(t)- B > 0, the packet is yellow, and Te(t) is decremented by B

  - else the packet is red.

- In color-blind operation, the algorithm assumes that the packet is green.

- Incoming red packets are not tested against any of the two token buckets and
  remain red.

Two features implemented in the |fp| use the |tc| API:

- Rate limitation of exceptions packets (MCORE_TC_ERL option), using instance 0,

- DSCP marking of IP packets. (MCORE_TC_DSCP option), using instances 1 to
  FP_TC_DSCP_MAX.

Instances in the range from FP_TC_DSCP_MAX and FP_TC_MAX are free for other
features.

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|
- |fp-qos|

Installation
------------

See the |qsg|.
