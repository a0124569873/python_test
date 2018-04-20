.. Copyright 2013 6WIND S.A.

.. title:: |flow-inspection|

About |flow-inspection|
=======================

|flow-inspection| provides the ability to
analyze packets coming in and out of the |fp| interfaces (*a la tcpdump*).

Features
--------

- Packets capture in Linux by means of standard tools like *tcpdump*
- BPF filtering automatic configuration in |fp|

The |fp| still processes the original packets while a copy is sent to
the Linux stack for display only.

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fpbase|

Installation
------------

See the |qsg|.
