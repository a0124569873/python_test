.. Copyright 2014 6WIND S.A.

.. title:: |vnb-l2tp|

About |vnb-l2tp|
================

|vnb-l2tp| provides |l2tp-long| support in the |fp| as a VNB node.

Features
--------

:rfc:`2661` compatible node:

- ng_l2tp: provides support of PPP frames over a layer 3 connection.

  A L2TP frame typically looks like this (abstract from :rfc:`2661`):

.. aafig::

   +--------------------+
   |'PPP Frames'        |
   +--------------------+    +-----------------------+
   |'L2TP Data Messages'|    |'L2TP Control Messages'|
   +--------------------+    +-----------------------+
   |'L2TP Data Channel' |    |'L2TP Control Channel' |
   |'(unreliable)'      |    |'(reliable)'           |
   +--------------------+----+-----------------------+
   |      'Packet Transport (UDP, FR, ATM, etc.)'    |
   +-------------------------------------------------+

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |vnb-ppp|

Installation
------------

See the |qsg|.
