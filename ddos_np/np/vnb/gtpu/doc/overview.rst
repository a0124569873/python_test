.. Copyright 2014 6WIND S.A.

.. title:: Fast Path VNB GTP-U

About |vnb-gtpu| and |gtpuctl|
==============================

About |vnb-gtpu|
----------------

|vnb-gtpu| provides |gtpu-long| support in the |fp| as a |vnb| node.

Features
~~~~~~~~

3GPP TS 29.060 compatible node:

- ng_gtpu

  Provides |gtpu| tunnels support. Used for carrying user data within the |gprs|
  Core Network and between the Radio Access Network and the core network.
  Located in the User Plane.

Dependencies
~~~~~~~~~~~~

6WINDGate modules
+++++++++++++++++

- |vnb-baseline|

About |gtpuctl|
---------------

The |gtpuctl| utility is used for creating |gtpu| tunnels.

|gtpuctl| design goals
~~~~~~~~~~~~~~~~~~~~~~

|gtpuctl| has been designed to replace shell scripts for the configuration of
the |gtpu| tunnels on both PDN GSN and serving GSN.

Using "C" source code, gtpuctl can configure a large number of |gtpu| tunnels in
a small time (for example, 1M tunnels in around 6 minutes on an Octeon target).

Features
~~~~~~~~

- Create |gtpu| tunnels
- Delete |gtpu| tunnels
- PDN GW mode: tunnels are terminated
- Serving GW mode: tunnels are relayed


Installation
------------

See the |qsg|.
