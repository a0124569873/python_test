.. Copyright 2013 6WIND S.A.

.. title:: Fast Path Plugin: egress_qos Example

About *egress_qos*
==================

Features
--------

This plugin is an example of how to write a plugin that gets all packets
received by the |fp| application in the *fp_if_output* hook, then schedules
them using the *fpn_sw_sched* API.

Dependencies
------------

6WINDGate modules
-----------------

- |fpbase|

Installation
------------

See the |qsg|.
