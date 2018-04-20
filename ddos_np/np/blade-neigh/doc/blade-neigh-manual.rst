.. Copyright 2013 6WIND S.A.

.. title:: Blade neighbour module

This module hooks to neighbour notifications, and in inactive mode,
prevents entries from falling, by putting any entry that changes state
to DELAY, STALE or PROBE in REACHABLE state.

A switch from inactive to active is followed by a period of time (30s
by default) during which the inactive behavior is still applied, to
avoid loosing entries during that time.

It is used in HA mode only, along with hao-arpd.

Features
========

- Procfs interface to configure activity and duration

Dependencies
============

None

Usage
=====

The module should be inserted first:

.. code-block:: console

   # modprobe blade-neigh

We can check that its insertion worked well (failures are reported in
dmesg).

To switch the module to active/inactive mode:

.. code-block:: console

   # echo 1 > /proc/sys/blade-neigh/active
   # echo 0 > /proc/sys/blade-neigh/active

To configure the duration of inactive to active transition, during
which the inactive behavior continues:

.. code-block:: console

   # echo 30 > /proc/sys/blade-neigh/gracetime
