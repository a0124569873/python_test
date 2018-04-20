.. Copyright 2014 6WIND S.A.

Usage
=====

set-force-reassembly
--------------------

.. rubric:: Description

Sets force reassembly flag for IPv4.

.. rubric:: Synopsis

.. code-block:: fp-cli

   set-force-reassembly IFNAME on|off

.. rubric:: Parameters

IFNAME
   Name of the interface in human reading form, must be unique.
on|off
   Enable reassembly.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> set-force-reassembly eth0 on

reass4-maxqlen
--------------

.. rubric:: Description

Set/show IPv4 max queue length for reassembly.

.. rubric:: Synopsis

.. code-block:: fp-cli

   reass4-maxqlen [LEN]

.. rubric:: Parameters

No parameter
   Show max queue length.
LEN
   Maximum queue length for IPv4 reassembly.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> reass4-maxqlen
   IPv4 reass. max queue length: 10

.. code-block:: fp-cli

   <fp-0> reass4-maxqlen 13

.. code-block:: fp-cli

   <fp-0> reass4-maxqlen
   IPv4 reass. max queue length: 13
