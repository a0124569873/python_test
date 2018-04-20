.. Copyright 2014 6WIND S.A.

Usage
=====

set-force-reassembly6
---------------------

.. rubric:: Description

Sets force reassembly flag for IPv6.

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

reass6-maxqlen
--------------

.. rubric:: Description

Set/show IPv6 maximum queue length for reassembly.

.. rubric:: Synopsis

.. code-block:: fp-cli

   reass6-maxqlen [LEN]

.. rubric:: Parameters

No parameter
   Show maximum queue length.
LEN
   Maximum queue length for IPv6 reassembly.

.. rubric:: Example

.. code-block:: fp-cli

   <fp-0> reass6-maxqlen
   IPv6 reass. max queue length: 10

.. code-block:: fp-cli

   <fp-0> reass6-maxqlen 16

.. code-block:: fp-cli

   <fp-0> reass6-maxqlen
   IPv6 reass. max queue length: 16
