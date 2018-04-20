.. Copyright 2014 6WIND S.A.

Usage
=====

Using fp-cli to configure |tc| in |6wg| |fp|
--------------------------------------------

|6wg| |fp| implements a proxy over NETFPC channel for fp-cli tool to interact
with FPN-SDK API.

To configure a |tc|, the syntax is:

.. code-block:: fp-cli

   tc-set <id> <committed rate>  <committed depth> <excess rate> <excess depth> \[GMK][pps|bps]

The value of 0 for committed depth will disable a |tc|.

To list one or all configured |tc| with statistics, the syntax is:

.. code-block:: fp-cli

   dump-tc  <id> | all

To reset the statistics:

.. code-block:: fp-cli

   tc-reset <id> all
