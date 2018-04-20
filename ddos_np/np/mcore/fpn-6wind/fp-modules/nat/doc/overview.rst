.. Copyright 2013 6WIND S.A.

.. title:: |fp-nat|

About |fp-nat|
==============

|fp-nat| provides Network Address Translation in the |fp|.

To ensure maximal performance, this module implements simple functions based on
information found in the |shmem|.

If the module cannot find in the |shmem| the relevant information based on
L3, L4, and L5 headers, the |fp| raises an exception.

In accordance with configured filter rules with higher priorities, this
exception:

- interacts with other |6wg| entities, or,
- drops the packet for security reasons.

Features
--------

- Static and ALG-less NAT/PAT

Dependencies
------------

6WINDGate modules
~~~~~~~~~~~~~~~~~

- |fp-filtering4|

Linux
~~~~~

- Netfilter: create audit records for x_tables replaces is a kernel patch
  (upstream 3.9)

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=fbabf31e4d482149b5e

- |rpfilter| netfilter export xt_rpfilter.h to
  userland is a kernel patch (upstream 3.12)

  http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=f0c03956ac40fdc4fb

Installation
------------

See the |qsg|.
