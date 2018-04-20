Usage
=====

|fpn-sdk-add-on-dpdk| automatically starts when you start the |fp| with the
following script:

.. code-block:: console

   # fast-path.sh start

.. seealso::

   For more information on how to start the |fp|, see the relevant
   documentation.

Providing options
-----------------

The :file:`fast-path.sh` script reads the :file:`/usr/local/etc/fast-path.env`
configuration file before actually starting the |fp| and associated modules.

You can edit that file to start |fpn-sdk-add-on-dpdk| with the options relevant
to your platform, specified as variables.

You can use one of the following syntaxes:

+----------------------+-------------------------------+-----------------+
|Syntax                |Description                    |Example          |
+======================+===============================+=================+
|PARAMETER:=value      |Supersedes the corresponding   |FP_MASK=0x2      |
|                      |global environment variable, if|                 |
|                      |any.                           |                 |
+----------------------+-------------------------------+-----------------+
|: ${PARAMETER:=value} |Ignored if the corresponding   |: ${FP_MASK:=0x2}|
|                      |global environment variable    |                 |
|                      |exists.                        |                 |
+----------------------+-------------------------------+-----------------+

You can set the most common options via a dedicated variable such as *FP_MASK*
or *NB_HUGEPAGES*.

To set the least common options, use one of the following variables:

  - *EAL_OPTIONS*
       for the DPDK EAL options
  - *FPNSDK_OPTIONS*
       for the fpn-sdk options
  - *FP_OPTIONS*
       for the |fp| options

Specify them using the appropriate option delimiter (*-d* for plugins,
*--nb-mbuf* for the number of mbufs, etc.).

The sections below describe the most useful DPDK EAL options and specific |fp|
options.

FPN-SDK start-up options
------------------------

.. program:: FPN-SDK

.. option:: NB_MEM_CHANNELS=[nb_mem_channels]

   **Mandatory.** Define the total number of memory channels to be used by
   mbufs.

.. option:: FP_MASK=[coremask]

   **Mandatory.** Define which cores run the |fp|.

   You can specify the core mask either:

   - as an hexadecimal mask starting with *0x*, or
   - as a list of comma-separated cores and core ranges.

   .. rubric:: Example

   To run the |fp| on cores 0, 1, 2, 3, 5, 7, and 11, you can use one of the
   following:

   ::

      FP_MASK=0x8AF
      FP_MASK=0-3,5,7,11

.. option:: NB_HUGEPAGES=[nb_hugepages]

   Specify the number of 2048-byte huge pages to allocate before starting the
   |fp|. Default: 256 huge pages.

   This option must be set as the *NB_HUGEPAGES* variable in the configuration
   file or as an environment variable. It can not be specified on the command
   line.

   On a NUMA architecture, this option can be set in two ways:

   - As an integer
       The kernel distributes (usually evenly) hugepages over available nodes.
   - As a comma-separated list of integers
       Each element of the list is the number of hugepages allocated to the
       corresponding node.

   By default, DPDK uses all memory defined by huge pages.

.. option:: HUGEPAGES_DIR=[hugepages_dir]

   Specify the huge pages' mount point. Default: :file:`/mnt/huge`.

   This option must be set as the *HUGEPAGES_DIR* variable in the configuration
   file or as an enviroment variable. It can not be specified on the command
   line.

.. option:: FP_MEMORY=[memory]

   Define how much memory (in megabytes) from the hugepages is used by the |fp|.

.. option:: IGNORE_NETDEV=[netdev interfaces]

   Specify which net device interfaces are ignored by DPDK.

.. option:: EAL_OPTIONS=[EAL options]

   Specify additional EAL options.

.. rubric:: Examples

.. code-block:: bash

   # mbufs used 3 memory channels.
   # Supersedes the corresponding global environment variable, if any.
   NB_MEM_CHANNELS:=3

.. code-block:: bash

   # mbufs used 3 memory channels.
   # Ignored if the corresponding global environment variable exists.
   : ${NB_MEM_CHANNELS:=3}

.. code-block:: bash

   # The fast path runs on core 0x2.
   : ${FP_MASK:=0x2}

.. code-block:: bash

   # On a dual socket architecture, 1024 hugepages are allocated on each node.
   : ${NB_HUGEPAGES:=2048}

.. code-block:: bash

   # On a dual socket architecture, 2048 hugepages are allocated on node0, none
   # on node1.
   : ${NB_HUGEPAGES:=2048,0}

.. code-block:: bash

   # Huge pages are mounted on /run/mount/huge.
   : ${HUGEPAGES_DIR:=/run/mount/huge}

.. code-block:: bash

   # The fast path uses 256 Mb from the hugepages.
   : ${FP_MEMORY:=256}

.. code-block:: bash

   # Ignore interfaces eth0 and eth1.
   : ${IGNORE_NETDEV:=eth0 eth1}

.. code-block:: bash

   # Ignore PCI device whose bus address is 0000:00:01.0.
   : ${EAL_OPTIONS:=-b 0000:00:01.0}

Sharing port queues among cores
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Description

A per-queue locking mechanism allows to share a port's single RX queue or single
TX queue among |fp| cores. This allows to run multiple packet processing
cores in the |fp| on Ethernet controllers, such as the Intel® e1000 or the
Intel® Niantic VF, that only support one single RX queue and one single TX
queue. By default, the sharing of queues is disabled, and can be independently
enabled for RX queues or TX queues on a per-port basis.

.. program:: FPN-SDK

.. option:: --rxq-shared=PORTMASK

   Force a single RX queue to be created and shared for each port specified by
   *PORTMASK*.

.. option:: --txq-shared=PORTMASK

   Force a single TX queue to be created and shared for each port specified by
   *PORTMASK*.

*PORTMASK* is a mask of |nic| ports used by the |fp|. These ports are listed in
the following order:

#. Virtual interfaces.

#. Physical interfaces as listed by the *lspci* command.


.. rubric:: Example

.. code-block:: bash

   ###########################
   ##### FPN-SDK OPTIONS #####
   ###########################

   :${FPNSDK_OPTIONS:= --rxq-shared=0x50 --txq-shared=0x07}

Useful DPDK EAL options
-----------------------

Here are the most useful |eal| options:

.. program:: EAL

.. option:: -c <FP_MASK>

   Mandatory. Specify the cores allocated to the |fp|. The FP mask has to
   be calculated depending on your platform, as explained in the `CPU mask
   calculation`_ section.

   Alternately, you can set *: ${FP_MASK:=<value>}* in the configuration file.

.. option:: -n <NB_MEM_CHANNELS>

   Mandatory. Specify the number of memory channels, from 1 to 4.  For instance,
   Intel® Sandy Bridge boards support 4 channels, Westmere boards support 3
   channels.

   Alternately, you can set *: ${NB_MEM_CHANNELS:=<value>}* in the configuration
   file.

   This parameter may impact performance.

.. option:: --no-hpet

   Recommended to avoid using slow HPET clock.

.. option:: -d[add-on library]

   Optional.
   Load a |6wg-dpdk| add-on library.
   *add-on library* is the shared library implementing the add-on.

   To load the Quickassist DPDK library, for instance:

   .. code-block:: console

      -dlibrte_crypto_quickassist.so

.. option:: -b <PCI bus address>

   Optional. Blacklist a PCI device. Example of PCI bus address:
   *0000:03:00:0*. By default, the |fp| manages all probed ports. Useful
   for skipping some ports and letting the ownership to Linux.
   This option cannot be used if a device is whitelisted.

.. option:: -w <PCI bus address>

   Optional. Whitelist a PCI device. Example of PCI bus address:
   *0000:03:00:0*. By default, the |fp| manages all probed ports.
   If this option is used, the fast path will only manage the
   specified devices. This option cannot be used if a device is
   whitelisted.

Any other |eal| option can be passed
by modifying the *EAL_OPTIONS* variable.

.. seealso::

   For the full list of options, see the DPDK documentation.

Fast path options
-----------------

Port options
~~~~~~~~~~~~

.. rubric:: Parameters

.. program:: FPN-SDK

.. option:: -q[1G queue number]

   Optional. Specify the number of 1GB ports handled per logical core, from 1
   to 16 (default is 8). Cannot be used together with -t.

.. option:: -Q[10G queue number]

   Optional. Specify the number of 10GB ports handled per logical core, from 1
   to 16 (default is 1). Cannot be used together with -t.

.. option:: --rxq-per-port[queues per 10G port]

   Optional. Specify the number of queues per 10GB port. Useful when using
   automatic mapping of cores to ports (default is 1 queue per port). Cannot be
   used together with -t.

Core / Port binding
~~~~~~~~~~~~~~~~~~~

.. rubric:: Parameters

.. program:: FPN-SDK

.. option:: -t [CORE_PORT_MAPPING]

   Optional. Map a logical core to a network port. This option overrides the
   :option:`-q` and :option:`-Q` options described above.

   `CORE_PORT_MAPPING` is of the form: `[processor id]=[port id]`

   *processor id* is the processor ID as seen by Linux (decimal value), preceded
   by "c". You can specify different processor ids via the "/" (slash)
   character.

   *port id* is the port number. You can specify different port ids via the ":"
   (colon) character.

   If more than one core is mapped to a same logical port, then |rss| is
   automatically enabled.

   Alternately, you can specify *: ${CORE_PORT_MAPPING:=<value>}* in the
   configuration file.

.. note::

   The |rss| feature uses a hash mechanism to
   distribute the flows over different cores.

.. rubric:: Examples

.. code-block:: console

   # CORE_PORT_MAPPING=c10=0/c8=0/c6=1/c4=1 fast-path.sh start

4 logical cores are used to poll 2 ports with |rss|
enabled:

- Port #0 is polled by logical cores #8 and #10
- Port #1 is polled by logical cores #4 and #6

.. code-block:: console

   # CORE_PORT_MAPPING=c2=0:1/c4=2:3 fast-path.sh start

2 logical cores are used to poll 4 ports:

- Port #0 is polled by logical core #2
- Port #1 is polled by logical core #2
- Port #2 is polled by logical core #4
- Port #3 is polled by logical core #4

Intercore implementation
~~~~~~~~~~~~~~~~~~~~~~~~

The following functions have been added to the DPDK *mbuf* api:

- *m_set_process_fct()*
- *m_call_process_fct()*

These functions use *mbuf* headroom to store a *fpn_callback* structure.

To avoid updating *mbuf* internal pointers, *m_prepend/m_adj* functions are not
used, yet the checks on available lengths in headroom are the same.

Since we don't call *m_prepend/m_adj*, once *m_set_process_fct()* has been
called, no operation can be done on *mbuf* until *m_call_process_fct()* is
called.

Software scheduling implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The software scheduling API is implemented on top of the DPDK
*librte_sched* library.

Linux / |fp| communication
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. rubric:: Parameters

.. program:: FPN-SDK

.. option:: -l <exception mask>

   Specify the |fp| cores involved in polling packets coming from Linux
   over |dpvi| interfaces. By default, all
   cores specified in *fp_mask* are used. All packets locally sent by the Linux
   stack are forwarded to the |fp| and processed by the selected cores.

.. option:: -e <DPVI_MASK>

   Specify the |cp| cores selected to process exception packets issued
   by the |fp|. The default is the first core of the oneline cpu which does
   not belong to the |fp| mask. The |fp| relies on |rss|
   or on the flow director tag value to select the
   |dpvi| core.

   Alternately, you can specify *: ${DPVI_MASK:=<value>}* in the configuration
   file.

.. option:: -x <lcore id for exception>

   Mandatory if compiled with TUN/TAP driver instead of DPVI (CONFIG_MCORE_FPVI_TAP=y):
   specify the |fp| core implementing the FPVI.

   Alternately, you can specify *: ${EXC_LCOREID:=<value>}* in the configuration
   file.

RX/TX descriptors and thresholds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: Parameters

.. program:: FPN-SDK

.. option:: --nb-mbuf=[mbuf number]

   Optional. Specify the number of *mbufs* to add in the pool, from 1 to
   16777215 (default is 16384).

   Alternately, you can set *: ${NB_MBUF:=<value>}* in the configuration file.

   The following rule is used to calculate the value of this option:

   .. code-block:: console

      nb-mbuf >= (nb_port * nb_rxq * (nb_rxd + 32))
      + (nb_port * nb_txq * nb_txd)
      + (nb_core_fp * nb_core_dpvi * 2 ** n)

   nb_port
      Number of ports.
   nb_rxq
      Number of RX queues in the |nic|.
   nb_txq
      Number of TX queues in the |nic|.
   nb_rxd
      Number of RX descriptors allocated to the |nic|.
   nb_txd
      Number of TX descriptors allocated to the |nic|.
   nb_core_fp
      Number of cores allocated to the |fp|.
   nb_core_dpvi
      Total number of cores - number of cores used by |fp|
   2 ** n
      2 to the power of the CONFIG_MCORE_FPN_DRING_ORDER value (found in
      :file:`/usr/local/6WINDGate/etc/fpnsdk.config`).

   .. note::

      For TCP use at least 1 million mbufs, since this protocol retransmits lost
      packets (the actual number depends on your TCP window size).

.. option:: --nb-rxd=[RX descriptor number]

   Optional. Specify the number of RX descriptors allocated to the |nic|
   (default is 128).

.. option:: --nb-txd=[TX descriptor number]

   Optional. Specify the number of TX descriptors allocated to the |nic|
   (default is 512).

.. option:: --igb-rxp=[RX prefetch threshold]

   Optional. Specify the prefetch threshold of IGB RX rings (default is 8).

.. option:: --igb-rxh=[RX host threshold]

   Optional. Specify the host threshold of IGB RX rings (default is 8).

.. option:: --igb-rxw=[RX write back threshold]

   Optional. Specify the write-back threshold of IGB RX rings (default is 16).

.. option:: --igb-txp=[TX prefetch threshold]

   Optional. Specify the prefetch threshold of IGB TX rings (default is 8).

.. option:: --igb-txh=[TX host threshold]

   Specify the host threshold of IGB TX rings (default is 4). This parameter is
   optional.

.. option:: --igb-txw=[TX write back threshold]

   Optional. Specify the write-back threshold of IGB TX rings (default is 16).

.. option:: --fdir-conf=([portid=])mode/memorysize/reportstatus/flexoffset/dropqueue

   Optional. Set Flow Director configuration for all ports or portid if
   specified. This feature is only available on ixgbe ports.

   mode
      'perfect' is the only mode supported at the moment.
   memorysize
      Possible values are '64k', '128k', '256k'. This value has a direct impact
      on the number of Flow Director filters available.
   reportstatus
      Possible values are 'noreport', 'report', 'always'. Instruct hardware to
      report the hash value that it computed.
   flexoffset
      If using Flow Director filters using flexbytes values, set the offset that
      will be used for them (must be set at init time and can not be changed
      without restarting the application).
   dropqueue
      If using Flow Director filters with drop flag set, set the queue where
      packets will be received (and if queue is not enabled, then packets will
      finally be dropped).

   Typical configuration:
      --fdir-conf=perfect/64k/noreport/0/127

Debug command line
~~~~~~~~~~~~~~~~~~

.. rubric:: Synopsis

.. code-block:: console

   # fpn-sdk-app [EAL options] -- [FPN-SDK options] -c <core_num> -- -f <filename>

.. rubric:: Parameters

.. program:: debug

.. option:: -c <core_num>

   Start the fp-cli command line on the specified core. This core must be
   included in the EAL core mask, and it must not be the first core of the mask
   (least significant bit). The embedded fp-cli command line provides an
   interface to configure the run-time options of the |fp| and to monitor
   statistics.

.. option:: -f <filename>

   With this option, the user can provide a configuration file (fp-cli format)
   that is executed by the |fp| at start up. This option can appear
   several times with different files: in this case, the files are evaluated in
   the same order as arguments lists.

CPU mask calculation
--------------------

You can specify how many cores are allocated to the FPN-SDK application with the
:option:`-c` option.

The CPU mask is obtained by a logical OR between the unique identifiers of the
logical cores to be used.

.. note::

   The unique identifier of a given logical core is the hexadecimal value of
   2^N, where N is the logical core number.

As logical core numbering is platform dependent, we advise you to use
*/proc/cpuinfo* to draw a table showing the mapping between sockets (physical
ids), physical cores (core ids) and logical cores (processors) for your
platform.

Mono socket Intel® Xeon X5570 processors (Nehalem)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Mono-socket platform with 4 physical cores and 2 logical cores per physical
core.

+-----------------------------------+-------------+------+
|     cat /proc/cpuinfo output      |             |      |
+-------------+---------+-----------+ binary mask | mask |
| physical id | core id | processor |             |      |
+-------------+---------+-----------+-------------+------+
|      0      |    0    |     0     |   00000001  | 0x01 |
+-------------+---------+-----------+-------------+------+
|      0      |    0    |     4     |   00010000  | 0x10 |
+-------------+---------+-----------+-------------+------+
|      0      |    1    |     1     |   00000010  | 0x02 |
+-------------+---------+-----------+-------------+------+
|      0      |    1    |     5     |   00100000  | 0x20 |
+-------------+---------+-----------+-------------+------+
|      0      |    2    |     2     |   00000100  | 0x04 |
+-------------+---------+-----------+-------------+------+
|      0      |    2    |     6     |   01000000  | 0x40 |
+-------------+---------+-----------+-------------+------+
|      0      |    3    |     3     |   00001000  | 0x08 |
+-------------+---------+-----------+-------------+------+
|      0      |    3    |     7     |   10000000  | 0x80 |
+-------------+---------+-----------+-------------+------+

.. rubric:: Example

<cpu mask>=0x01
   Use the first logical core of the first physical core.
<cpu mask>=0x22
   Use all logical cores of the second physical core.
<cpu mask>=0x0f
   Use the first logical cores of all physical cores.

Dual Socket Intel® Xeon X5570 processors (Nehalem)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dual-socket platform with 4 physical cores per socket and 2 logical cores per
physical core.

+-----------------------------------+----------------------+----------+
|     cat /proc/cpuinfo output      |                      |          |
+-------------+---------+-----------+      binary mask     |   mask   |
| physical id | core id | processor |                      |          |
+-------------+---------+-----------+----------------------+----------+
|      0      |    0    |     0     |  0000 0000 0000 0001 |  0x0001  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    0    |     8     |  0000 0001 0000 0000 |  0x0100  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    1    |     2     |  0000 0000 0000 0100 |  0x0004  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    1    |    10     |  0000 0100 0000 0000 |  0x0400  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    2    |     4     |  0000 0000 0001 0000 |  0x0010  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    2    |    12     |  0001 0000 0000 0000 |  0x1000  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    3    |     6     |  0000 0000 0100 0000 |  0x0040  |
+-------------+---------+-----------+----------------------+----------+
|      0      |    3    |    14     |  0100 0000 0000 0000 |  0x4000  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    0    |     1     |  0000 0000 0000 0010 |  0x0002  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    0    |     9     |  0000 0010 0000 0000 |  0x0200  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    1    |     3     |  0000 0000 0000 1000 |  0x0008  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    1    |    11     |  0000 1000 0000 0000 |  0x0800  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    2    |     5     |  0000 0000 0010 0000 |  0x0020  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    2    |    13     |  0010 0000 0000 0000 |  0x2000  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    3    |     7     |  0000 0000 1000 0000 |  0x0080  |
+-------------+---------+-----------+----------------------+----------+
|      1      |    3    |    15     |  1000 0000 0000 0000 |  0x8000  |
+-------------+---------+-----------+----------------------+----------+

.. rubric:: Example

<cpu mask>=0x5555
   Use all logical cores on socket 0.
<cpu mask>=0xaaaa
   Use all logical cores on socket 1.
<cpu mask>=0x00ff
   Use the first logical cores of all physical cores on all sockets.

Dual Socket Intel® Xeon E5645 processors (Westmere)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+-----------------------------------+-------------------------------+----------+
|     cat /proc/cpuinfo output      |                               |          |
+-------------+---------+-----------+          binary mask          |   mask   |
| physical id | core id | processor |                               |          |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    0    |     0     | 0000 0000 0000 0000 0000 0001 | 0x000001 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    0    |    12     | 0000 0000 0001 0000 0000 0000 | 0x001000 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    1    |     2     | 0000 0000 0000 0000 0000 0100 | 0x000004 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    1    |    14     | 0000 0000 0100 0000 0000 0000 | 0x004000 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    2    |     4     | 0000 0000 0000 0000 0001 0000 | 0x000010 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    2    |    16     | 0000 0001 0000 0000 0000 0000 | 0x010000 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    8    |     6     | 0000 0000 0000 0000 0100 0000 | 0x000040 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    8    |    18     | 0000 0100 0000 0000 0000 0000 | 0x040000 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    9    |     8     | 0000 0000 0000 0001 0000 0000 | 0x000100 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |    9    |    20     | 0001 0000 0000 0000 0000 0000 | 0x100000 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |   10    |    10     | 0000 0000 0000 0100 0000 0000 | 0x000400 |
+-------------+---------+-----------+-------------------------------+----------+
|      0      |   10    |    22     | 0100 0000 0000 0000 0000 0000 | 0x400000 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    0    |     1     | 0000 0000 0000 0000 0000 0010 | 0x000002 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    0    |    13     | 0000 0000 0010 0000 0000 0000 | 0x002000 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    1    |     3     | 0000 0000 0000 0000 0000 1000 | 0x000008 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    1    |    15     | 0000 0000 1000 0000 0000 0000 | 0x008000 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    2    |     5     | 0000 0000 0000 0000 0010 0000 | 0x000020 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    2    |    17     | 0000 0010 0000 0000 0000 0000 | 0x020000 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    8    |     7     | 0000 0000 0000 0000 1000 0000 | 0x000080 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    8    |    19     | 0000 1000 0000 0000 0000 0000 | 0x080000 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    9    |     9     | 0000 0000 0000 0010 0000 0000 | 0x000200 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |    9    |    21     | 0010 0000 0000 0000 0000 0000 | 0x200000 |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |   10    |    11     | 0000 0000 0000 1000 0000 0000 |   0x800  |
+-------------+---------+-----------+-------------------------------+----------+
|      1      |   10    |    23     | 1000 0000 0000 0000 0000 0000 | 0x800000 |
+-------------+---------+-----------+-------------------------------+----------+

.. rubric:: Example

<cpu mask>=0x001001
   Use all logical cores of the first physical core.
<cpu mask>=0xaaaaaa
   Use all logical cores on socket 1.

Fast path plugins options
-------------------------

.. program:: fast path plugins

.. option:: -p plugin.so

   Optional. Load a |fp| plugin. Multiple plugins can be loaded by
   specifying multiple -p options.

   Regardless of whether *-p* is specified or not, all plugins matching the
   pattern :file:`/usr/local/lib/fastpath/*.so` are loaded first. You can
   edit the autoload path via the environment variable *FP_PLUGINS*.

.. rubric:: Examples

.. code-block:: console

   fp-rte [...]

(Without the *-p* argument and without exporting *FP_PLUGINS*.)

Load all plugins from :file:`/usr/local/lib/fastpath/*.so` and
:file:`/usr/local/lib/fp-cli/*.so`.

.. code-block:: console

   fp-rte [...] -p '/path/to/my_plugin.so'

Load all plugins from :file:`/usr/local/lib/fastpath/*.so` and
:file:`/path/to/my_plugin.so`.

.. code-block:: console

   FP_PLUGINS="/another_path/to/*.so" fp-rte [...]

Load all plugins from :file:`/another_path/to/*.so`.

.. code-block:: console

   FP_PLUGINS="/another_path/to/*.so" fp-rte [...] -p '/path/to/my_plugin.so'

Load all plugins from :file:`/another_path/to/*.so` and
:file:`/path/to/my_plugin.so`.
