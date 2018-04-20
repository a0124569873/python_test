.. Copyright 2013 6WIND S.A.

Usage
=====

|fpn-sdk| is a library and a framework on which you can build your portable
application.

Application
-----------

Application initialization:

   .. code-block:: c

      /* SDK specific initialization */
      fpn_sdk_init(argc, argv);

      /* Register your packet handler called from FPN-SDK main loop function */
      ops = { .input = rx_packet_handler };
      fpn_register_mainloop_ops(&ops);

      /* Run default FPN-SDK main loop on all available core */
      fpn_job_run_oncpumask(&fpn_coremask, fpn_main_loop, NULL, FPN_JOB_SKIP_NONE);

Application packet processing:

   .. code-block:: c

      void rx_packet_handler(struct mbuf *m)
      {
        /* read incoming port */
        port = m_input_port(m);

       /* ARP go to Linux  */
       eth = mtod(m, struct fpn_ether_header *);
       if (eth->ether_type == htons(0x806)) {
           fpn_send_exception(m, port);
           return;
       }

       /* remove ethernet header */
       m_adj(m, 14);

       /* add custom header */
       m_prepend(m, 32);
       data = mtod(m, struct custom *);
       data->field = m_len(m);

       /* send it back */
       fpn_send_packet(m, port);
       }

Application Makefile:

   .. code-block:: make

      FPNSDK_DIR?=/usr/local/fpn-sdk
      OUTPUT = myapp
      S?=$(CURDIR)

      SRCS     := $(S)/myapp.c

      include $(FPNSDK_DIR)/mk/fpn-prog.mk

.. seealso::

   *L2-switch* example.

Tools
-----

cpu-usage
~~~~~~~~~

.. rubric:: Description

Display the number of percents of cpu usage spent to process
packets.

.. rubric:: Synopsis

.. code-block:: console

   # cpu-usage

.. rubric:: Example

.. code-block:: console

   # cpu-usage
   Fast path CPU usage:
   cpu: %busy     cycles
     8:   99%  544651672
     9:  100%  544605376
    10:  100%  544719036
    11:  100%  544679220
    24:   99%  544752300
    25:   99%  543468684
    26:  100%  544732856
    27:   99%  544706976
   average cycles/packets received from NIC: 816 (4356316120/5334336)

fp-shmem-ports
~~~~~~~~~~~~~~

.. rubric:: Description

Display and configure the parameters of detected ports at |fpn-sdk| level.

.. rubric:: Synopsis

.. code-block:: console

   # fp-shmem-ports <action> <options>

.. rubric:: Parameters

.. program:: fp-shmem-ports

.. option:: -d, --dump

   Display FPN-SDK port information.

.. option:: -a, --add_vlan

   Add a |vlan| port. Use the *-i* option to specify the |vlan| identifier.

.. option:: -l <pkt_size>, --sw_lro=<pkt_size>

   Set software LRO (Large Receive Offload). *pkt_size* is the maximum size
   of coalesced packets. To disable LRO, set *pkt_size* to 0.

.. option:: -t <boolean>, --force_tso=<boolean>

   Enable TSO (TCP Segmentation Offload) on this port. When this option is
   enabled, any TCP packet larger than the MTU is segmented by the hardware.

.. option:: -e <eth_port>|all|ALL, --eth_port=<eth_port>|all|ALL

   Select a given FPN-SDK port. *all* means all enabled ports, and *ALL* means
   all ports, enabled or disabled.

.. option:: -i <vlan_id>, --vlan_id=<vlan_id>

   Select the |vlan| identifier. Used with *-a*.

.. option:: -p <vlan_pcp>, --vlan_pcp=<vlan_pcp>

   Select the |vlan| priority code point. Used with *-a*.

.. option:: -m <mac_addr>, --mac=<mac_addr>

   Select the MAC address. Used with *-a*.

.. rubric:: Examples

- Display FPN-SDK port information:

   .. code-block:: console

      # fp-shmem-ports --dump
      port 0: mac 52:54:00:12:34:56 RX_CAP 0x0 TX_CAP 0xc eth0_0

  To decode RX and TX CAP values, see the flag definitions below:

     .. code-block:: console

       VLAN_INSERT 0x0001
       IPv4_CKSUM  0x0002
       TCP_CKSUM   0x0004
       UDP_CKSUM   0x0008
       TCP_TSO     0x0010

- Enable Large Receive Offload on all enabled ports (the maximum reassembled
  packet size is set to 9000):

   .. code-block:: console

      # fp-shmem-ports --sw_lro=9000 --eth_port=all

- Force TCP Segmentation Offload at MTU on port 2:

   .. code-block:: console

      # fp-shmem-ports --force_tso=1 --eth_port=2

fp-shmem-ready
~~~~~~~~~~~~~~

.. rubric:: Description

Display the name of the |shmem| if it is ready for mapping, or *Not found*
if it is not available.

The tool can be used in a script as a sentinel to synchronize multiple
applications, because the process of adding a new very large |shmem|
instance may take a long while.

.. rubric:: Synopsis

.. code-block:: console

   # fp-shmem-ready

.. rubric:: Example

.. code-block:: console

    # fp-shmem-ready fp-shared
    fp-shared
    # fp-shmem-ready unknown-name
    Not found

fp-track-dump
~~~~~~~~~~~~~

.. rubric:: Description

Display the per core history of function names recorded in your application by
the *FPN_RECORD_TRACK()* macro. Can help detect infinite loops.

.. rubric:: Synopsis

.. code-block:: console

   # fp-track-dump

.. rubric:: Example

.. code-block:: c

   myfunction()
     while () {
       FPN_RECORD_TRACK();
       ...
 }

 fp-track-dump
 Core 0
        [23] PC=0x4ec59b RA=0x4e793e Func=myfunction:133 cycles=5383286
        [22] PC=0x4ec341 RA=0x4e793e Func=myfunction:133 cycles=1430467202
        [21] PC=0x4ec59b RA=0x4e793e Func=myfunction:133 cycles=5381148
        [20] PC=0x4ec341 RA=0x4e793e Func=myfunction:133 cycles=715474104
 ...
 Core 1
        [31] PC=0x4ec59b RA=0x4e793e Func=myfunction:133 cycles=5383286
        [30] PC=0x4ec341 RA=0x4e793e Func=myfunction:133 cycles=1430467202
 ...

fp-intercore-stats
~~~~~~~~~~~~~~~~~~

.. rubric:: Description

Display the state of intercore structures.

By default, only cores belonging to the intercore mask are displayed. To display
all cores, use the *--all* parameter.


*fp-intercore-stats* can also display the number of cycles spent on packets that
went through the pipeline.

.. rubric:: Synopsis

.. code-block:: console

   # fp-intercore-stats

.. rubric:: Examples

.. code-block:: console

   # fp-intercore-stats
   Intercore information
         mask 0x4004
   Core 2
   ring <fpn_intercore_2>
     size=512
     ct=0
     ch=0
     pt=0
     ph=0
     used=0
     avail=511
     watermark=0
     bulk_default=1
     no statistics available
   Core 14
   ring <fpn_intercore_14>
     size=512
     ct=0
     ch=0
     pt=0
     ph=0
     used=0
     avail=511
     watermark=0
     bulk_default=1
     no statistics available

.. code-block:: console

   # fp-intercore-stats --all
   Intercore information
        mask 0x4004
   Core 0 (NOT IN MASK)
   ring <fpn_intercore_0>
    size=512
    ct=0
    ch=0
    pt=0
    ph=0
    used=0
    avail=511
    watermark=0
    bulk_default=1
    no statistics available
   Core 1 (NOT IN MASK)
   ring <fpn_intercore_1>
    size=512
    ct=0
    ch=0
    pt=0
    ph=0
    used=0
    avail=511
    watermark=0
    bulk_default=1
    no statistics available
   Core 2
   ring <fpn_intercore_2>
    size=512
    ct=0
    ch=0
    pt=0
    ph=0
    used=0
    avail=511
    watermark=0
    bulk_default=1
    no statistics available
   ...

.. code-block:: console

   # fp-intercore-stats --cpu
   Fast path CPU usage:
   cpu: %busy     cycles   cycles/pkt  cycles/ic pkt
     2:   99%  697179716          829              0
     4:   51%  363169408            0           1729
     6:   54%  383451844            0           1825
     8:   <1%    6180544            0              0
    14:   <1%    5683196            0              0
    16:   51%  362776960            0           1727
    18:   54%  382313120            0           1820
    20:   <1%    6234228            0              0
   average cycles/packets received from NIC: 2626 (2206989016/840180)
   ic pkt: packets that went intercore

API
---

See the :file:`fpn-\*.h` header files.

Core set management API
~~~~~~~~~~~~~~~~~~~~~~~

Job management function *fpn_job_run_oncpumask* can be used to start a job
on a set of cores. Some coremask manipulation functions are provided by FPN
SDK.

Initializing a coremask
   *fpn_cpumask_clear* clears a coremask
Manipulating coremasks
   *fpn_cpumask_set* add a core to a coremask
   *fpn_cpumask_unset* removes a core from a coremask
   *fpn_cpumask_invert* inverts a coremask
   *fpn_cpumask_add* merge two coremasks
   *fpn_cpumask_sub* substracts a coremask from another one
   *fpn_cpumask_filter* filter a coremask from another one
Walking coremasks
   *fpn_for_each_cpumask* is a for loop on all cores of a coremask
   *fpn_cpumask_getnext* returns the next core of a set
Testing coremasks
   *fpn_cpumask_ismember* tests if a core is part of a coremask
   *fpn_cpumask_isempty* tests if coremask is empty
   *fpn_cpumask_isequal* tests if two coremasks are equal
Miscelaneous
   *fpn_cpumask_size* returns the number of cores in a coremask
   *fpn_cpumask_display* display coremask on screen
   *fpn_cpumask_parse* parse a string and generate a coremask

Intercore API
~~~~~~~~~~~~~

.. important::
   This API is currently only available on the DPDK architectures.

Intercore rings have been added so that any core can send a *mbuf* to another
core. A context is associated with the *mbuf* sent, so that the destination core
knows what to do with the *mbuf* it receives. Context storing is specific to
your architecture.

.. seealso::

   For more information, see your architecture documentation.

Initialization
   *fpn_intercore_mask* must be set prior to calling the cores' mainloop. This
   mask is used by cores to know if they need to handle intercore traffic.
   Sending core's *m_set_process_fct()* is called with the *mbuf* to be sent, a
   callback, and a parameter. The callback type must be *int (f)(struct mbuf \*,
   void \*);*.

   *fpn_intercore_enqueue()* is called with this very *mbuf* and the
   destination core's id.
Receiving core
   The context callback is called with *mbuf* and context parameters.

Checksum computation API
~~~~~~~~~~~~~~~~~~~~~~~~

FPN-SDK provides a set of helpers to compute packet checksums. These functions
are documented in :file:`fpn-cksum.h`.

The *fpn-cksum* API can take advantage of hardware RX and TX checksum offload,
when available. You can define the following macros in
:file:`${arch}/fpn-mbuf-${arch}.h`:

FPN_HAS_TX_CKSUM

   If your platform supports TX checksum offload, you can use the following
   functions:

   - *m_reset_tx_l4cksum()*
   - *m_set_tx_l4cksum()*
   - *m_set_tx_tcp_cksum()*
   - *m_set_tx_udp_cksum()*
   - *m_get_tx_l4cksum()*

FPN_HAS_HW_CHECK_IPV4
   If your platform supports the L3 IPv4 RX checksum verification, you can use
   the *fpn_mbuf_hw_check_ipv4()* function.
FPN_HAS_HW_CHECK_IPV6
   If your platform supports the L3 IPv6 RX checksum verification, you can use
   the *fpn_mbuf_hw_check_ipv6()* function.
FPN_HAS_HW_CHECK_L4
  If your platform supports the L4 RX checksum verification, you can use the
  *fpn_mbuf_hw_check_l4()* function.

TCP Segmentation Offload API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If supported by the driver and the hardware, FPN-SDK can offload the
segmentation of TCP packets to the Ethernet device. The *FPN_HAS_TSO* macro is
defined in the :file:`${arch}/fpn-mbuf-${arch}.h` header file when the TSO API
is available.

The following macros can be used on a packet to control the offload of TCP
segmentation:

m_set_tso(m, mss, l2_len, l3_len, l4_len)
   Flag this TCP packet to be segmented by the hardware. The user has to
   calculate the pseudo header checksum and to set it in the TCP header, as
   required when doing hardware TCP checksum offload, and to set the IP checksum
   to 0.

m_reset_tso(m)
   Reset TSO offload flags.

Garbage collector
~~~~~~~~~~~~~~~~~

FPN-SDK provides a garbage collector mechanism that allows to postpone an
operation until all cores are returned at least once in the main loop.

The *fpn_gc* function takes an *fpn_gc_object* pointer and a function pointer,
as parameters. When the *fpn_gc* function is called, a snapshot of all core
states is taken and the corresponding function is called (with *fpn_gc_object*
as the only parameter) only when all cores are returned at least once in the
main loop. This mechanism has a granularity of 10 ms.

This feature is typically used to ensure that dynamically allocated objects are
not used anymore by any core before being freed. It can be used as follows:

  - Remove an item from any list/table to ensure that the item will not be
    usable anymore on the next mainloop round.
  - Call *fpn_gc* on the item, with a parameter function that will free the
    dynamically allocated structure.

This ensures that when the freeing function is called, memory is not used and
can be freed without any side effects.
