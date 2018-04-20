Usage
=====

To use |vnb|, call the following
program:

.. code-block:: console

  # <install_dir>/usr/local/bin/vnb.sh start

By default, it will load all available vnb modules.

To avoid loading some modules, specify only the VNB modules you want to load in
the MODULES variable in the VNB configuration file
:file:`<install_dir>/usr/local/etc/vnb.env`.

For instance:

.. code-block:: console

   : ${MODULES:=ether iface eiface ksocket socket split div tee one2many mux}

.. note::

   The `: ${param:=}` syntax to set the variable enables existing environment
   variables to be used instead of those in the configuration file.

.. note::

   To use a custom configuration file, use the CONF_FILE_vnb environment
   variable. For instance:

   .. code-block:: console

      # CONF_FILE_vnb=/path/to/conf/conf_file vnb.sh start

.. note::

   Respect the modules list order to avoid symbol resolution complications.

Tools for node and hook creation
--------------------------------

ngctl
~~~~~

.. rubric:: Description

Create and manage nodes. All commands can be passed as parameters, or
interactively if no parameter is specified.

.. rubric:: Synopsis

.. code-block:: console

   ngctl [COMMAND [ARG]]

.. rubric:: Parameters

Possible COMMAND values:

config
   Get or set configuration of node at *path*.
connect
   Connect node's hook *peerhook* at *relpath* to *hook*.
conforce
   Force to connect node's hook *peerhook* at *relpath* to *hook*.
debug
   Get/set debugging verbosity level.
help
   Show a command summary or get more help on a specific command.
list
   Show information about nodes.
mkpeer
   Create and connect a new node to the node at *path*.
msg
   Send a netgraph control message to the node at *path*.
name
   Assign *name* to the node at *path*.
read
   Read and execute commands from a file.
rm <hook>
   Disconnect *hook* from the node at *path*.
show
   Show information about the node at *path*
shutdown
   Shutdown the node at *path*.
status
   Get human readable status information from the node at *path*.
types
   Show information about all installed node types.
write
   Send a data packet down the hook named by *hook*.
quit
   Exit program.
getstats
   Send a netgraph *getstats* control message to the node at *path*.
dot
   Create a GraphViz (.dot) graph of the entire netgraph.
inspeer
   Create and insert a new node to the node at *path* and propagates connection
   to *peerhook2*.
insnode
   Insert node's hook *peerhook* at *relpath* to *hook* and propagates
   connection to *peerhook2*.
bypass
   Disconnect *hook* and *hook2* from the node at *path*, and reconnects peers
   together.
nldump
   Trigger a |vnb| dump for the
   nodes.

.. rubric:: Example

To build the simple graph below:

.. aafig::

               +----------------------------+
   ______      |  +----------+              |
  /      \     |  | 'EIFACE' |              |
 |'ngeth0'|----|--+__________|\'ether'      |
  \______/     |  | 'ngethL' | \            |
               |  +----------+  \           |
               |                 \'left'    |
               |                 +-------+  |
               |                 | 'TEE' |  |
               |                 |_______|  |
               |                 | 'Tee' |  |
               |                 +-------+  |
   ______      |  +----------+   /'right'   |
  /      \     |  | 'EIFACE' |  /           |
 |'ngeth1'|----|--+__________| /            |
  \______/     |  | 'ngethR' |/'ether'      |
               |  +----------+              |
               +----------------------------+

#. Enter the following netgraph commands:

   .. code-block:: console

      # ngctl
      + mkpeer tee ether left2right
      + list
      Name: <unnamed>       Type: tee             ID: 0000003b   Num hooks: 1   Ns: 0
      Name: ngctl19605      Type: socket          ID: 0000003a   Num hooks: 1   Ns: 0
      Name: eth0            Type: ether           ID: 00000037   Num hooks: 0   Ns: 0
      There are 3 total nodes, 3 nodes listed
      + name [3b]: Tee
      + mkpeer Tee: eiface left ether
      + list
      Name: <unnamed>       Type: eiface          ID: 0000003c   Num hooks: 1   Ns: 0
      Name: Tee             Type: tee             ID: 0000003b   Num hooks: 2   Ns: 0
      Name: ngctl19605      Type: socket          ID: 0000003a   Num hooks: 1   Ns: 0
      Name: eth0            Type: ether           ID: 00000037   Num hooks: 0   Ns: 0
      There are 4 total nodes, 4 nodes listed
      + name [3c]: ngethL
      + mkpeer Tee: eiface right ether
      + list
      Name: <unnamed>       Type: eiface          ID: 0000003d   Num hooks: 1   Ns: 0
      Name: ngethL          Type: eiface          ID: 0000003c   Num hooks: 1   Ns: 0
      Name: Tee             Type: tee             ID: 0000003b   Num hooks: 3   Ns: 0
      Name: ngctl19605      Type: socket          ID: 0000003a   Num hooks: 1   Ns: 0
      Name: eth0            Type: ether           ID: 00000037   Num hooks: 0   Ns: 0
      There are 5 total nodes, 5 nodes listed
      + name [3d]: ngethR
      + rmhook Tee: left2right
      + msg ngethL: setifname "ngeth0"
      + msg ngethR: setifname "ngeth1"
      + list
      Name: ngeth1          Type: ether           ID: 0000003f   Num hooks: 0   Ns: 0
      Name: ngeth0          Type: ether           ID: 0000003e   Num hooks: 0   Ns: 0
      Name: ngethR          Type: eiface          ID: 0000003d   Num hooks: 1   Ns: 0
      Name: ngethL          Type: eiface          ID: 0000003c   Num hooks: 1   Ns: 0
      Name: Tee             Type: tee             ID: 0000003b   Num hooks: 2   Ns: 0
      Name: ngctl19605      Type: socket          ID: 0000003a   Num hooks: 0   Ns: 0
      Name: eth0            Type: ether           ID: 00000037   Num hooks: 0   Ns: 0
      There are 7 total nodes, 7 nodes listed

#. Configure newly created interfaces:

   .. code-block:: console

      # ip li set ngeth0 address 00:01:01:02:02:02
      # ip li set ngeth1 address 00:01:01:03:03:03
      # ip a a 192.168.1.1/24 dev ngeth0
      # ip a a 192.168.2.1/24 dev ngeth1
      # ip li set up dev ngeth0
      # ip li set up dev ngeth1

#. Send a ping from interface *ngeth0*:

   .. code-block:: console

      # arp -s 192.168.1.2 00:05:05:05:03:01
      # tcpdump -ni ngeth1 &
      # ping 192.168.1.2
      PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
      15:13:17.024980 IP 192.168.1.1 > 192.168.1.2: ICMP echo request, id 20162, seq 1, length 64
      15:13:18.032906 IP 192.168.1.1 > 192.168.1.2: ICMP echo request, id 20162, seq 2, length 64
      15:13:19.040903 IP 192.168.1.1 > 192.168.1.2: ICMP echo request, id 20162, seq 3, length 64

   Packets are forwarded on *ngeth1* through the *Tee* node.

#. Check *Tee* node statistics:

   .. code-block:: console

      # ngctl
      msg Tee: getstats
      Rec'd response "getstats" (1) from "Tee:":
      Args:   { right={ inOctets=468 inFrames=6 outOctets=1588 outFrames=26 } left={ inOctets=1588 inFrames=26 outOctets=468 outFrames=6 } right2left={ inOctets=0 inFrames=0 outOctets=0 outFrames=0 } left2right={ inOctets=0 inFrames=0 outOctets=0 outFrames=0 } }

nghooks
~~~~~~~

.. rubric:: Description

Create a *ng_socket* socket type node and connects it to hookname *hook* of the
node found at *path*.

.. rubric:: Synopsis

.. code-block:: console

   nghook [-da] [-p <port>] PATH [HOOKNAME]**

At this point:

- all data written to standard input is redirected to the node, and
- all data received from the node is redirected to standard output.

.. rubric:: Parameters

PATH
   Path to node to hook with.
HOOKNAME
   Name of the node to hook with.
a
   Output each packet read in ASCII.
d
   Increase the debugging verbosity level.
p <port>
   Uses a UDP socket with *srcport = PORT* and *dstport = (PORT + 1)* instead of
   *stdin* and *stdout*.

.. rubric:: Example

Assuming the *tcpdump* instance started at the example above is still running
with the same |vnb| graph:

.. code-block:: console

   # nghook Tee: right2left
   This should a packet hex
   15:30:13.978588 68:6f:75:6c:64:20 > 54:68:69:73:20:73, ethertype Unknown (0x6120), length 25:
          0x0000:  7061 636b 6574 2068 6578 0a

VNB socket
----------

About VNB sockets
~~~~~~~~~~~~~~~~~

VNB sockets allow userspace program to configure the VNB graph or inject packet
into it.

It's the standard BSP socket API with the family AF_NETGRAPH (260).

Control socket
~~~~~~~~~~~~~~

Control sockets are used to send Control messages to individual VNB nodes (for
example, for creating the VNB graph), and optionally receive command results.

Data socket
~~~~~~~~~~~

Data sockets are used to exchange data packets with the VNB graph.

Packets received by VNB nodes and sent on hooks connected to data sockets are
received by the userland program which opened the socket (for example, lacpdu
packets are transmitted from ethgrp to lacpd of the lag module).

Packets sent by userland programs on data sockets are received by corresponding
VNB nodes, then processed and forwarded on the network (for example, LSP ping
packets are created by lsp_ping in the mpls module and then sent by the mpls VNB
nodes).

Ancillary data
++++++++++++++

There are two kinds of ancillary data accepted by a vnb socket:

#. NG_OPT_METADATA
#. NG_OPT_MARK

NG_OPT_METADATA
```````````````
This option contains a set of 'struct meta_field_header' + data. These fields
options are defined in the node and identified by the node cookie + a type
value. Here is the format of the option:

.. aafig::

 +--------------------------+
 |'struct meta_header'      |
 +--------------------------+
 |'struct meta_field_header'|  \
 +--------------------------+   |
 |'data'                    |   |
 +--------------------------+   | 'struct meta_header->len'
 |'...'                     |   |
 +--------------------------+   |
 |'struct meta_field_header'|   |
 +--------------------------+   |
 |'data'                    |  /
 +--------------------------+

The first header contains the length to the following field options.

NG_OPT_MARK
```````````
Just an uint32_t to set the skb->mark.

Example
```````
See MPLS / lsp_ping, this application sets NG_OPT_MARK and
NG_OPT_METADATA(NGM_MPLS_OAM_LSP_INFO).
