Usage
=====

This plugin must be loaded when starting the |fp| application.
To check that plugins are supported and how to load them,
see your architecture manual.

This plugin uses the *FP_RX_CPUPORTMAP* environment variable to get its
configuration.

This variable has the following format:

FP_RX_CPUPORTMAP
   [[recvcore=]port=destcore/][recvcore=]port=destcore

When calling the *fp_ether_input* hook:

#. The plugin checks which core is currently running the hook (*recvcore*).
#. Depending on the port, the packet is sent to the destination core
   (*destcore*).
#. The destination core executes the original *fp_ether_input* code.
