Usage
=====

This plugin must be loaded when starting the |fp| application.
To check that plugins are supported and how to load them,
see your architecture manual.

This plugin uses the *FP_TX_CPUPORTMAP* environment variable to get its
configuration.

This variable has the following format:

FP_TX_CPUPORTMAP
   [[recvcore=]port=destcore/][recvcore=]port=destcore

When calling the *fp_if_output hook*:

#. The plugin checks which core is currently running this hook (*recvcore*).
#. Depending on the port, the packet is sent to the *destcore* core.
#. The *destcore* core executes the original *fp_if_output* code.

.. Compilation
.. ===========
