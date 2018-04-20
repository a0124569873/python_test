Usage
=====

This plugin must be loaded when starting the |fp| application. To check
that plugins are supported and how to load them, see your architecture manual.

This plugin uses two environment variables to get its configuration.

EGRESS_QOS_SCHED_CONFIG_DIR
   This variable is used as a prefix to find the configuration files. If this
   variable is unset, then the plugin will look at /usr/admin/etc.
EGRESS_QOS_SCHED_CPUPORTMAP
   This variable is used to create packet scheduling objects. This variable has
   the following format:

   .. code-block:: console

      [core=port=file/]core=port=file

When calling the *fp_if_output hook*:

#. The plugin checks which core is currently running this hook (*core*).
#. Depending on the port, the packet is sent to the scheduler created at
   initialization using the configuration *file*.

Packets are dequeued and periodically handed from schedulers to the mainloop.
