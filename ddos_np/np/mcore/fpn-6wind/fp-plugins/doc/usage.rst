Usage
=====

Plugin loading varies according to the architecture; see the relevant
documentation. For DPDK, see the *fpn-sdk-dpdk-manual* document.

How to write a plugin
=====================

Registering the module
----------------------

#. Define a global *fp_mod object* containing:

   - the module name,
   - a dependency list that contains the names of the modules that must be
     initialized before this one,
   - an initialization function.

   The dependency list can be *NULL* and, if it exists, must be *NULL*
   terminated.

#. Register your module via the *FP_MOD_REGISTER macro*.

   If your module is to use some *ifnet* *devops*, these *devops* must be stored
   in the *fp_mod* *if_ops* structure.

After initialization, the *fp_mod* structure's *uid* field is populated with an
integer value that will uniquely identify the module in shared memory. This
*uid* will be used to register *ifnet* *devops* during configuration.

.. rubric:: Example

.. code-block:: c

   const char my_dependency_list={"my_dep1", "my_dep2", NULL};

   static void my_plugin_init(void) {
       // init module
   }

   static struct fp_mod my_plugin_mod = {
      .name = "my_plugin",
      .init = my_plugin_init,
      .dependency_list = my_dependency_list,
      .if_ops = {
         [RX_DEV_OPS] = my_plugin_input,
         [TX_DEV_OPS] = my_plugin_output,
      },
   };

   FP_MOD_REGISTER(my_plugin)

Overriding hooks
----------------

To override a hookable function, a module must just export a function with
the corresponding hook name.

.. rubric:: Example

Overriding *fp_ether_input hook*:

.. code-block:: c

  int fp_ether_input(struct mbuf *m, fp_ifnet_t *ifp)
  {
    if (mbuf_is_interesting(m)) {
      do_some_stuff();
      return FP_DONE;
    }
    return FP_DROP;
  }

If your implementation of a given hook is not sure about what to do at some time, you
can call the previous hook implementation using the FPN_HOOK_PREV macro:

.. rubric:: Example

.. code-block:: c

  FPN_HOOK_CHAIN(fp_ether_input)

  int fp_ether_input(struct mbuf *m, fp_ifnet_t *ifp)
  {
    if (mbuf_is_interesting(m)) {
      do_some_stuff();
      return FP_DONE;
    }
    return FPN_HOOK_PREV(fp_ether_input)(m, ifp);
  }

By doing so, you don't need to rewrite all the |fp| code, that handles
already many protocols.
Besides, an interesting feature is that if you write multiple plugins that
deal with different types of traffic, you can call them one after another. Yet,
this can have an impact on performance.
Before using FPN_HOOK_PREV, your code must contain a FPN_HOOK_CHAIN declaration
that will contain the value of the hook's previous implementation.

Using dev ops api
-----------------

When a plugin just needs to be run only on some interfaces, it is
possible to use the dev ops api to register a function that will be
called during normal processing, instead of overriding hooks. Dev
ops functions must be populated in initialization structure.

.. rubric:: Example

.. code-block:: c

  int my_plugin_input(struct mbuf *m, fp_ifnet_t *ifp, void *data)
  {
    do_some_stuff();
    return FP_DONE;
  }

  int my_plugin_init(void)
  {
    fp_ifnet_t *ifp;

    if ((ifp = fp_getifnetbyname("eth0")) == NULL)
      return -1;

    if (fp_ifnet_ops_register(ifp, RX_DEV_OPS, my_plugin_mod.uid, NULL))
      printf("could not register my_ether_input\n");
      return -1;
  }

  int my_plugin_exit(void)
  {
    fp_ifnet_t *ifp;

    if ((ifp = fp_getifnetbyname("eth0")) == NULL)
      return -1;

    fp_ifnet_ops_unregister(ifp, RX_DEV_OPS);
  }

Care that if data is allocated, it must be allocated in |fp|
memory, using fpn_malloc/fpn_gc helpers, to avoid using a wrong data
pointer if a packet is processed during unregistration.

There can be only one function registered on an interface at one
time. If the room is taken, fp_ifnet_ops_register will return 1.

Using *netfpc* messages
-----------------------

A plugin can be notified on reception of a *netfpc* message in the |fp|.

To register a new *netfpc* message, use the *fp_netfpc_register()* API.  This
function accepts a message id (between 0 and 511) and a callback function.  The
id should belong to the 256-511 (maximum id value) range, to avoid collisions
with built-in messages. A log is displayed when the callback is already
registered, and the registration will *succeed*. This means that the last
callback registered for an id will be the one to be called.

.. note::

   You must free the input *mbuf* in the callback function.

.. rubric:: Example

.. code-block:: c

  static int my_netfpc_func(struct mbuf *m, struct fp_netfpc_ctx *ctx)
  {
    do_some_stuff();
    m_free(m);
    return 0;
  }

  static void my_plugin_init(void)
  {
    // register new netfpc msg
    fp_netfpc_register(NETFPC_MSGTYPE_MYMSG, my_netfpc_func);
  }

To be notified on reception of an existing message, use the
*fp_netfpc_add_hook()* API. The messages that support hooks are the following:

NEWIF
   Called when an interface is created.
DELIF
   Called when an interface is deleted.
GR_START
   Called at graceful restart start.

There is no limit on the number of hooks per message.

.. rubric:: Example

.. code-block:: c

  static int my_hook_func(struct mbuf *m, struct fp_netfpc_ctx *ctx)
  {
    do_some_stuff();

    return 0;
  }

  static fp_netfpc_hook_t my_hook = { .func = my_hook_func };

  static void my_plugin_init(void)
  {
    // add hook on reception of existing netfpc msg
    fp_netfpc_add_hook(NETFPC_MSGTYPE_NEWIF, &my_hook);
  }

A plugin can also allow other plugins to be notified on reception of its own
*netfpc* messages. To that end, it must register one of the following standard
message handlers:

*fp_netfpc_cmd_handler*
   Implements message ack.
*fp_netfpc_notif_handler*
   Does not implement message ack.

Hooks can then be registered for this message via *fp_netfpc_add_hook()*.

Using the IP protocol handler API
---------------------------------

Plugins can use the IP protocol handler API to process IP input flows.

You can add new IP protocol handlers via the *fp_ip_proto_handler_register()*
function, which accepts the following arguments:

- an IP proto id (*FP_IPPROTO_\**), and,
- an *fp_ip_proto_handler* structure containing the handler function.

The handler function accepts an *mbuf* as an input, and must return a *FP* code
such as *FP_DONE* or *FP_CONTINUE*.

You can register several handlers for the same IP protocol, but only one handler
can process the input flow. Therefore, *fp_ip_input_demux()* calls all
registered handlers, until one returns a value that is **not** *FP_CONTINUE*.

For IPv6, a similar *fp_ip6_proto_handler_register()* API function is available.

.. rubric:: Example

.. code-block:: c

  static int my_gre_handler_func(struct mbuf *m)
  {
    if (not_for_me())
      return FP_CONTINUE;

    do_some_stuff();

    return FP_DONE;
  }

  static fp_ip_proto_handler_t my_gre_handler = { .func = my_gre_handler_func };

  static void my_plugin_init(void)
  {
    fp_ip_proto_handler_register(FP_IPPROTO_GRE, &my_gre_handler);
  }

Being notified on *ifnet* creation in the |fp|
---------------------------------------------------

To be notified on *ifnet* kernel interfaces creation in the |fp|, a plugin
can use the *fp_if_notifier_register()* function.

.. rubric:: Example

.. code-block:: c

  static int myplugin_on_ifadd(uint16_t vrfid, const char* name,
                               const uint8_t *mac, uint32_t mtu, uint32_t ifuid,
                               uint8_t port, uint8_t type)
  {
    do_some_stuff();
  }

  static fp_if_notifier_t myplugin_if_notifier = {
    .add = myplugin_on_ifadd,
  };

  static void my_plugin_init(void)
  {
    fp_if_notifier_register(&myplugin_if_notifier);
  }

Adding a custom *fp-test-fpn0* test
-----------------------------------

Plugins can register their custom *fp-test-fpn0* tests via
*fp_test_fpn0_register()*. This function accepts the following arguments:

- a test ID, and,
- an handler object.

The test ID should belong to the 1-255 range. Range 1 to 205 is reserved for
internal usage. If the ID is out of range or already used, the function returns
an error (*not 0*).

To start a *fpn0* test whose id is 234, type the following commands:

.. code-block:: console

  # ip addr add 1.1.1.1/24 dev fpn0
  # ping 1.1.1.234

.. rubric:: Example

.. code-block:: c

  #include "fp-test-fpn0.h"

  #define TEST_FPN0_MYPLUGIN 234

  static void my_test_func(void)
  {
    // do some test
  }

  static fp_test_fpn0_handler_t fp_test_fpn0_myplugin = {
    .func = my_test_func,
    .comment = "My comment",
  };

  static void my_plugin_init(void)
  {
    if (fp_test_fpn0_register(TEST_FPN0_MYPLUGIN, &fp_test_fpn0_myplugin) != 0) {
      // error: the id is probably already used
    }
  }

Defining additional |fp| log types
---------------------------------------

Fast path plugins can use the *USER* log type for their log messages, or
register a custom log type.

To define a new log type, you must define a 48-bit log flag named
*FP_LOGTYPE_\** and register it via the *FP_LOG_REGISTER()* macro. If the
logtype flag is already used, *FP_LOG_REGISTER* does nothing and a warning is
displayed.

You can then use *FP_LOG* with your custom log type, and enable or disable it
with the *fp-cli* *logtype* command.

.. rubric:: Example

.. code-block:: c

  #define FP_LOGTYPE_MYPLUGIN             UINT64_C(0x000040000000)

  static void my_plugin_init(void)
  {
    FP_LOG_REGISTER(MYPLUGIN);

    FP_LOG(FP_LOG_DEBUG, MYPLUGIN, "my log\n");
  }

How to add commands from a plugin in the *fp-cli* interface
===========================================================

+--------------------------------------+--------------------------------------+
|**Information to add**                |**Function to use**                   |
+--------------------------------------+--------------------------------------+
|Custom *fp-cli* commands.             |*fpdebug_add_commands()*              |
+--------------------------------------+--------------------------------------+
|Custom statistics to provide          |*fpdebug_add_stats()*                 |
|additional information in the built-in|                                      |
|*fp-cli* *dump-stats* command.        |                                      |
+--------------------------------------+--------------------------------------+
|Custom interface to provide additional|*fpdebug_add_ifnet_info()*            |
|information in the built-in *fp-cli*  |                                      |
|*dump-interfaces* command.            |                                      |
+--------------------------------------+--------------------------------------+

.. rubric:: Example

.. code-block:: c

   #include "fpdebug.h"
   #include "fpdebug-priv.h"
   #include "fpdebug-stats.h"
   #include "fpdebug-ifnet.h"

   static int plugin_command(char *tok)
   {
     int i, numtokens = gettokens(tok);

     for (i = 0; i < numtokens; i++) {
       fpdebug_printf("chargv[%d]=%s\n", i, chargv[i]);
     }
     return 0;
   }

   static CLI_COMMAND plugin_cmds[] = {
     {"command", plugin_command, "this is an example" },
     { NULL, NULL, NULL },
   };
   static cli_cmds_t plugin_cli = { .module = "my-plugin", .c = plugin_cmds, };

   static int dump_my_stats(int percore)
   {
     // print stats
     return 0;
   }
   static void reset_my_stats(void)
   {
     // reset stats
   }

   static CLI_STATS my_stats[] = {
     {"my-stats", dump_my_stats, reset_my_stats },
     { NULL, NULL, NULL },
   };
   static cli_stats_t my_stats_cli = { .module = "my-stats", .s = my_stats, };

   static int dump_my_ifnet_info(fp_ifnet_t *ifp)
   {
	fpdebug_printf("\tmy-plugin:");
	print_some_ifnet_stuff();
	fpdebug_printf("\n");
	return 0;
   }

   static fpdebug_ifnet_info_t my_ifnet_info = { .func = dump_my_ifnet_info };

   static void my_plugin_init(void)
   {
     fpdebug_add_commands(&plugin_cli);
     fpdebug_add_stats(&my_stats_cli);
     fpdebug_add_ifnet_info(&my_ifnet_info);
   }
