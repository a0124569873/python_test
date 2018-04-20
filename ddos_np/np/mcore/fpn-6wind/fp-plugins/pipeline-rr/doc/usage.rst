Usage
=====

This plugin must be loaded when starting the |fp| application.
To check that plugins are supported and how to load them,
see your architecture manual.

This plugin uses the *RR_LB_CPUPORTMAP* environment variable to get its
configuration.

This variable has the following format:

RR_LB_CPUPORTMAP
   [[recvcore=]port=[destcore:]destcore/][recvcore=]port=[destcore:]destcore

All traffic going through the *fp_ether_input* hook is handled by the plugin.
Based on the core running this hook and on the port on which traffic has been
received, this plugin uses the cpu port map (filled by *RR_LB_CPUPORTMAP*) to
find which core will handle it. If no destination core is found, then the packet
is handled by the current core.
