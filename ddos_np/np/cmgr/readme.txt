       Cache Manager



1) General Organization

   main.c
       well, just libevent init, daemonization
       config file (currently none) ...
   init.c
       global CM initialization. Single entry point cm_init() in
       charge of calling several xxx_init()
   netlink.c
       Netlink Stuff (socket creation, ...)
       Main netlink dispatcher stuff (RTM_NEWxxx, ...) that calls more
       specific fct located in nl_xxx.c (prototype in cm_netlink.h)
   fpm.c
       UNIX socket management with FPM, and all message sending/queuing
       Thus needs a single entry point to post a message.
   base.c / nl_base.c
       fct creating the CM-FPM messages, related to interfaces,
       addresses and routes. They are cm_XXX and are called, from   
       fct in nl_base.c
       Their API is "public", as it may be foreseen a direct call,
       for addresses for example.
       nl_base.c manages all the netlink commands related to  routes,
       interfaces and addresses.
       Should be extended, with the same philosophy to other modules
        - tunnels.c/nl_tunnel.c
        - trans.c/nl_trans.c
        ...
   cm_dump.c
       anything to dump packets exchanged with the FPM.
       used by both cmgrd AND cmstub
   fake_fpm.c
       FPM emulator: receive messages, and can send ACK and/or NACK
   cm_cpdp.h
       API between CM and FPM (a.k.a. CPDP, for Control Plane-Date Plane)
   cm_pub.h
       everything to create message at the CM-FPM format,
       and the init basic function. Possible netlink removal should
       be here.
   cm_netlink.h
       everything about netlink sockets fct : proto called from
       netlink.c, some tools ...
   cm_priv.h
       CM internal prototypes
  

2) How to add a new feature

   2-1 inits

       - write a fonction XXX_init()
       - install its prototype in cm_priv.h
       - add XXX_init() call inside cm_init() (cm_init.c)      

   2-2 gathering data through netlink

       All incoming netlink msg end up in a common management fct
       cm_nl_recv() in netlink.c

       Here just add your switch/case entries  RTM_xxx, with simple
       fct call to netlink, processing fct located in nl_XXX.c.
       Prototype of this new fct will be set in cm_netlink.h

       2-2-1 using the NETLINK_ROUTE

             It should in this case use another group membership,
             what needs to be done, is this case is to update group
             list while creating the cm_netlink.
             In netlink.c, cm_netlink_init()
                cm_netlink_sock (NETLINK_ROUTE,
                                 &cm_netlink,
                                (RTMGRP_LINK | ...
                                    | your_group)

       2-2-2 using another family

             In netlink.c, cm_netlink_init(),  create one other
             netlink socket, with cm_netlink_sock() fct.

   2-3 gathering data without netlink socket

       Well, not much to be done ;-)
       We just suppose, a good guy will find the data, and directly call
       the cm_XXX_yyy() seen hereafter.

   2-3 data conversion

       - write your functions cm_XXX_yyy()
         those function create CM-FPM messages with the SN set to 0.
         should be somehow :
           void
           cm_XXX_yyy(....)
           {
               struct cp_hdr *hdr;
               ...
               post_msg (hdr);
               return;
           }
       - install their prototype in cm_pub.h


3) internal data structures

   For internal purpose, some objects are memorized, those are:
   - interfaces 
     + need for internal state, because flags change come 
       through an RTM_NEWLINK message
     + linked list (ifacehead)
     + research by index: iflookup()
   - IPv6 addresses 
     + because in cas of autoconf, an RTM_NEWADDR comes after
       each received RA!
     + linked list (addr6head)
     + research fct: addr6lookup()

   Netlink tools
   - Attribute parsing cm_nl_parse_nlattr()
   - NetLink requests  cm_nl_request()
     used in  cm_nl_dump_if(), cm_nl_dump_addr(), cm_nl_dump_route()
