/*
 * Copyright 2006-2012 6WIND S.A.
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

extern struct eth_if * get_ifp_index (int ifindex);
extern int get_port_for_ifp (struct eth_if *ifp, int portnum);

#endif

