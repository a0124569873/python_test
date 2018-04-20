/*
 * Copyright (c) 2012 6WIND, All rights reserved.
 */

#ifndef __FPN_TUNTAP_DPDK_H__
#define __FPN_TUNTAP_DPDK_H__

#include <linux/if.h>
/* flags is IFF_ flags added to interfaces */
extern int fpn_create_tap_nodes(const char * fpmapping_fname,
				unsigned int flags);
extern void fpn_init_tap_ring(void);
extern void push_to_tap(struct mbuf *m);

#endif /*__FPN_TUNTAP_DPDK_H__*/
