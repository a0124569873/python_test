/*
 * Copyright (c) 2011 6WIND, All rights reserved.
 */

#ifndef _FPMONITORD_NETLINK_H_
#define _FPMONITORD_NETLINK_H_

#include <netinet/in.h>

int fpmonitord_netlink_init( void (*fpn0_CB)(void) );
int fpmonitord_netlink_close(void);

int fpmonitord_netlink_dump(void);

#endif /* _FPMONITORD_NETLINK_H_ */
