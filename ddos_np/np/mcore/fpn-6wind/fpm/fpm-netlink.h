/*
 * Copyright 2014 6WIND S.A.
 */

#ifndef __FPM_NETLINK_H__
#define __FPM_NETLINK_H__

void fpm_netlink_init(struct event_base *fpm_event_base);
void fpm_netlink_close(void);

#endif
