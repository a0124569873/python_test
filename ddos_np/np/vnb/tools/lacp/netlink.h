/*
 * Copyright 2007-2011 6WIND S.A.
 */

#ifndef _LACP_NETLINK_H_
#define _LACP_NETLINK_H_

int lacpd_netlink_init(int lacpd_nl_sockbufsiz);
int lacpd_netlink_close(void);

int lacpd_netlink_dump(void);

#endif /* _LACP_NETLINK_H_ */
