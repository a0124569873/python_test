/*
 * Copyright 2009 6WIND S.A.
 */

#ifndef _IFFLAGS_H_
#define _IFFLAGS_H_

#define IFFLAGSD_ERR_INIT           228   /* system error */
#define IFFLAGSD_ERR_PARAM          229   /* wrong parameters */
#define IFFLAGSD_ERR_DAEMON         230   /* error when fmip6ard tries to become a daemon */
#define IFFLAGSD_ERR_SOCKET         231   /* socket error */

#define IFFLAGSD_PIDFILE            "/var/run/ifflagsd.pid"

#define IFFLAGSD_COMMAND_PORT       9990

#if defined (USE_VRF_NETNS)
#include <libvrf.h>
struct nl_sock *get_nl_sock(struct libif_iface *iface);
#endif

#endif /* _IFFLAGS_H_ */

