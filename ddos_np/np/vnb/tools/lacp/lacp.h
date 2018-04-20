/*
 * Copyright 2007-2011 6WIND S.A.
 */

#ifndef _LACP_H_
#define _LACP_H_

#define LACPD_ERR_INIT           228   /* system error */
#define LACPD_ERR_PARAM          229   /* wrong parameters */
#define LACPD_ERR_DAEMON         230   /* error when lacpd tries to become a daemon */

#define LACPD_PIDFILE            "/var/run/lacpd.pid"

#define LACPD_COMMAND_PORT       6990

#define LACP_NOTIF

struct lacp_state {
	int active;  /* */
	int graceful;  /* */
	struct event timer_evt;
// ??? int lacpdebug;
	int sock_lacpdu;/* socket for sending LACPDU */
};
extern struct lacp_state cur_lacp_state;

#ifdef HA_SUPPORT
/* AF_UNIX path for lacpd => haf-lacpd communication */
#define LACPDU_DUP_TX_PATH       "/tmp/.haf_lacpd_tx"
/* AF_UNIX path for haf-lacpd => lacpd communication */
#define LACPDU_DUP_RX_PATH       "/tmp/.haf_lacpd_rx"
#endif

#endif /* _LACP_H_ */

