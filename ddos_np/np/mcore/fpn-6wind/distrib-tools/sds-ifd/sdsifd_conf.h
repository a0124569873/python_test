/*
 * Copyright 2013 6WIND, All rights reserved.
 */

#ifndef _SDSIFD_CONF_H_
#define _SDSIFD_CONF_H_

#include <sys/queue.h>

#define CP_MODE  1
#define FP_MODE  2

#define IFD_LOG(prio, fmt, args...) \
do { \
	syslog((prio), "%s: " fmt "\n", __func__, ##args);	\
} while (0)
extern const char *sdsifd_progname;

extern int         sdsifd_verbose;
extern int         sdsifd_force;         /* force sds-ifd restart */
extern int         sdsifd_foreground;
extern int         sdsifd_console;
extern int         sdsifd_mode;          /* CP_MODE or FP_MODE */
extern const char *sdsifd_pidfile;

extern const char *sdsifd_cp_address;    /* ip of control plane */
extern uint16_t    sdsifd_cp_port;       /* port to connect */

extern uint8_t     sdsifd_local_peer_id;      /* our blade id */

extern int         sdsifd_gracetime;
extern char        sdsifd_bind_bladepeer[16]; /* ifname of blade peer */

#ifdef HA_SUPPORT
extern char        has_srvname[16];
#endif

struct sdsifd_interface_conf {
	SLIST_ENTRY(sdsifd_interface_conf) next;
	const char *ifname;
	uint16_t   fpib:1;
	uint16_t   allmulti:1;
};

struct sdsifd_interface_conf *
sdsifd_interface_conf_lookup_by_name(const char *ifname);

int conf_readargs (int argc, char **argv);

/* used only for cp */
struct sdsifd_iface {
	SLIST_ENTRY(sdsifd_iface) iface_next;

	char name[IFNAMSIZ];
	int fpib;
	struct sdsifd_peer *peer;
};

/* used only for cp */
struct sdsifd_peer {
	SLIST_ENTRY(sdsifd_peer) peer_next;
	struct stream stream;
	int id;
	sock_addr_t addr;
	uint16_t grace_time_seconds;

	SLIST_HEAD(sinterface_list, sdsifd_iface) peer_iface_list;
};


#endif /* _SDSIFD_CONF_H_ */
