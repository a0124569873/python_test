/*
 * Copyright 2006-2012 6WIND S.A.
 */

#include "snoop.h"
#include <linux/mroute.h>
#include <linux/mroute6.h>
/*
 */
struct mc_proxy_binding {
	LIST_ENTRY(mc_proxy_binding)       binding_link;    /* binding inkage */
	struct eth_if*			interface;
};

struct mc_proxy {
	LIST_ENTRY(mc_proxy)    proxy_link;   	/* proxy inkage */
	u_int8_t             *proxy_name;       /* proxy name */
	u_int8_t              proxy_started;
	u_int8_t              proxy_mld;
	u_int8_t              proxy_igmp;

	struct eth_if*		    proxy_upstream;
	LIST_HEAD(,mc_proxy_binding)   proxy_downstreams;
};
LIST_HEAD(proxyhead, mc_proxy);

extern struct proxyhead all_proxies;


void proxy_init(void);
void proxy_close(void);

void proxy_enable(struct mc_proxy *proxy);
void proxy_disable(struct mc_proxy *proxy);


mifi_t proxy_add_vif(const char *ifname);
vifi_t proxy_add_mif(const char *ifname);

mifi_t proxy_del_vif(const char *ifname);
vifi_t proxy_del_mif(const char *ifname);

void proxy_add_mfc4(struct sockaddr *src, struct sockaddr *dst, vifi_t in, struct if_set *out);
void proxy_add_mfc6(struct sockaddr *src, struct sockaddr *dst, mifi_t in, struct if_set *out);

void proxy_del_mfc4(struct sockaddr *src, struct sockaddr *dst, vifi_t in);
void proxy_del_mfc6(struct sockaddr *src, struct sockaddr *dst, mifi_t in);

void proxy_mfc_change (struct mc_proxy *prx, struct eth_if *ifp, struct mc_fwd *mcf, u_int32_t cmd);

extern void display_proxy_info (int fd, struct mc_proxy *, int, int);
