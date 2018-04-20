/*
 * Copyright 2008-2013 6WIND S.A.
 */

#ifndef _LACP_IFACE_H_
#define _LACP_IFACE_H_

struct lacpd_iface {
	LIST_ENTRY(lacpd_iface) next;
	char name[IFNAMSIZ];
	int flags;
	unsigned int k_index;
	uint16_t portid;
};

int lacpd_iface_init(void);
int lacpd_iface_destroy_all(void);

struct lacpd_iface *lacpd_iface_lookup(const char *ifname);
int lacpd_iface_update(struct lacpd_iface *iface, int flags);
int lacpd_iface_add(const char *ifname, unsigned int k_index, uint32_t ifuid, int flags);
int lacpd_iface_delete(const char *ifname);

#endif
