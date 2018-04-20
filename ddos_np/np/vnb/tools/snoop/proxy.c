/*
 * Copyright 2006-2013 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <net/if.h>

#include <netgraph.h>
#include <syslog.h>
#include <ifaddrs.h>
#include "proxy.h"
#include "snoop.h"
#include "igmp.h"
#include "mld.h"

static int mif2phyif[MAXMIFS];
static int vif2phyif[MAXVIFS];

static int proxy_get_mifi(mifi_t *mifi, int ifindex);
static int proxy_get_vifi(vifi_t *vifi, int ifindex);
static void ifname2addr(const char *ifname, struct in_addr *addr);

#define VIF_FOUND (-1)
#define VIF_FAILED (-2)

void
proxy_init()
{
	int on;

	/* start vif/mif management */
	bzero(mif2phyif, sizeof(mif2phyif));
	mif2phyif[0] = -1;
	bzero(vif2phyif, sizeof(vif2phyif));
	vif2phyif[0] = -1;

	on = 1;
	if (setsockopt(igmp_socket, IPPROTO_IP, MRT_INIT, &on, sizeof(on)) < 0) {
		log_msg(LOG_WARNING, 0, "%s unable to initialize IPv4 mutlicast routing socket\n", "snoopd");
		return;
	}

	on = 1;
	if (setsockopt(mld6_socket, IPPROTO_IPV6, MRT6_INIT, &on, sizeof(on)) < 0) {
		log_msg(LOG_WARNING, 0, "%s unable to initialize IPv6 mutlicast routing socket\n", "snoopd");
		return;
	}
}

void
proxy_close()
{
	if ( setsockopt(igmp_socket, IPPROTO_IP, MRT_DONE, (char *)NULL, 0) < 0 ) {
		log_msg(LOG_WARNING, 0, "%s unable to remove IPv4 mutlicast routing socket\n", "snoopd");
	}

	if ( setsockopt(mld6_socket, IPPROTO_IPV6 , MRT6_DONE, (char *)NULL, 0) < 0 ) {
		log_msg(LOG_WARNING, 0, "%s unable to remove IPv6 mutlicast routing socket\n", "snoopd");
	}

	/* start vif/mif management */
	bzero(mif2phyif, sizeof(mif2phyif));
	mif2phyif[0] = -1;
	bzero(vif2phyif, sizeof(vif2phyif));
	vif2phyif[0] = -1;

}


void
proxy_disable(struct mc_proxy *proxy)
{
	if (proxy->proxy_upstream == 0)
		return;
	if (proxy->proxy_igmp) {
		vifi_t vifiUp;
		struct mc_proxy_binding *binding;

		/* A zero address == ignore the source */
		struct sockaddr_in src;
		src.sin_addr.s_addr = 0;
		src.sin_family = AF_INET;

		if ( proxy_get_vifi(&vifiUp, proxy->proxy_upstream->if_index) != VIF_FAILED )
			proxy_del_mfc4((struct sockaddr *)&src, (struct sockaddr *)&src, vifiUp);
		else
			log_msg(LOG_WARNING, 0, "cannot find vif for proxy upstream %s", proxy->proxy_upstream->if_name);


		/* notify the removing of all groups */
		/* for each downstream... */
		LIST_FOREACH (binding, &proxy->proxy_downstreams, binding_link) {
			struct eth_if *intf = binding->interface;
			struct mc_fwd *mc;

			/* for each subscribed group... */
			LIST_FOREACH (mc, &(intf->if_igmp_head), mcf_link) {
                                proxy_del_mfc4((struct sockaddr *)&src, &mc->mcf_sa, vifiUp);
				igmp_join_group(&mc->mcf_sin, proxy->proxy_upstream->if_index, NOTIFY_GROUP_DELETE);
			}
		}
	}

	if (proxy->proxy_mld) {
		mifi_t mifiUp;
		struct mc_proxy_binding *binding;

		/* A zero address == ignore the source */
		struct sockaddr_in6 src6;
		bzero(&src6, sizeof(src6));
		src6.sin6_family = AF_INET6;

		if ( proxy_get_mifi(&mifiUp, proxy->proxy_upstream->if_index) != VIF_FAILED )
			proxy_del_mfc6((struct sockaddr *)&src6, (struct sockaddr *)&src6, mifiUp);
		else
			log_msg(LOG_WARNING, 0, "cannot find mif for proxy upstream %s", proxy->proxy_upstream->if_name);


		/* notify the removing of all groups */
		/* for each downstream... */
		LIST_FOREACH (binding, &proxy->proxy_downstreams, binding_link) {
			struct eth_if *intf = binding->interface;
			struct mc_fwd *mc;

			/* for each subscribed group... */
			LIST_FOREACH (mc, &(intf->if_mld_head), mcf_link) {
                                proxy_del_mfc6((struct sockaddr *)&src6, &mc->mcf_sa, mifiUp);
				mld_join_group(&mc->mcf_sin6, proxy->proxy_upstream->if_index, NOTIFY_GROUP_DELETE);
			}
		}
	}
}

void
proxy_enable(struct mc_proxy *proxy)
{
	if (proxy->proxy_upstream == 0)
		return;
	if (proxy->proxy_igmp) {
		struct mc_proxy_binding *binding;
		struct if_set out;
		vifi_t vifiUp;

		/* A zero address == ignore the source */
		struct sockaddr_in src;
		src.sin_addr.s_addr = 0;
		src.sin_family = AF_INET;

		/* The upstream is added to all MFC */
		vifiUp = proxy_add_vif(proxy->proxy_upstream->if_name);
		IF_ZERO(&out);
		IF_SET(vifiUp, &out);

		/* for each downstream... */
		LIST_FOREACH (binding, &proxy->proxy_downstreams, binding_link) {
			IF_SET(proxy_add_vif(binding->interface->if_name), &out);
		}
		proxy_add_mfc4((struct sockaddr *)&src, (struct sockaddr *)&src, vifiUp, &out);

		/* creating for forwarding routes of all groups for each downstream... */
		LIST_FOREACH (binding, &proxy->proxy_downstreams, binding_link) {
			struct eth_if *intf = binding->interface;
			struct mc_fwd *mc;

			/* for each subscribed group... */
			LIST_FOREACH (mc, &(intf->if_igmp_head), mcf_link) {
				proxy_mfc_change(proxy, intf, mc, NOTIFY_GROUP_ADD);
                        }
		}
	}
	if (proxy->proxy_mld) {
		struct mc_proxy_binding *binding;
		struct if_set out6;
		mifi_t mifiUp;

		/* A zero address == ignore the source */
		struct sockaddr_in6 src6;
		bzero(&src6, sizeof(src6));
		src6.sin6_family = AF_INET6;

		/* The upstream is added to all MFC */
		mifiUp = proxy_add_mif(proxy->proxy_upstream->if_name);
		IF_ZERO(&out6);
		IF_SET(mifiUp, &out6);

		/* for each downstream... */
		LIST_FOREACH (binding, &proxy->proxy_downstreams, binding_link) {
			IF_SET(proxy_add_mif(binding->interface->if_name), &out6);
		}
		proxy_add_mfc6((struct sockaddr *)&src6, (struct sockaddr *)&src6, mifiUp, &out6);

		/* creating for forwarding routes of all groups for each downstream... */
		LIST_FOREACH (binding, &proxy->proxy_downstreams, binding_link) {
			struct eth_if *intf = binding->interface;
			struct mc_fwd *mc;

			/* for each subscribed group... */
			LIST_FOREACH (mc, &(intf->if_mld_head), mcf_link) {
				proxy_mfc_change(proxy, intf, mc, NOTIFY_GROUP_ADD);
                        }
		}
	}
}

mifi_t
proxy_add_mif(const char *ifname)
{
	struct mif6ctl mif6c;
	int ifindex = 0;
	int err;

	bzero(&mif6c, sizeof(mif6c));
	ifindex = if_nametoindex(ifname);
	if (proxy_get_mifi(&mif6c.mif6c_mifi, ifindex) == VIF_FAILED)
		goto end; /* it's already registered */
	mif6c.mif6c_pifi = ifindex;
	mif6c.mif6c_flags = 0;
	err = setsockopt(mld6_socket, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6c, sizeof(mif6c));
	if (err < 0)
		log_msg(LOG_WARNING, errno, "Can't add MIF (%s)", ifname);
end:
	return mif6c.mif6c_mifi;
}

mifi_t
proxy_del_mif(const char *ifname)
{
	struct mif6ctl mif6c;
	int ifindex = 0;
	int err;

	bzero(&mif6c, sizeof(mif6c));
	ifindex = if_nametoindex(ifname);
	if (proxy_get_mifi(&mif6c.mif6c_mifi, ifindex) == VIF_FAILED)
		goto end; /* it's already registered */
	mif6c.mif6c_pifi = ifindex;
	mif6c.mif6c_flags = 0;
	err = setsockopt(mld6_socket, IPPROTO_IPV6, MRT6_DEL_MIF, &mif6c, sizeof(mif6c));
	if (err < 0)
		log_msg(LOG_WARNING, errno, "Can't del MIF");
end:
	return mif6c.mif6c_mifi;
}

vifi_t
proxy_add_vif(const char *ifname)
{
	struct vifctl vifc;
	int ifindex = 0;
	int err;

	bzero(&vifc, sizeof(vifc));
	ifindex = if_nametoindex(ifname);
	if (proxy_get_vifi(&vifc.vifc_vifi, ifindex) == VIF_FAILED)
		goto end;
	ifname2addr(ifname, &vifc.vifc_lcl_addr);
	if (vifc.vifc_lcl_addr.s_addr == INADDR_ANY) {
		log_msg(LOG_WARNING, errno, "Can't add VIF: no IPv4 address on interface %s", ifname);
		return 0;
	}

	vifc.vifc_flags = 0;
	vifc.vifc_threshold = 1;
	err = setsockopt(igmp_socket, IPPROTO_IP, MRT_ADD_VIF, &vifc, sizeof(vifc));
	if (err < 0)
		log_msg(LOG_WARNING, errno, "Can't add VIF (%s)", ifname);

end:
	return vifc.vifc_vifi;
}

vifi_t
proxy_del_vif(const char *ifname)
{
	struct vifctl vifc;
	int ifindex = 0;
	int err;

	bzero(&vifc, sizeof(vifc));
	ifindex = if_nametoindex(ifname);
	if (proxy_get_vifi(&vifc.vifc_vifi, ifindex) == VIF_FAILED)
		goto end;
	ifname2addr(ifname, &vifc.vifc_lcl_addr);
	vifc.vifc_flags = 0;
	vifc.vifc_threshold = 1;
	err = setsockopt(igmp_socket, IPPROTO_IP, MRT_DEL_VIF, &vifc, sizeof(vifc));
	if (err < 0)
		log_msg(LOG_WARNING, errno, "Can't del VIF");

end:
	return vifc.vifc_vifi;
}

void
proxy_del_mfc6(struct sockaddr *src, struct sockaddr *dst, mifi_t in)
{
	struct mf6cctl mf6c;
	struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)src;
	struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;
	/* A zero address == ignore the source */
	struct sockaddr_in6 nullAddr;
	bzero(&nullAddr, sizeof(nullAddr));
	nullAddr.sin6_family = AF_INET6;

	bcopy(src, &mf6c.mf6cc_origin, sizeof(mf6c.mf6cc_origin));
	bcopy(dst, &mf6c.mf6cc_mcastgrp, sizeof(mf6c.mf6cc_mcastgrp));
	mf6c.mf6cc_parent = in;

	if (setsockopt(mld6_socket, IPPROTO_IPV6, MRT6_DEL_MFC_PROXY, &mf6c, sizeof(mf6c)) < 0) {
                log_msg(LOG_WARNING, errno, "Can't delete MFC6");
		return;
	}
}

void
proxy_add_mfc6(struct sockaddr *src, struct sockaddr *dst, mifi_t in,
	 struct if_set *out)
{
	struct mf6cctl mf6c;
	struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)src;
	struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;
	/* A zero address == ignore the source */
	struct sockaddr_in6 nullAddr;
	bzero(&nullAddr, sizeof(nullAddr));
	nullAddr.sin6_family = AF_INET6;

	bcopy(src, &mf6c.mf6cc_origin, sizeof(mf6c.mf6cc_origin));
	bcopy(dst, &mf6c.mf6cc_mcastgrp, sizeof(mf6c.mf6cc_mcastgrp));
	mf6c.mf6cc_parent = in;
	mf6c.mf6cc_ifset = *out;

	if (setsockopt(mld6_socket, IPPROTO_IPV6, MRT6_ADD_MFC_PROXY, &mf6c, sizeof(mf6c)) < 0) {
                log_msg(LOG_WARNING, errno, "Can't add MFC6");
		return;
	}
}

void
proxy_del_mfc4(struct sockaddr *src, struct sockaddr *dst, vifi_t in)
{
	struct mfcctl mfc;
	struct sockaddr_in *src4 = (struct sockaddr_in *)src;
	struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
	int i;

	bcopy(&src4->sin_addr, &mfc.mfcc_origin, sizeof(mfc.mfcc_origin));
	bcopy(&dst4->sin_addr, &mfc.mfcc_mcastgrp, sizeof(mfc.mfcc_mcastgrp));
	mfc.mfcc_parent = in;
	if (setsockopt(igmp_socket, IPPROTO_IP, MRT_DEL_MFC_PROXY, &mfc, sizeof(mfc)) < 0) {
                log_msg(LOG_WARNING, errno, "Can't delete MFC4");
		return;
	}
}

void
proxy_add_mfc4(struct sockaddr *src, struct sockaddr *dst, vifi_t in,
	 struct if_set *out)
{
	struct mfcctl mfc;
	struct sockaddr_in *src4 = (struct sockaddr_in *)src;
	struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
	int i;

	bcopy(&src4->sin_addr, &mfc.mfcc_origin, sizeof(mfc.mfcc_origin));
	bcopy(&dst4->sin_addr, &mfc.mfcc_mcastgrp, sizeof(mfc.mfcc_mcastgrp));
	mfc.mfcc_parent = in;
	for (i = 0; i < MAXVIFS; i++) {
		if (IF_ISSET(i, out))
			mfc.mfcc_ttls[i] = 1;
		else
			mfc.mfcc_ttls[i] = 255;
	}
	if (setsockopt(igmp_socket, IPPROTO_IP, MRT_ADD_MFC_PROXY, &mfc, sizeof(mfc)) < 0) {
                log_msg(LOG_WARNING, errno, "Can't add MFC4");
		return;
	}
}

static int
proxy_get_mifi(mifi_t *mifi, int ifindex)
{
	int i;
	for (i = 1; i < MAXMIFS; i++) {
		/* found already allocated one */
		if (mif2phyif[i] == ifindex) {
			*mifi = i;
			return VIF_FOUND;
		}

		/* you have seeked all the registerd mifs */
		if (mif2phyif[i] == 0) {
			*mifi = i;
			mif2phyif[i] = ifindex;
			return i;
		}
	}
	return VIF_FAILED;
}

static int
proxy_get_vifi(vifi_t *vifi, int ifindex)
{
	int i;
	for (i = 1; i < MAXVIFS; i++) {
		/* found already allocated one */
		if (vif2phyif[i] == ifindex) {
			*vifi = i;
			return VIF_FOUND;
		}

		/* you have seeked all the registerd vifs */
		if (vif2phyif[i] == 0) {
			*vifi = i;
			vif2phyif[i] = ifindex;
			return i;
		}
	}
	return VIF_FAILED;
}


void
proxy_mfc_change (   struct mc_proxy *prx,
		     struct eth_if   *ifp,
                     struct mc_fwd   *mcf,
                     u_int32_t        cmd)
{
	/* update the kernel MFC if the proxy associated with the ifp is active */
        if (mcf->mcf_sa.sa_family == AF_INET) {
		if (prx && prx->proxy_started && prx->proxy_igmp) {
			struct eth_if *intf;
			struct mc_proxy_binding *binding;

			int subscribers = 0;
			vifi_t vifiDown = proxy_add_vif(ifp->if_name);

			/* A zero address == ignore the source */
			struct sockaddr_in src;
			src.sin_addr.s_addr = 0;
			src.sin_family = AF_INET;

			/* The upstream is added to all MFC */
			vifi_t vifiUp = proxy_add_vif(prx->proxy_upstream->if_name);
			struct if_set out;
			IF_ZERO(&out);
			IF_SET(vifiUp, &out);

			/* Get all the vif interested by this group */
			/* for each downstream... */
			LIST_FOREACH (binding, &prx->proxy_downstreams, binding_link) {
				intf = binding->interface;
				struct mc_fwd *mc;

				/* for each subscribed group... */
				LIST_FOREACH (mc, &(intf->if_igmp_head), mcf_link) {
					if (mc->mcf_sin.sin_addr.s_addr == mcf->mcf_sin.sin_addr.s_addr) {
						IF_SET(proxy_add_vif(intf->if_name), &out);
						subscribers++;
					}
				}
                        }

			if (subscribers == 0) {
				proxy_del_mfc4((struct sockaddr *)&src, &mcf->mcf_sa, vifiUp);
			} else {
				proxy_add_mfc4((struct sockaddr *)&src, &mcf->mcf_sa, vifiUp, &out);
			}

			/*
			 *  We also need to subscribe/unsubscribe the upstream interface to the group
			 *  only if first/last vifi
			 */
			if ((subscribers == 1  && cmd == NOTIFY_GROUP_ADD) || (subscribers == 0 && cmd == NOTIFY_GROUP_DELETE))
				igmp_join_group(&mcf->mcf_sin, prx->proxy_upstream->if_index, cmd == NOTIFY_GROUP_ADD);
		}
	} else {
		if (prx && prx->proxy_started && prx->proxy_mld) {
			struct eth_if *intf;
			struct mc_proxy_binding *binding;

			int subscribers = 0;
			mifi_t mifiDown = proxy_add_mif(ifp->if_name);

			/* A zero address == ignore the source */
			struct sockaddr_in6 src;
			bzero(&src, sizeof(src));
			src.sin6_family = AF_INET6;

			/* The upstream is added to all MFC */
			mifi_t mifiUp = proxy_add_mif(prx->proxy_upstream->if_name);
			struct if_set out;
			IF_ZERO(&out);
			IF_SET(mifiUp, &out);

			/* Get all the mif interested by this group */
			/* for each downstream... */
			LIST_FOREACH (binding, &prx->proxy_downstreams, binding_link) {
				intf = binding->interface;
				struct mc_fwd *mc;

				/* for each subscribed group... */
				LIST_FOREACH (mc, &(intf->if_mld_head), mcf_link) {
					if (IN6_ARE_ADDR_EQUAL(&mc->mcf_sin6.sin6_addr, &mcf->mcf_sin6.sin6_addr)) {
						IF_SET(proxy_add_mif(intf->if_name), &out);
						subscribers++;
					}
				}
                        }

			if (subscribers == 0) {
				proxy_del_mfc6((struct sockaddr *)&src, &mcf->mcf_sa, mifiUp);
			} else {
				proxy_add_mfc6((struct sockaddr *)&src, &mcf->mcf_sa, mifiUp, &out);
			}

			/*
			 *  We also need to subscribe/unsubscribe the upstream interface to the group
			 *  only if first/last vifi
			 */
			if ((subscribers == 1  && cmd == NOTIFY_GROUP_ADD) || (subscribers == 0 && cmd == NOTIFY_GROUP_DELETE))
				mld_join_group(&mcf->mcf_sin6, prx->proxy_upstream->if_index, cmd == NOTIFY_GROUP_ADD);
		}
	}
}

static void
ifname2addr(const char *ifname, struct in_addr *addr)
{
	struct ifaddrs *ifa, *ifap;

	bzero(addr, sizeof(*addr));
	getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		bcopy(&((struct sockaddr_in *) (ifa->ifa_addr))->sin_addr,
		      addr, sizeof(*addr));
		goto final;
	}

final:
	freeifaddrs(ifap);
	return;
}
