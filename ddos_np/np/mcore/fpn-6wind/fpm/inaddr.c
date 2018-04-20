/*
 * Copyright (c) 2006 6WIND
 * $Id: inaddr.c,v 1.26 2009-10-07 15:53:43 guerin Exp $
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <event.h>
#include <arpa/inet.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"
#include "net/fp-ethernet.h"
#ifdef CONFIG_MCORE_IP
#include "fp-neigh.h"
#endif

uint32_t nb_incomplete = 0;
int timer_running = 0;
int timer_restarted = 0;
struct event arp_timer;

#ifdef CONFIG_MCORE_IP
/*
 * Add an exception path for all the addresses that
 * we own, so the slow path can process these packets.
 * We do not need to check if the fast path support this
 * kind of interface or not. It will be done by the procedure
 * that must add the connected routes.
 */
static int
fpm_interface_ipv4_addr_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_ipv4_addr *req =
		(const struct cp_iface_ipv4_addr *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_interface_ipv4_addr_add: %u.%u.%u.%u ifx=0x%08x\n",
		       FP_NIPQUAD(req->cpiface_addr.s_addr),
		       ntohl(req->cpiface_ifuid));

	fp_add_address4(req->cpiface_addr.s_addr, req->cpiface_ifuid);
	return EXIT_SUCCESS;
}

/*
 */
static int
fpm_interface_ipv4_addr_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_ipv4_addr *req =
		(const struct cp_iface_ipv4_addr *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_interface_ipv4_addr_del: %u.%u.%u.%u ifx=0x%08x\n",
		       FP_NIPQUAD(req->cpiface_addr.s_addr),
		       ntohl(req->cpiface_ifuid));

	fp_delete_address4(req->cpiface_addr.s_addr, req->cpiface_ifuid);
	return EXIT_SUCCESS;
}
#endif /* CONFIG_MCORE_IP */

static void arp_timer_cb(int fd,  short event, void* arg)
{
    __attribute__((unused)) unsigned int i;
#ifdef CONFIG_MCORE_IP

	/* Scan ipv4 neighbour table */
    for (i = 1; i < FP_IPV4_NBNHENTRIES; i++) {
        fp_nh4_entry_t *nhe = &fp_shared->fp_nh4_table[i];
        if (!nhe->nh.nh_refcnt)
            continue;
        if (nhe->nh.nh_l2_state == L2_STATE_INCOMPLETE) {
			fp_delete_neighbour4(nhe->nh_gw, nhe->nh.nh_ifuid);
		}
    }
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
	/* Scan ipv6 neighbour table */
    for (i = 1; i < FP_IPV6_NBNHENTRIES ; i++) {
        fp_nh6_entry_t *nhe = &fp_shared->fp_nh6_table[i];
        if (!nhe->nh.nh_refcnt)
            continue;
		if (nhe->nh.nh_l2_state == L2_STATE_INCOMPLETE) {
			fp_delete_neighbour6(&nhe->nh_gw, nhe->nh.nh_ifuid);
		}
    }
#endif
	timer_running = 0;
	nb_incomplete = 0;

}

void fpm_monitor_incomplete_nh_entries(void)
{
	int i;
	struct timeval tv;

	nb_incomplete = 0;
	timer_restarted = 0;

	/* Scan ipv4 neighbour table */
	for (i = 1; i < FP_IPV4_NBNHENTRIES; i++) {
		fp_nh4_entry_t *nhe = &fp_shared->fp_nh4_table[i];
		if (!nhe->nh.nh_refcnt)
			continue;
		if (nhe->nh.nh_l2_state == L2_STATE_INCOMPLETE) {
			nb_incomplete++;
		}
	}
#ifdef CONFIG_MCORE_IPV6
	/* Scan ipv4 neighbour table */
	for (i = 1; i < FP_IPV6_NBNHENTRIES ; i++) {
		fp_nh6_entry_t *nhe = &fp_shared->fp_nh6_table[i];
		if (!nhe->nh.nh_refcnt)
			continue;
		if (nhe->nh.nh_l2_state == L2_STATE_INCOMPLETE) {
			nb_incomplete++;
		}
	}
#endif
	if (nb_incomplete > 0) {
		tv.tv_sec = FPM_NH_INCOMPLETE_TIME;
		tv.tv_usec = 0;
		timer_running = 1;
		timer_restarted = 0;
		evtimer_set(&arp_timer, arp_timer_cb, NULL);
		evtimer_add(&arp_timer, &tv);
	}
}

#ifdef CONFIG_MCORE_IP
static int fpm_arp_update(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_l2* req = (const struct cp_l2*)request;
	uint32_t ifuid;
	uint32_t nh;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_arp_update: req=%u %u.%u.%u.%u "
		       FP_NMAC_FMT " ifx=0x%08x\n",
		       req->cpl2_state, FP_NIPQUAD(req->cpl2_ip4addr),
		       FP_NMAC(req->cpl2_mac), ntohl(req->cpl2_ifuid));

	ifuid = req->cpl2_ifuid;

	/* When an entry in the shared memory is created in incomplete state it can stay
	 * forever. A periodic check done by the FPM could clean those entries. The goal
	 * would be to scan the next-hop table to locate the neighbors in INCOMPLETE
	 * state and move them to the NONE state.
	 *
	 * For optimization such check can be triggered only IF there are some INCOMPLETE
	 * ARP entries. To handle this the number of such APR entries must be kept by
	 * FPM (either stored in shared memory, or re-computed during FPM GR phase).
	 *
	 * When the 1st ARP entry to monitor is created, a timer is launched for clean-up
	 * with a delay T1.
	 *
	 * When new ARP entries are created INCOMPLETE, if the timer is already running
	 * it should be stopped and re-started. This restart of timer must be done only
	 * once; if the same situation re-happens, the timer must not be restarted.
	 *
	 * When the number of INCOMPLETE ARP reaches 0, the timer must be stopped if it
	 * was running.
	 */

	nh = fp_nh4_lookup(req->cpl2_ip4addr.s_addr, ifuid, RT_TYPE_NEIGH, NULL);
	if((nh == 0 || fp_shared->fp_nh4_table[nh].nh.nh_l2_state != L2_STATE_INCOMPLETE) &&
			req->cpl2_state == CM_L2STATE_INCOMPLETE) {
		struct timeval tv;

		tv.tv_sec = FPM_NH_INCOMPLETE_TIME;
		tv.tv_usec = 0;
		nb_incomplete++;
		if (!timer_running) {
			timer_running = 1;
			timer_restarted = 0;
			evtimer_set(&arp_timer, arp_timer_cb, NULL);
			evtimer_add(&arp_timer, &tv);
		} else if (!timer_restarted) {
			timer_restarted = 1;
			evtimer_del(&arp_timer);
			evtimer_set(&arp_timer, arp_timer_cb, NULL);
			evtimer_add(&arp_timer, &tv);
		}
	} else if ((nh != 0 && fp_shared->fp_nh4_table[nh].nh.nh_l2_state == L2_STATE_INCOMPLETE) &&
			req->cpl2_state != CM_L2STATE_INCOMPLETE) {
		nb_incomplete--;
		if (nb_incomplete == 0) {
			timer_running = 0;
			evtimer_del(&arp_timer);
		}
	}

	switch (req->cpl2_state) {
	case CM_L2STATE_NONE:
		/* Delete the entry */
		fp_delete_neighbour4(req->cpl2_ip4addr.s_addr, ifuid);
		break;

	case CM_L2STATE_STALE:
		/* Add the entry */
		fp_add_neighbour4(req->cpl2_ip4addr.s_addr, req->cpl2_mac,
				ifuid, L2_STATE_STALE);
		break;

	case CM_L2STATE_REACHABLE:
		/* Add the entry */
		fp_add_neighbour4(req->cpl2_ip4addr.s_addr, req->cpl2_mac,
				ifuid, L2_STATE_REACHABLE);
		break;

	case CM_L2STATE_INCOMPLETE: /* req->cpl2_mac is unspec */
		/* Add the entry */
		fp_add_neighbour4(req->cpl2_ip4addr.s_addr, req->cpl2_mac,
				ifuid, L2_STATE_INCOMPLETE);
		break;

	default:
		/* must never reach this line */
		assert(req->cpl2_state != 0);
		break;
	}

	return EXIT_SUCCESS;
}
#endif


#ifdef CONFIG_MCORE_IPV6
/*
 * Add an exception path for all the addresses that
 * we own, so the slow path can process these packets.
 * We do not need to check if the fast path support this
 * kind of interface or not. It will be done by the procedure
 * that must add the connected routes.
 */
static int
fpm_interface_ipv6_addr_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_ipv6_addr* req =
		(const struct cp_iface_ipv6_addr *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_interface_ipv6_addr_add: %x:%x:%x:%x:%x:%x:%x:%x ifx=0x%08x\n",
		       NIPOCT(req->cpiface_addr.s6_addr16), ntohl(req->cpiface_ifuid));

	fp_add_address6((fp_in6_addr_t *)&req->cpiface_addr, req->cpiface_ifuid);
	return EXIT_SUCCESS;
}

static int
fpm_interface_ipv6_addr_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_ipv6_addr* req =
		(const struct cp_iface_ipv6_addr *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_interface_ipv4_addr_del: %x:%x:%x:%x:%x:%x:%x:%x ifx=0x%08x\n",
		       NIPOCT(req->cpiface_addr.s6_addr16), ntohl(req->cpiface_ifuid));

	fp_delete_address6((fp_in6_addr_t *)&req->cpiface_addr, 
	                   req->cpiface_ifuid);
	return EXIT_SUCCESS;
}

static int fpm_ndp_update(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_l2 *req = (const struct cp_l2 *)request;
	uint32_t ifuid;
	uint32_t nh;;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_ndp_update: req=%u %x:%x:%x:%x:%x:%x:%x:%x "
		       FP_NMAC_FMT " ifx=0x%08x\n",
		       req->cpl2_state, NIPOCT(req->cpl2_ip6addr.s6_addr16),
		       FP_NMAC(req->cpl2_mac), ntohl(req->cpl2_ifuid));

	ifuid = req->cpl2_ifuid;

	/* When an entry in the shared memory is created in incomplete state it can stay
	 * forever. A periodic check done by the FPM could clean those entries. The goal
	 * would be to scan the next-hop table to locate the neighbors in INCOMPLETE
	 * state and move them to the NONE state.
	 *
	 * For optimization such check can be triggered only IF there are some INCOMPLETE
	 * NDP entries. To handle this the number of such APR entries must be kept by
	 * FPM (either stored in shared memory, or re-computed during FPM GR phase).
	 *
	 * When the 1st NDP entry to monitor is created, a timer is launched for clean-up
	 * with a delay T1.
	 *
	 * When new NDP entries are created INCOMPLETE, if the timer is already running
	 * it should be stopped and re-started. This restart of timer must be done only
	 * once; if the same situation re-happens, the timer must not be restarted.
	 *
	 * When the number of INCOMPLETE NDP reaches 0, the timer must be stopped if it
	 * was running.
	 */
	nh = fp_nh6_lookup((fp_in6_addr_t *)&(req->cpl2_ip6addr), ifuid, RT_TYPE_NEIGH, NULL);
	if ((nh == 0 || fp_shared->fp_nh6_table[nh].nh.nh_l2_state != L2_STATE_INCOMPLETE) &&
			req->cpl2_state == CM_L2STATE_INCOMPLETE) {
		struct timeval tv;

		tv.tv_sec = FPM_NH_INCOMPLETE_TIME;
		tv.tv_usec = 0;
		nb_incomplete++;
		if (!timer_running) {
			timer_running = 1;
			timer_restarted = 0;
			evtimer_set(&arp_timer, arp_timer_cb, NULL);
			evtimer_add(&arp_timer, &tv);
		} else if (!timer_restarted) {
			timer_restarted = 1;
			evtimer_del(&arp_timer);
			evtimer_set(&arp_timer, arp_timer_cb, NULL);
			evtimer_add(&arp_timer, &tv);
		}
	} else if ((nh != 0 && fp_shared->fp_nh6_table[nh].nh.nh_l2_state == L2_STATE_INCOMPLETE) &&
			req->cpl2_state != CM_L2STATE_INCOMPLETE) {
		nb_incomplete--;
		if (nb_incomplete == 0) {
			timer_running = 0;
			evtimer_del(&arp_timer);
		}
	}

	switch (req->cpl2_state) {
	case CM_L2STATE_NONE:
		/* Delete the entry */
		fp_delete_neighbour6((fp_in6_addr_t *)&(req->cpl2_ip6addr),
				ifuid);
		break;

	case CM_L2STATE_STALE:
		/* Add the entry */
		fp_add_neighbour6((fp_in6_addr_t *)&(req->cpl2_ip6addr), req->cpl2_mac,
				ifuid, L2_STATE_STALE);
		break;

	case CM_L2STATE_REACHABLE:
		/* Add the entry */
		fp_add_neighbour6((fp_in6_addr_t *)&(req->cpl2_ip6addr), req->cpl2_mac,
				ifuid, L2_STATE_REACHABLE);
		break;

	case CM_L2STATE_INCOMPLETE: /* req->cpl2_mac is unspec */
		/* Add the entry */
		fp_add_neighbour6((fp_in6_addr_t *)&(req->cpl2_ip6addr), req->cpl2_mac,
				ifuid, L2_STATE_INCOMPLETE);
		break;

	default:
		/* must never reach this line */
		assert(req->cpl2_state != 0);
		break;
	}

	return EXIT_SUCCESS;
}
#endif /* CONFIG_MCORE_IPV6 */

/* fpm_add_v4_arp_cmd, fpm_add_v4_addr_cmd and fpm_add_v6_addr_cmd */
/* Special cases; those dumps are done through rt_dump common code */
/* Through calls to fpm_rt4_entries_to_cmd done in route dump */

/* IPv4 routes and addresses entries */
#ifdef CONFIG_MCORE_IP
int fpm_add_v4_addr_cmd(uint32_t ifuid, uint32_t address)
{
	struct cp_iface_ipv4_addr req;

	/* Clear memory */
	memset(&req, 0, sizeof(req));

	if (ifuid) {
		req.cpiface_ifuid = ifuid;
		memcpy(&req.cpiface_addr, &address, sizeof(req.cpiface_addr));

		return fpm_cmd_create_and_enqueue(FPM_GR_SHMEM_LIST,
		                                  CMD_INTERFACE_IPV4_ADDR_ADD, &req);
	}

	return 0;
}

int fpm_add_v4_arp_cmd(uint32_t ifuid, uint32_t address, uint8_t *dhost)
{
	struct cp_l2 req;

	/* Clear memory */
	memset(&req, 0, sizeof(req));

	req.cpl2_ifuid = ifuid;
	memcpy(&req.cpl2_mac, dhost, sizeof(req.cpl2_mac));
	memcpy(&req.cpl2_ip4addr, &address, sizeof(req.cpl2_ip4addr));
	req.cpl2_state = CM_L2STATE_NONE;

	return fpm_cmd_create_and_enqueue(FPM_GR_SHMEM_LIST, CMD_ARP_UPDATE, &req);
}
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
int fpm_add_v6_addr_cmd(uint32_t ifuid, fp_in6_addr_t *address)
{
	struct cp_iface_ipv6_addr req;

	/* Clear memory */
	memset(&req, 0, sizeof(req));

	if (ifuid) {
		req.cpiface_ifuid = ifuid;
		memcpy(&req.cpiface_addr, address, sizeof(req.cpiface_addr));

		return fpm_cmd_create_and_enqueue(FPM_GR_SHMEM_LIST,
		                                  CMD_INTERFACE_IPV6_ADDR_ADD, &req);
	}

	return 0;
}

int fpm_add_v6_ndp_cmd(uint32_t ifuid, fp_in6_addr_t *ip6, uint8_t *dhost)
{
	struct cp_l2 req;

	/* Clear memory */
	memset(&req, 0, sizeof(req));

	req.cpl2_ifuid = ifuid;
	memcpy(&req.cpl2_mac, dhost, sizeof(req.cpl2_mac));
	memcpy(&req.cpl2_ip6addr, ip6, sizeof(req.cpl2_ip6addr));
	req.cpl2_state = CM_L2STATE_NONE;

	return fpm_cmd_create_and_enqueue(FPM_GR_SHMEM_LIST, CMD_NDP_UPDATE, &req);
}
#endif /* CONFIG_MCORE_IPV6 */

static int fpm_interface_ipv4_addr_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_iface_ipv4_addr *addr1 = cmd1->data;
	struct cp_iface_ipv4_addr *addr2 = cmd2->data;

	if (addr1->cpiface_ifuid == addr2->cpiface_ifuid) {
		return memcmp(&addr1->cpiface_addr, &addr2->cpiface_addr,
		              sizeof(addr1->cpiface_addr));
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_interface_ipv4_addr_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_INTERFACE_IPV4_ADDR_DEL);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_interface_ipv4_addr_display(const fpm_cmd_t *fpm_cmd,
                                            char *buffer, int len)
{
	struct cp_iface_ipv4_addr *data = fpm_cmd->data;
	char addr_str[INET_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_INTERFACE_IPV4_ADDR - %s/%u ifuid 0x%08x\n", 
		   inet_ntop(AF_INET, &data->cpiface_addr, addr_str, sizeof(addr_str)),
		   (unsigned)data->cpiface_pfxlen, ntohl(data->cpiface_ifuid));
}

static fpm_cmd_t *fpm_interface_ipv4_addr_graceful(int gr_type, uint32_t cmd,
                                                   const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE_ADDR, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_iface_ipv4_addr));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_INTERFACE_ADDR;
	fpm_cmd->comp    = fpm_interface_ipv4_addr_comp;
	fpm_cmd->revert  = fpm_interface_ipv4_addr_revert;
	fpm_cmd->display = fpm_interface_ipv4_addr_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

static int fpm_arp_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_l2 *arp1 = cmd1->data;
	struct cp_l2 *arp2 = cmd2->data;

	return (memcmp(&(arp1->cpl2_ip4addr), &(arp2->cpl2_ip4addr),
	        sizeof(arp1->cpl2_ip4addr)) ||
		    (arp1->cpl2_ifuid != arp2->cpl2_ifuid));
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_arp_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_ARP_UPDATE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_arp_display(const fpm_cmd_t *fpm_cmd,
                            char *buffer, int len)
{
	struct cp_l2 *data = fpm_cmd->data;
	char addr_str[INET_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_ARP - %s is %02x:%02x:%02x:%02x:%02x:%02x - state %d ifuid 0x%08x\n",
	   inet_ntop(AF_INET, &data->cpl2_ip4addr, addr_str, sizeof(addr_str)),
	   data->cpl2_mac[0], data->cpl2_mac[1], data->cpl2_mac[2],
	   data->cpl2_mac[3], data->cpl2_mac[4], data->cpl2_mac[5],
	   data->cpl2_state, ntohl(data->cpl2_ifuid));
}

static fpm_cmd_t *fpm_arp_graceful(int gr_type, uint32_t cmd,
                                   const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_L2, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_l2));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_L2;
	fpm_cmd->comp    = fpm_arp_comp;
	fpm_cmd->revert  = fpm_arp_revert;
	fpm_cmd->display = fpm_arp_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

#ifdef CONFIG_MCORE_IPV6
static int fpm_interface_ipv6_addr_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_iface_ipv6_addr* addr1 = cmd1->data;
	struct cp_iface_ipv6_addr* addr2 = cmd2->data;

	if (addr1->cpiface_ifuid == addr2->cpiface_ifuid) {
		return memcmp(&addr1->cpiface_addr, &addr2->cpiface_addr,
		              sizeof(addr1->cpiface_addr));
	}
	return 1;
}
#endif

/* Invert the command, and send it to the fpm dispatch function */
#ifdef CONFIG_MCORE_IPV6
static int fpm_interface_ipv6_addr_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_INTERFACE_IPV6_ADDR_DEL);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}
#endif

#ifdef CONFIG_MCORE_IPV6
static void fpm_interface_ipv6_addr_display(const fpm_cmd_t *fpm_cmd,
                                            char *buffer, int len)
{
	struct cp_iface_ipv6_addr *data = fpm_cmd->data;
	char addr_str[INET6_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_INTERFACE_IPV6_ADDR - %s/%u ifuid 0x%08x\n",
	   inet_ntop(AF_INET6, &data->cpiface_addr, addr_str, sizeof(addr_str)),
	   (unsigned)data->cpiface_pfxlen, ntohl(data->cpiface_ifuid));
}
#endif

#ifdef CONFIG_MCORE_IPV6
static fpm_cmd_t *fpm_interface_ipv6_addr_graceful(int gr_type, uint32_t cmd,
                                                   const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE_ADDR, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_iface_ipv6_addr));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_INTERFACE_ADDR;
	fpm_cmd->comp    = fpm_interface_ipv6_addr_comp;
	fpm_cmd->revert  = fpm_interface_ipv6_addr_revert;
	fpm_cmd->display = fpm_interface_ipv6_addr_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif

#ifdef CONFIG_MCORE_IPV6
static int fpm_ndp_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_l2 *ndp1 = cmd1->data;
	struct cp_l2 *ndp2 = cmd2->data;

	return (memcmp(&(ndp1->cpl2_ip6addr), &(ndp2->cpl2_ip6addr),
	        sizeof(ndp1->cpl2_ip6addr)) ||
	        (ndp1->cpl2_ifuid != ndp2->cpl2_ifuid));
}
#endif

#ifdef CONFIG_MCORE_IPV6
/* Invert the command, and send it to the fpm dispatch function */
static int fpm_ndp_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_NDP_UPDATE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}
#endif

#ifdef CONFIG_MCORE_IPV6
static void fpm_ndp_display(const fpm_cmd_t *fpm_cmd,
                            char *buffer, int len)
{
	struct cp_l2 *data = fpm_cmd->data;
	char addr_str[INET6_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_NDP - %s is %02x:%02x:%02x:%02x:%02x:%02x - state %d ifuid 0x%08x\n",
	   inet_ntop(AF_INET6, &data->cpl2_ip6addr, addr_str, sizeof(addr_str)),
	   data->cpl2_mac[0], data->cpl2_mac[1], data->cpl2_mac[2],
	   data->cpl2_mac[3], data->cpl2_mac[4], data->cpl2_mac[5],
	   data->cpl2_state, ntohl(data->cpl2_ifuid));
}
#endif

#ifdef CONFIG_MCORE_IPV6
static fpm_cmd_t *fpm_ndp_graceful(int gr_type, uint32_t cmd,
                                   const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_L2, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_l2));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_L2;
	fpm_cmd->comp    = fpm_ndp_comp;
	fpm_cmd->revert  = fpm_ndp_revert;
	fpm_cmd->display = fpm_ndp_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif

static int fpm_inaddr_shared_cmd(int gr_type, enum list_type list)
{
	int ret = 0;

#ifdef CONFIG_MCORE_IPV6
	int nh6_idx;

	/* Dump IPv6 routes if needed */
	if (fpm_cmd_match_gr_type(FPM_CMD_L2, gr_type)) {
		fp_nh6_entry_t *fp_nh6_table = fp_shared->fp_nh6_table;

		for (nh6_idx=1 ; nh6_idx<FP_IPV6_NBNHENTRIES ; nh6_idx++) {
			fp_nh6_entry_t nhe = fp_nh6_table[nh6_idx];
			struct cp_l2 req;

			if (nhe.nh.nh_refcnt) {
				if (nhe.nh.nh_type == NH_TYPE_GW) {
					/*
					 * Only a non CM_L2STATE_NONE entry can be a
					 * NDP entry, see fpm_ndp_update()
					 */
					if (nhe.nh.nh_l2_state == CM_L2STATE_NONE)
						continue;
					/*
					 * All non link-local NDP entries are managed
					 * through the routing table dump.
					 */
					if (!fp_in6_is_link_local(nhe.nh_gw))
						continue;

					/* Clear memory */
					memset(&req, 0, sizeof(req));

					req.cpl2_ifuid = nhe.nh.nh_ifuid;
					memcpy(&req.cpl2_mac, nhe.nh.nh_eth.ether_dhost, sizeof(req.cpl2_mac));
					memcpy(&req.cpl2_ip6addr, &nhe.nh_gw, sizeof(req.cpl2_ip6addr));
					req.cpl2_state = CM_L2STATE_NONE;

					ret |= fpm_cmd_create_and_enqueue(list, CMD_NDP_UPDATE, &req);
				}
			}
		}
	}
#endif /* CONFIG_MCORE_IPV6 */

	return ret;
}

static void fpm_inaddr_init(__attribute__((unused)) int graceful)
{
#ifdef CONFIG_MCORE_IP
	fpm_register_msg(CMD_INTERFACE_IPV4_ADDR_ADD, fpm_interface_ipv4_addr_add,
	                 fpm_interface_ipv4_addr_graceful);
	fpm_register_msg(CMD_INTERFACE_IPV4_ADDR_DEL,
	                 fpm_interface_ipv4_addr_del, NULL);
	fpm_register_msg(CMD_ARP_UPDATE, fpm_arp_update, fpm_arp_graceful);
#endif /* CONFIG_MCORE_IP */

#ifdef CONFIG_MCORE_IPV6
	fpm_register_msg(CMD_INTERFACE_IPV6_ADDR_ADD, fpm_interface_ipv6_addr_add,
	                 fpm_interface_ipv6_addr_graceful);
	fpm_register_msg(CMD_INTERFACE_IPV6_ADDR_DEL,
	                 fpm_interface_ipv6_addr_del, NULL);
	fpm_register_msg(CMD_NDP_UPDATE, fpm_ndp_update, fpm_ndp_graceful);
#endif /* CONFIG_MCORE_IPV6 */
}

static struct fpm_mod fpm_inaddr_mod = {
	.name = "inaddr",
	.init = fpm_inaddr_init,
	.shared_cmd = fpm_inaddr_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_inaddr_mod);
}
