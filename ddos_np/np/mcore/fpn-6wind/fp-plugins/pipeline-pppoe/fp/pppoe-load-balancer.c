/*
 * Copyright(c) 2013 6WIND
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "fpn.h"
#include "fpn-intercore.h"

#include "fp.h"
#include "fp-ether.h"

#include "net/fp-ethernet.h"
#include "net/fp-socket.h"
#include "netinet/fp-in.h"
#include "netinet/fp-in6.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-ip6.h"

#include "fp-jhash.h"

#define PLUGIN_NAME "pppoe-load-balancer"

#include "log.h"
#include "portmap.h"

static struct cpumap cpumap[FPN_MAX_CORES];

FPN_HOOK_CHAIN(fp_ether_input)

#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
#define ETHERTYPE_PPPOE_SESS 0x8864
#define PROT_IP              0x0021
#define PROT_IPV6            0x0057
#else
#define ETHERTYPE_PPPOE_SESS 0x6488
#define PROT_IP              0x2100
#define PROT_IPV6            0x5700
#endif

struct pppoe_hdr {
	unsigned int ver:4;
	unsigned int type:4;
	u_int8_t code;
	u_int16_t sid;
	u_int16_t length;
} __attribute__ ((packed));

struct pppoe_ppp_hdr {
	struct fpn_ether_header eh;
	struct pppoe_hdr ph;
	uint16_t ppp_proto;
} __attribute__ ((packed));

struct pppoe_ip_hdr {
	struct fpn_ether_header eh;
	struct pppoe_hdr ph;
	uint16_t ppp_proto;
	struct fp_ip ih;
} __attribute__ ((packed));

struct pppoe_ipv6_hdr {
	struct fpn_ether_header eh;
	struct pppoe_hdr ph;
	uint16_t ppp_proto;
	struct fp_ip6_hdr ih;
} __attribute__ ((packed));

static inline int handle_pppoe_session(struct mbuf *m, struct portmap *map,
                                       struct pppoe_ppp_hdr *ppp,
                                       fp_ifnet_t *ifp)
{
	unsigned int next;
	uint32_t rxhash = 0;
	uint32_t a, b, c;
	struct pppoe_ip_hdr *ip;
	struct pppoe_ipv6_hdr *ip6;

	switch (ppp->ppp_proto) {
	case PROT_IP:
		if (!m_maypull(m, sizeof(*ip)))
			break;
		ip = mtod(m, struct pppoe_ip_hdr *);
		a = ip->ih.ip_src.s_addr;
		b = ip->ih.ip_dst.s_addr;
		c = ppp->ph.sid;
		fp_jhash_mix(a, b, c);

		rxhash = c;
		break;

	case PROT_IPV6:
		if (!m_maypull(m, sizeof(*ip6)))
			break;
		ip6 = mtod(m, struct pppoe_ipv6_hdr *);

		a = ip6->ih.ip6_src.fp_s6_addr32[0];
		b = ip6->ih.ip6_src.fp_s6_addr32[1];
		c = ip6->ih.ip6_src.fp_s6_addr32[2];
		fp_jhash_mix(a, b, c);

		a += ip6->ih.ip6_src.fp_s6_addr32[3];
		b += ip6->ih.ip6_dst.fp_s6_addr32[0];
		c += ip6->ih.ip6_dst.fp_s6_addr32[1];
		fp_jhash_mix(a, b, c);

		a += ip6->ih.ip6_dst.fp_s6_addr32[2];
		b += ip6->ih.ip6_dst.fp_s6_addr32[3];
		c += ppp->ph.sid;
		fp_jhash_mix(a, b, c);

		rxhash = c;
		break;

	default:
		rxhash = ppp->ph.sid;
		break;
	}

	/*
	 * because of this shift operation , we can't have too many elements
	 * in map => COREMAP_MAX == 32
	 */
	next = map->next[((uint64_t)rxhash * map->count)>>COREMAP_MAX];

	if (!m_set_process_fct(m, FPN_HOOK_PREV(fp_ether_input), ifp) &&
	    !fpn_intercore_enqueue(m, next))
		/* Let's tell Fast Path we handled this packet */
		return FP_KEEP;

	/* Fast Path will drop and free mbuf */
	return FP_DROP;
}

int fp_ether_input(struct mbuf *m, fp_ifnet_t *ifp)
{
	unsigned int cur = fpn_get_core_num();
	struct portmap *map;
	struct pppoe_ppp_hdr *ppp;

	map = &cpumap[cur].ports[ifp->if_port];

	/* we want to look at pppoe header + ppp proto */
	if (map->count && m_maypull(m, sizeof(*ppp))) {
		ppp = mtod(m, struct pppoe_ppp_hdr *);

		if (ppp->eh.ether_type == ETHERTYPE_PPPOE_SESS) {
			return handle_pppoe_session(m, map, ppp, ifp);
		}
	}

	/* else, handle locally */
	return FPN_HOOK_PREV(fp_ether_input)(m, ifp);
}


static void lib_init(void) __attribute__((constructor));
void lib_init(void)
{
	int i, j, k;
	char *cpumap_env;
	fpn_cpumask_t mask;

	fpn_cpumask_clear(&mask);
	memset(cpumap, 0, sizeof(cpumap));

	if ((cpumap_env = getenv("PPPOE_LB_CPUPORTMAP"))) {
		if (parse_cpumap(cpumap_env, cpumap, &fpn_coremask,
		                 parse_cores) < 0)
			return;
	}

	/* Let's find which cpu must look at their intercore ring */
	for (i = 0; i < FPN_MAX_CORES; i++) {
		for (j = 0; j < FPN_MAX_PORTS; j++) {
			struct portmap *map = &cpumap[i].ports[j];
			for (k = 0; k < map->count; k++) {
				fpn_cpumask_set(&mask, map->next[k]);
			}
		}
	}

	/* Ok, ready */
	fpn_cpumask_add(&fpn_intercore_mask, &mask);

	fpn_cpumask_display(PLUGIN_NAME ": using fpn_intercore_mask=", &fpn_intercore_mask);
	fpn_cpumask_display(", plugin mask=", &mask);
	printf("\n");
}
