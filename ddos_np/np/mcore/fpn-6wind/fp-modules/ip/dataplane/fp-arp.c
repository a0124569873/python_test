/*
 * Copyright(c) 2012 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-arp.h"

#include "fp-log.h"
#include "fp-main-process.h"
#include "fp-lookup.h"

#define TRACE_ARP(level, fmt, args...) do {		\
	FP_LOG(level, ARP, fmt "\n", ## args);		\
} while(0)

struct fp_arphdr {
#define FP_ARPHRD_ETHER	1
	  uint16_t ar_hrd;		/* format of hardware address */

	  uint16_t ar_pro;		/* format of protocol address */
	  uint8_t ar_hln;		/* length of hardware address */
	  uint8_t ar_pln;		/* length of protocol address */

#define	FP_ARPOP_REQUEST	1	/* request to resolve address */
#define	FP_ARPOP_REPLY		2	/* response to previous request */
#define	FP_ARPOP_REVREQUEST	3	/* request proto addr given hardware */
#define	FP_ARPOP_REVREPLY	4	/* response giving protocol address */
#define	FP_ARPOP_INVREQUEST	8	/* request to identify peer */
#define	FP_ARPOP_INVREPLY	9	/* response identifying peer */
	  uint16_t ar_op;		/* ARP opcode (command) */

#if 0
	  uint8_t ar_sha[ETH_ALEN];	/* sender hardware address */
	  uint8_t ar_sip[4];		/* sender IP address */
	  uint8_t ar_tha[ETH_ALEN];	/* target hardware address */
	  uint8_t ar_tip[4];		/* target IP address */
#endif
};

static int fp_arp_answer(struct mbuf *m, fp_ifnet_t *ifp);

int fp_arp_input(struct mbuf *m, fp_ifnet_t *ifp)
{
	struct fp_arphdr *arp;
	struct fp_ether_header* eh;

	TRACE_ARP(FP_LOG_DEBUG, "%s(ifp=%s)", __FUNCTION__, ifp->if_name);

	eh = mtod(m, struct fp_ether_header *);

	if (m_headlen(m) < sizeof(struct fp_ether_header) +
	    sizeof(struct fp_arphdr)) {
		TRACE_ARP(FP_LOG_WARNING, "arp too short");
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_errors);
		return FP_DROP;
	}

	arp = (struct fp_arphdr *)(eh + 1);

	if (ntohs(arp->ar_hrd) != FP_ARPHRD_ETHER) {
		TRACE_ARP(FP_LOG_DEBUG,
			  "arp hrd is not ethernet: 0x%x",
			  ntohs(arp->ar_hrd));
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_unhandled);
		return FP_CONTINUE;
	}

	if (ntohs(arp->ar_pro) != FP_ETHERTYPE_IP) {
		TRACE_ARP(FP_LOG_DEBUG,
			  "arp ethertype is not IP: 0x%x 0x%x",
			  ntohs(arp->ar_pro), FP_ETHERTYPE_IP);
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_unhandled);
		return FP_CONTINUE;
	}

	if (arp->ar_hln != FP_ETHER_ADDR_LEN) {
		TRACE_ARP(FP_LOG_DEBUG,
			  "arp hw header len is not %d: %d",
			  FP_ETHER_ADDR_LEN, arp->ar_hln);
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_unhandled);
		return FP_CONTINUE;
	}

	if (arp->ar_pln != 4) {
		TRACE_ARP(FP_LOG_DEBUG,
			  "arp hw prot len is not 0x4: 0x%x",
			  arp->ar_pln);
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_unhandled);
		return FP_CONTINUE;
	}

	if (ntohs(arp->ar_op) != FP_ARPOP_REQUEST) {
		TRACE_ARP(FP_LOG_DEBUG,
			  "arp opcode is not 0x%x (arp-request): 0x%x",
			  FP_ARPOP_REQUEST, ntohs(arp->ar_op));
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_unhandled);
		return FP_CONTINUE;
	}

	return fp_arp_answer(m, ifp);
}

static int fp_arp_answer(struct mbuf *m, fp_ifnet_t *ifp)
{
	struct fp_ether_header* eh;
	struct fp_arphdr *arp;
	fp_rt4_entry_t *rt4;
	fp_nh4_entry_t *nh4;
	char tmp[10]; /* to swap ip+mac */
	uint32_t addr;
	uint16_t vrfid;
	int i;

	if (m_headlen(m) < sizeof(struct fp_ether_header) +
	    sizeof(struct fp_arphdr) + 20) { /* 20 is 2x (IP + mac address) */
		TRACE_ARP(FP_LOG_WARNING, "arp too short");
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_errors);
		return FP_DROP;
	}

	eh = mtod(m, struct fp_ether_header *);
	arp = (struct fp_arphdr *)(eh + 1);

	/* lookup for this address */
	memcpy(&addr, (char *)(arp + 1) + 16, sizeof(addr));
	vrfid = ifp->if_vrfid;
	TRACE_ARP(FP_LOG_DEBUG, "looking up for "FP_NIPQUAD_FMT
			" vrfid %" PRIu16,
			FP_NIPQUAD(addr), vrfid);
	rt4 = fp_rt4_lookup(vrfid, addr);

	if (rt4 == NULL) {
		TRACE_ARP(FP_LOG_DEBUG, "address not found (rt)");
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_not_found);
		return FP_DROP;
	}

	/* rt entry found, look at next hops (which stores address) */
	for (i = 0; i < rt4->rt.rt_nb_nh; i++) {
		nh4 = &fp_shared->fp_nh4_table[rt4->rt.rt_next_hop[i]];
		if (nh4->nh.rt_type != RT_TYPE_ADDRESS)
			continue;
		if (nh4->nh.nh_ifuid != ifp->if_ifuid)
			continue;
		break; /* found ! */
	}
	if (i == rt4->rt.rt_nb_nh) {
		/* not found */
		TRACE_ARP(FP_LOG_DEBUG, "address not found (nh)");
		FP_ARP_STATS_INC(fp_shared->arp_stats, arp_not_found);
		return FP_DROP;
	}

	/* build the new ethernet header */
	memcpy(eh->ether_dhost, eh->ether_shost, FP_ETHER_ADDR_LEN);
	memcpy(eh->ether_shost, ifp->if_mac, FP_ETHER_ADDR_LEN);

	arp->ar_op = htons(FP_ARPOP_REPLY);

	/* swap ip+mac */
	memcpy(tmp, (char *)(arp + 1), 10);
	memcpy((char *)(arp + 1), (char *)(arp + 1) + 10, 10);
	memcpy((char *)(arp + 1) + 10, tmp, 10);

	memcpy((char *)(arp + 1), ifp->if_mac, FP_ETHER_ADDR_LEN);

	FP_ARP_STATS_INC(fp_shared->arp_stats, arp_replied);
	return FPN_HOOK_CALL(fp_if_output)(m, ifp);
}
