/*
 * Copyright 2007-2010 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <event.h>
#include <time.h>
#include <sys/queue.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netgraph.h>
#include <netgraph/ng_filter.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "pingd.h"
#include "util.h"
#include "network.h"
#include "node.h"
#include "in_cksum.h"

/* ping echo request sent */
uint32_t stats_request_snd = 0;
/* ping echo request received */
uint32_t stats_request_rcv = 0;
/* ping echo reply received */
uint32_t stats_reply_rcv = 0;

static int send_echorequest(struct node *entry);
static int send_echoreply(struct node *entry, uint32_t daddr, uint32_t saddr,
		uint16_t seqno, uint16_t id, uint16_t datalen, uint8_t *data);

#define DATALEN 56
#define MAXPACKET 2048
static uint8_t snd_packet[MAXPACKET];
static uint8_t rcv_packet[MAXPACKET];

void update_seqno(struct node *entry)
{
	if (++entry->nd_current_seqno == 0) {
		entry->nd_current_seqno = (~0) - entry->nd_last_seqno + 1;
		entry->nd_last_seqno = 0;
	}
}

void check_carrier(__attribute__ ((unused))int sock,
		__attribute__ ((unused))short event, void *arg)
{
	struct node *entry = (struct node *)arg;

	if (entry->nd_carrier &&
	    entry->nd_current_seqno - entry->nd_last_seqno >= entry->nd_robustness) {
		DEBUG(LOG_DEBUG, "No carrier for %s\n", entry->nd_name);
		entry->nd_carrier = 0;
		node_setcarrier(entry);
	}
	if (!entry->nd_carrier &&
	    entry->nd_current_seqno - entry->nd_last_seqno < entry->nd_robustness) {
		DEBUG(LOG_DEBUG, "Carrier detected for %s\n", entry->nd_name);
		entry->nd_carrier = 1;
		node_setcarrier(entry);
	}
	return;
}

void csock_input(int sock, __attribute__ ((unused))short event,
		__attribute__ ((unused))void *arg)
{
	/* Nothing expected on the Control Socket from VNB node.
	   Just purge socket */
	NgRecvData(sock, rcv_packet, sizeof(rcv_packet), NULL);
	return;
}

void dsock_input(int sock, __attribute__ ((unused))short event, void *arg)
{
	struct node *entry = (struct node *)arg;
	struct iphdr *ip;
	struct icmphdr *icmp;
	int len;

	len = NgRecvData(sock, rcv_packet, sizeof(rcv_packet), NULL);
	if (len < sizeof(struct iphdr) + sizeof(struct icmphdr)) {
		DEBUG(LOG_WARNING, "Receive unexpected data on %s (packet is too short)\n",
				entry->nd_name);
		return;
	}

	ip = (struct iphdr *)rcv_packet;
	if (ip->protocol != IPPROTO_ICMP) {
		DEBUG(LOG_WARNING, "Receive unexpected data on %s (not an ICMP packet)\n",
				entry->nd_name);
		return;
	}

	icmp = (struct icmphdr *)(ip + 1);
	switch (icmp->type) {
	case ICMP_ECHO:
		DEBUG(LOG_DEBUG, "Receive ICMP Echo Request on %s\n", entry->nd_name);
		if (len != htons(ip->tot_len)) {
			DEBUG(LOG_WARNING, "Receive an invalid ICMP "
					"Echo Request on %s (length mismatch)\n",
					entry->nd_name);
			return;
		}
		stats_request_rcv++;
		/* src addr is always our address (even if Echo Request is sent
		   on broadcast addr */
		send_echoreply(entry, ip->saddr, entry->nd_ouraddr,
				icmp->un.echo.sequence,
				icmp->un.echo.id,
				len - sizeof(struct iphdr) - sizeof(struct icmphdr),
				(uint8_t *)(icmp + 1));
		break;
	case ICMP_ECHOREPLY:
		if (icmp->un.echo.id != ping_id) {
			DEBUG(LOG_INFO, "This ICMP Echo Reply isn't for us (%s)\n",
					entry->nd_name);
			return;
		}
		if (ntohs(icmp->un.echo.sequence) > entry->nd_last_seqno &&
		     ntohs(icmp->un.echo.sequence) <= entry->nd_current_seqno) {
			entry->nd_last_seqno = ntohs(icmp->un.echo.sequence);
			DEBUG(LOG_DEBUG, "Got ICMP Echo Reply #%d for %s\n",
					entry->nd_last_seqno, entry->nd_name);
		}
		stats_reply_rcv++;
		check_carrier(0, 0, entry);
		break;
	default:
		DEBUG(LOG_WARNING, "Receive unexpected packet on %s (unknow ICMP type)\n",
				entry->nd_name);
		break;
	}

	return;
}

void send_echorequest_event(__attribute__ ((unused))int sock,
		__attribute__ ((unused))short event, void *arg)
{
	struct node *entry = (struct node *)arg;

	update_seqno(entry);
	send_echorequest(entry);
	node_set_pingtimer(entry);
	node_set_carriertimer(entry);
}

static int send_echorequest(struct node *entry)
{
	struct iphdr *ip;
	struct icmphdr *icmp;
	int err = 0;

	memset(snd_packet, 0, sizeof(*snd_packet));

	/* Create IPv4 header */
	ip = (struct iphdr *)snd_packet;
	ip->version = IPVERSION;
	ip->ihl = 0x5; /* Size is 20 bytes */
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + DATALEN);
	ip->frag_off = 0; /* XXX: set Don't fragment flag ? */
	ip->ttl = IPDEFTTL;
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->saddr = entry->nd_ouraddr;
	ip->daddr = entry->nd_peeraddr;
	/* compute IP checksum here */
	ip->check = in_cksum((u_short *)ip, sizeof(struct iphdr));

	/* Create ICMP header */
	icmp = (struct icmphdr *)(ip + 1);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = htons(entry->nd_current_seqno);
	icmp->un.echo.id = ping_id;
	/* compute ICMP checksum here */
	icmp->checksum = in_cksum((u_short *)icmp, sizeof(struct icmphdr) + DATALEN);

	if ((err = NgSendData(entry->nd_dsock, PINGD_NG_SOCK_HOOK_NAME,
				snd_packet, ntohs(ip->tot_len))) < 0)
		DEBUG(LOG_ERR, "send data error for node %s (%d - %s)\n",
				entry->nd_name, err, strerror(err));
	else {
		stats_request_snd++;
		DEBUG(LOG_DEBUG, "ICMP Echo Request #%d for %s is sent\n",
				entry->nd_current_seqno, entry->nd_name);
	}

	return err;
}

static int send_echoreply(struct node *entry, uint32_t daddr, uint32_t saddr,
		uint16_t seqno, uint16_t id, uint16_t datalen, uint8_t *data)
{
	struct iphdr *ip;
	struct icmphdr *icmp;
	int err = 0;
	uint8_t *icmpdata;

	memset(snd_packet, 0, sizeof(*snd_packet));

	/* Create IPv4 header */
	ip = (struct iphdr *)snd_packet;
	ip->version = IPVERSION;
	ip->ihl = 0x5; /* Size is 20 bytes */
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + datalen);
	ip->frag_off = 0; /* XXX: set Don't fragment flag ? */
	ip->ttl = IPDEFTTL;
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->saddr = saddr;
	ip->daddr = daddr;
	/* compute IP checksum here */
	ip->check = in_cksum((u_short *)ip, sizeof(struct iphdr));

	/* Create ICMP header */
	icmp = (struct icmphdr *)(ip + 1);
	icmp->type = ICMP_ECHOREPLY;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = seqno;
	icmp->un.echo.id = id;

	/* Copy data */
	icmpdata = (uint8_t *)(icmp + 1);
	memcpy(icmpdata, data, datalen);

	/* compute ICMP checksum here */
	icmp->checksum = in_cksum((u_short *)icmp, sizeof(struct icmphdr) + datalen);

	if ((err = NgSendData(entry->nd_dsock, PINGD_NG_SOCK_HOOK_NAME,
				snd_packet, ntohs(ip->tot_len))) < 0)
		DEBUG(LOG_ERR, "send data error for node %s (%d - %s)\n",
				entry->nd_name, err, strerror(err));
	else
		stats_request_snd++;

	return err;
}
