/*
 * Copyright 2007-2013 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <event.h>

#include <syslog.h>
#include "esisd.h"


/*
 * OSI msg handling
 */
static  u_short clnp_id= 0x2904;

/*
 * OSI checksum computation
 */
int skip_cksum = 0;
static int
iso_gen_csum (u_int8_t *ptr, int ck_offset, int len, int compute)
{
	int    c0 = 0, c1 = 0;
	int    i = 0;
	u_int8_t *p = ptr;

	if (compute) {
		ptr[ck_offset] = 0;
		ptr[ck_offset+1] = 0;
	} else {
		/* cks set to 0: no check ! */
		if ((ptr[ck_offset] == 0) && (ptr[ck_offset+1] == 0))
			return 1;
	}
	if (skip_cksum)
		return 1;

	while (i < len) {
		c0 = (c0 + *p++);
		c1 += c0;
		i++;
		;
	}
	if (compute) {
		c1 = (((c0 * (len - 8)) - c1) % 255);
		ptr[ck_offset] = (u_char) ((c1 < 0) ? c1 + 255 : c1);
		c1 = (-(int) (c1 + c0)) % 255;
		ptr[ck_offset+1] = (u_char) (c1 < 0 ? c1 + 255 : c1);
		return 0;
	}
	return (((c0 % 255) == 0) && ((c1 % 255) ==0));
}

/*
 * Compute ES Hello msg for the an entry
 * this will include two source address, one for each SEL (0x00, 0x01)
 * btw an an_entry for announce has its  SEL = 0x00
 */
static u_int8_t snd_buf [2048];
void send_es_hello (struct iface *ifp)
{
	struct an_entry *an;
	struct eth_llc_hdr *eh;
	struct esis_fixed *h;
	u_int8_t *n_src;
	u_int8_t *ptr;
	struct osi_addr *os;

	if (LIST_FIRST(&(ifp->if_an_head)) == NULL)
		return;

	/*
	 * What is sent is
	 *  - Ethe Header (with NULL src addr);
	 *  - ES-IS payload in the data part
	 */
	eh = (struct eth_llc_hdr *)snd_buf;
	bcopy (eth_ESIS_ESH, eh->eh_dst, 6);
	memset (eh->eh_src, 0x00, 6);
	eh->eh_dsap = LCC_DSAP_OSI;
	eh->eh_ssap = LCC_SSAP_OSI;
	eh->eh_ctrl = LLC_OSI_CRTL;

	h = (struct esis_fixed *) (eh + 1);
	h->esis_proto_id = NLPI_ESIS;
	h->esis_vers = ESIS_VERSION;
	h->esis_res1 = 0;
	h->esis_type = ESIS_ESH;
	h->esis_ht_msb = ES_HOLD_TIME >> 8;
	h->esis_ht_lsb = ES_HOLD_TIME & 0xff;
	h->esis_cksum_msb = 0;
	h->esis_cksum_lsb = 0;

	ptr = (u_int8_t *)(h + 1);
	n_src = ptr++;
	*n_src = 0;
	log_msg (LOG_DEBUG, 0, "ES Hello on %s for : \n", ifp->if_name);
	LIST_FOREACH (an, &(ifp->if_an_head), an_link) {
		os = (struct osi_addr *)ptr;
		*ptr++ = an->an_osi.osi_len;
		bcopy (an->an_osi.osi_val, ptr, an->an_osi.osi_len);
		ptr += an->an_osi.osi_len - 1;
		*ptr++ = NSEL_NON_OSI;
		dump_osi (os, dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0, "  %s\n", dump_buf1);
		os = (struct osi_addr *)ptr;
		*ptr++ = an->an_osi.osi_len;
		bcopy (an->an_osi.osi_val, ptr, an->an_osi.osi_len);
		ptr += an->an_osi.osi_len - 1;
		*ptr++ = NSEL_OSI;
		dump_osi (os, dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0, "  %s\n", dump_buf1);
		(*n_src) += 2;
	}
	h->esis_hdr_len = ptr - (u_int8_t *)h;
	iso_gen_csum ((u_int8_t *)h, ESIS_CKSUM_OFF, h->esis_hdr_len, 1);
	/* Eth lenght starts at LLC header*/
	eh->eh_len = htons (ptr -  (u_int8_t *)&(eh->eh_dsap));

	{
		int len = 0;
		len += snprintf (&dump_buf1[len], SZ_DBUF - len,
		                   "  Hello Body is: \n");
		log_msg (LOG_DEBUG, 0, "%s", dump_buf1);
		dump_hex (LOG_DEBUG, snd_buf, ptr,
		          dump_buf1, SZ_DBUF, NULL);
	}

#ifndef _SKIP_VNB
	if (NgSendData (ifp->if_dsock, NG_SOCK_HOOK_NAME,
	          snd_buf, (ptr-snd_buf)) < 0) {
		log_msg (LOG_WARNING, 0, "send data error for iface %s\n",
		          ifp->if_name);
	}
#endif /* _SKIP_VNB */

	return;
}

/*
 * Recv ERQ or ERP message
 */
static void
echo_input (struct iface *ifp, u_int8_t *rdbuf, int len)
{
	struct eth_llc_hdr *eh;
	struct clnp_fixed *h;
	struct clnp_segment *sg;
	u_int8_t *ptr, *addr_dst;
	u_int8_t *ptr_lim = rdbuf + len;
	struct osi_addr *osi;

	/* LLC checks already done */
	eh = (struct eth_llc_hdr *)rdbuf;

	/* ES-IS  check */
	h = (struct clnp_fixed *) (eh + 1);
	if ((h->cnf_proto_id != NLPI_CLNP)    ||
	    (h->cnf_vers != CLNP_VERSION)) {
		log_msg (LOG_WARNING, 0, "CLNP check failed\n");
		return;
	}

	/* cksum */
	if (!iso_gen_csum ((u_int8_t *)h, CLNP_CKSUM_OFF, h->cnf_hdr_len, 0)) {
		log_msg (LOG_WARNING, 0, "CKSUM failed\n");
		return;
	}

	/*
	 * look after address part, and keep addr_dst for later adr swap
	 * note also that osi point to the second address ...
	 */
	ptr = (u_int8_t *)(h + 1);
	addr_dst = ptr;
	osi = (struct osi_addr *)ptr;
	if ((ptr + osi->osi_len) < ptr_lim) {
		ptr += osi->osi_len + 1;
		osi = (struct osi_addr *)ptr;
		if ((ptr + osi->osi_len) < ptr_lim) {
			ptr += osi->osi_len + 1;
		}
	}
	if (((u_int8_t *)osi == addr_dst) || (ptr == addr_dst)) {
		log_msg (LOG_WARNING, 0, "Size error in CLNP packet\n");
		return;
	}
	sg = (struct clnp_segment *)ptr;
	if ((h->cnf_type & CNF_MORE_SEGS) || sg->cng_off) {
		log_msg (LOG_WARNING, 0, "CLNP Fragmentation not supported\n");
		return;
	}

	if (! osi_get_an (ifp, (struct osi_addr *)addr_dst)) {
		dump_osi ((struct osi_addr *)addr_dst, dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_WARNING, 0, "CLNP unknown addr %s \n", dump_buf1);
		return;
	}

	switch (h->cnf_type & CNF_TYPE) {
	case CLNP_ERQ: {
		struct osi_addr tmp_osi;
		struct mac_addr *mac;
		int l, hlen;

		/*
		 * Copy the full SNDU after the header
		 * We expect here that buffer is large enough
		 * overlap is managed by bcopy ..
		 */
		hlen  = ((u_int8_t *)osi - (u_int8_t *)h) + osi->osi_len + 1 +
		        sizeof (struct clnp_segment);
		bcopy ((u_int8_t *)h, (u_int8_t *)h + hlen, len - sizeof (*eh));
		/* ... and dupdate length */
		/* In eth header */
		eh->eh_len = htons (htons(eh->eh_len) + hlen);
		l = hlen + (h->cnf_seglen_msb << 8) + h->cnf_seglen_lsb;
		/* In CLNP header PDU length, and total length */
		h->cnf_hdr_len = hlen & 0xff;
		h->cnf_seglen_msb = (l >> 8);
		h->cnf_seglen_lsb =  l & 0xff;
		sg->cng_tot_len = htons (l);
		len += hlen;

		/* swap CLNP addresses */
		bcopy (addr_dst, &tmp_osi, (*addr_dst) + 1);
		l = osi->osi_len + 1;
		bcopy (osi, addr_dst, osi->osi_len + 1);
		bcopy (&tmp_osi, &addr_dst[l], tmp_osi.osi_len + 1);

		/* Update TTL, type, and ID */
		h->cnf_ttl = 64;
		h->cnf_type = (h->cnf_type & (~CNF_TYPE)) | CLNP_ERP;
		sg->cng_id = htons (clnp_id++);

		/* cksum */
		iso_gen_csum ((u_int8_t *)h, CLNP_CKSUM_OFF, h->cnf_hdr_len, 1);

		mac = osi_get_l2 (ifp, (struct osi_addr *)addr_dst);
		if (mac) {
			int l = 0;
			bcopy (mac->mac_val, eh->eh_dst, 6);
			memset (eh->eh_src, 0x00, 6);
			l += snprintf (&dump_buf1[l], SZ_DBUF - l,
			               "  CLNP ERP sent  on %s: \n",
			               ifp->if_name);
			log_msg (LOG_DEBUG, 0, "%s", dump_buf1);
			dump_hex (LOG_DEBUG, rdbuf, &rdbuf[len], dump_buf1, SZ_DBUF, NULL);
#ifndef _SKIP_VNB
			if (NgSendData (ifp->if_dsock, NG_SOCK_HOOK_NAME, rdbuf, len) < 0) {
				log_msg (LOG_WARNING, 0, "send data error for iface %s\n",
				         ifp->if_name);
			}
#endif /* _SKIP_VNB */
		}
		break;
	}
	case CLNP_ERP: {
		struct ping_entry *pe = ifp->if_pe;
		int i;
		if (!pe) {
			log_msg (LOG_WARNING, 0,
			         "Unexpected OSI Echo Reply received on %s\n",
			         ifp->if_name);
			break;
		}
		for (i=0; i<pe->pe_sent; i++) {
			if (memcmp (&rdbuf[sizeof (struct eth_llc_hdr) + h->cnf_hdr_len],
			       &pe->pe_packet[i][sizeof (struct eth_llc_hdr)],
			       len - h->cnf_hdr_len - sizeof (struct eth_llc_hdr)) == 0) {
				if (pe->pe_received[i]) {
					log_msg (LOG_WARNING, 0,
					         "OSI echo Reply received twice on %s\n",
					         ifp->if_name);
				}
				pe->pe_received[i] = 1;
				if (console_acces >= 0)
					display_console (console_acces,
				                     "  OSI Echo Reply #%d received\n", i);
				return;
			}
		}
		log_msg (LOG_WARNING, 0,
		         "Non matching OSI echo Relpy received on %s\n",
		         ifp->if_name);
		break;
	}
	default:
		log_msg (LOG_WARNING, 0, "Unsupported CLNP type %02x (%02x)\n",
		         h->cnf_type & CNF_TYPE, h->cnf_type);
		break;
	}
	return;
}

/*
 * Recv data messages form the VNB node ie.e ES/IS/REdirect ...
 */
static void
esis_input (struct iface *ifp, u_int8_t *rdbuf, int len)
{
	struct eth_llc_hdr *eh;
	struct esis_fixed *h;
	u_int16_t hold;
	u_int8_t *ptr;
	u_int8_t *ptr_lim = rdbuf + len;
	struct mac_addr mac;
	int lg = 0;
	lg += snprintf (&dump_buf1[lg], SZ_DBUF - lg,
	                "  Received OSI packet on %s: \n",
	                ifp->if_name);
	log_msg (LOG_DEBUG, 0, "%s", dump_buf1);
	dump_hex (LOG_DEBUG, rdbuf, &rdbuf[len], dump_buf1, SZ_DBUF, NULL);

	/*
	 * do the message parsing and call ad-hoc receive methods
	 * if need be a receive methdo can be called several times
	 * (one for each entry)
	 * available methods are:
	 *   - receive_es_hello
	 *   - receive_is_hello
	 *   - receive_redirect
	 * For any of those message, we'll ignore the options
	 */

	/* LLC checks  */
	eh = (struct eth_llc_hdr *)rdbuf;
	if ((eh->eh_dsap != LCC_DSAP_OSI)   ||
	     (eh->eh_ssap != LCC_SSAP_OSI)  ||
	     (eh->eh_ctrl != LLC_OSI_CRTL))  {
		log_msg (LOG_WARNING, 0, "LLC check failed\n");
		return;
	}
	mac.mac_len = 6;
	bcopy (eh->eh_src, mac.mac_val, 6);

	/* get the echo reply/request */
	if (*(u_int8_t *)(eh + 1) == NLPI_CLNP) {
		echo_input (ifp, rdbuf, len);
		return;
	}
	else if (*(u_int8_t *)(eh + 1) != NLPI_ESIS) {
		log_msg (LOG_WARNING, 0, "no CLNP nor ES-IS packet\n");
		return;
	}

	/* ES-IS  check */
	h = (struct esis_fixed *) (eh + 1);
	if ((h->esis_proto_id != NLPI_ESIS)    ||
	    (h->esis_vers != ESIS_VERSION)) {
		log_msg (LOG_WARNING, 0, "ES-IS check failed\n");
		return;
	}

	/* cksum */
	if (!iso_gen_csum ((u_int8_t *)h, ESIS_CKSUM_OFF, h->esis_hdr_len, 0)) {
		log_msg (LOG_WARNING, 0, "CKSUM failed\n");
		return;
	}
	hold = (h->esis_ht_msb << 8) | 	h->esis_ht_lsb;
	ptr = (u_int8_t *)(h+1);
	/* Do the real parsing */
	switch (h->esis_type) {
	case ESIS_ESH: {
		int nb = *ptr++;
		while (nb) {
			struct osi_addr *osi = (struct osi_addr *)ptr;
			if ((ptr + osi->osi_len) < ptr_lim) {
				receive_es_hello (ifp, osi, &mac, hold);
				nb--;
				ptr += osi->osi_len + 1;
			} else {
				log_msg (LOG_WARNING, 0, "Size error in ES Hello packet\n");
				break;
			}
		}
		break;
	}
	case ESIS_ISH: {
		struct osi_addr *osi = (struct osi_addr *)ptr;
		if ((ptr + osi->osi_len) < ptr_lim) {
			receive_is_hello (ifp, osi, &mac, hold);
		} else {
			log_msg (LOG_WARNING, 0, "Size error in IS Hello packet\n");
		}
		break;
	}
	case ESIS_RD: {
		struct osi_addr *osi_tgt = (struct osi_addr *)ptr;

		if ((ptr + osi_tgt->osi_len) < ptr_lim) {
			struct mac_addr *m = (struct mac_addr *)ptr;
			ptr = (u_int8_t *) (osi_tgt + 1);
			m = (struct mac_addr *)ptr;

			if ((ptr + m->mac_len) < ptr_lim) {
				struct osi_addr *osi_gw;
				ptr = (u_int8_t *) (m + 1);
				osi_gw = (struct osi_addr *)ptr;

				if ((ptr + osi_gw->osi_len) < ptr_lim) {
					receive_redirect (ifp, osi_tgt, m, osi_gw, hold);
					break;
				}
			}
		}
		log_msg (LOG_WARNING, 0, "Size error in RD packet\n");
		break;
	}
	case ESIS_RA:
		log_msg (LOG_DEBUG, 0, "Ignoring RA packet\n");
		break;
	case ESIS_AA:
		log_msg (LOG_DEBUG, 0, "Ignoring AA packet\n");
		break;
	default:
		log_msg (LOG_WARNING, 0, "Unknown ES-IS packet type %02x\n",
		         h->esis_type);
		break;
	}
	return;
}

static u_int8_t buf_ds_read[2048];
void read_dsock_cb (int fd, short event, void *param)
{
	struct iface *ifp = (struct iface *)param;
    int len;

    len = NgRecvData(fd, buf_ds_read, sizeof(buf_ds_read), NULL);
	log_msg (LOG_DEBUG, 0, "Received packet (%d bytes) on %s\n",
	         len, ifp->if_name);
	esis_input ((struct iface *)param, buf_ds_read, len);
}

static void
send_ping (int fd, short event, void *param)
{
	struct ping_entry *pe = (struct  ping_entry *)param;
	struct iface *ifp = pe->pe_ifp;
	struct timeval tm;
	int i, recv;

	if (pe->pe_sent < pe->pe_tosend) {
		int len = 0;
		len += snprintf (&dump_buf1[len], SZ_DBUF - len,
		               "  Ping (%d) sent on %s: \n",
		               pe->pe_sent, ifp->if_name);
		log_msg (LOG_DEBUG, 0, "%s", dump_buf1);
		dump_hex (LOG_DEBUG,
		          &(pe->pe_packet[pe->pe_sent][0]),
		          &(pe->pe_packet[pe->pe_sent][pe->pe_len]),
		          dump_buf1, SZ_DBUF, NULL);
#ifndef _SKIP_VNB
		if (NgSendData (ifp->if_dsock, NG_SOCK_HOOK_NAME,
		          &(pe->pe_packet[pe->pe_sent][0]), pe->pe_len) < 0) {
			log_msg (LOG_WARNING, 0, "send data error for iface %s\n",
			          ifp->if_name);
		}
#endif /* _SKIP_VNB */

		tm.tv_sec  = PING_INTERVAL_SEC;
		tm.tv_usec = PING_INTERVAL_USEC;
		evtimer_add (&(pe->pe_evt), &tm);
		pe->pe_sent++;
		return;
	}

	/* Time for the statistics */
	for (i=0, recv=0; i<MAX_PING; i++ )
		recv += pe->pe_received[i] ?  1 : 0;
	display_console	(pe->pe_fd, "  Received %d out of %d responses: %d%%\n",
	                  recv, pe->pe_tosend, (100*recv)/pe->pe_tosend);
	ping_fd = 0;
	display_prompt (pe->pe_fd);

	ifp->if_pe = NULL;
	free (pe);
	return;
}

void
pinger (int fd, struct iface *ifp, struct osi_addr *dst)
{
	u_int8_t pkt[OSI_PING_SIZE];
	struct ping_entry *pe = ifp->if_pe;
	struct an_entry *an;
	struct eth_llc_hdr *eh;
	struct clnp_fixed *h;
	struct clnp_segment *sg;
	u_int8_t *ptr;
	u_int8_t clnp_hlen;
	struct mac_addr *mac;
	int i;

	/* Only ONE ping session at a time per interface */
	if (pe) {
		dump_osi (&pe->pe_dst, dump_buf1, SZ_DBUF, NULL);
		display_console (fd, " On going ping to %s\n", dump_buf1);
		return;
	}
	pe = malloc (sizeof(*pe));
	if (!pe) {
		display_console (fd, " OSI ping error, unable to allocate memory\n");
		return;
	}
	ifp->if_pe = pe;
	bzero (pe, sizeof(*pe));
	pe->pe_ifp = ifp;
	pe->pe_fd = fd;

	/*
	 * While ping is running, block prompt ion the console
	 * In case of multi-console acces this will need to be a
	 * console-specific (i.e. console-context) info.
	 */
	ping_fd = fd;

	pe->pe_dst = *dst;
	/*
	 * To contruct this ping we need
	 *  - src addr
	 *  - a resolv entry
	 */
	an = LIST_FIRST (&(ifp->if_an_head));
	if (!an) {
		display_console (fd, " No OSI addr available on %s\n", ifp->if_name);
		goto ping_fail;
	} else {
		/* Force OSI SEL for source */
		pe->pe_src = an->an_osi;
		pe->pe_src.osi_val [pe->pe_src.osi_len - 1] = NSEL_OSI;
		dump_osi (&pe->pe_src, dump_buf1, SZ_DBUF, NULL);
		display_console (fd, "  Using OSI addr %s\n", dump_buf1);
	}
	mac = osi_get_l2 (ifp, dst);
	if (!mac) {
		dump_osi (dst, dump_buf1, SZ_DBUF, NULL);
		display_console (fd, " Address resolution on %s failed for\n %s\n;",
		                 ifp->if_name, dump_buf1);
		goto ping_fail;
	}
	clnp_hlen = sizeof (struct clnp_fixed) +  sizeof (struct clnp_segment) +
	            2 + pe->pe_src.osi_len + pe->pe_dst.osi_len;

	bzero (pkt, OSI_PING_SIZE);
	/* Prepare generic packets */
	eh = (struct eth_llc_hdr *)pkt;
	bcopy (mac->mac_val, eh->eh_dst, 6);
	eh->eh_dsap = LCC_DSAP_OSI;
	eh->eh_ssap = LCC_SSAP_OSI;
	eh->eh_ctrl = LLC_OSI_CRTL;
	eh->eh_len = htons (LLC_SIZE + clnp_hlen + OSI_PING_DATA);

	h = (struct clnp_fixed *)(eh +1);
	h->cnf_proto_id = NLPI_CLNP;
	h->cnf_vers = CLNP_VERSION;
	h->cnf_ttl = 0x40;
	h->cnf_type = CNF_SEG_OK | CLNP_ERQ;
	h->cnf_hdr_len = clnp_hlen;
	h->cnf_seglen_msb = (clnp_hlen + OSI_PING_DATA) >> 8;
	h->cnf_seglen_lsb = (clnp_hlen + OSI_PING_DATA) & 0xff;

	ptr = (u_int8_t *)(h + 1);
	bcopy (&pe->pe_dst, ptr, pe->pe_dst.osi_len + 1);
	ptr +=  pe->pe_dst.osi_len + 1;
	bcopy (&pe->pe_src, ptr, pe->pe_src.osi_len + 1);
	ptr +=  pe->pe_src.osi_len + 1;

	sg = (struct clnp_segment *)ptr;
	sg->cng_tot_len = htons (clnp_hlen + OSI_PING_DATA);

	ptr = (u_int8_t *) (sg + 1);
	memset (ptr, 0x55, OSI_PING_DATA);

	/*
	 * copy packets
	 */
	pe->pe_len = sizeof (struct eth_llc_hdr) + clnp_hlen + OSI_PING_DATA;
	for (i=0; i<MAX_PING ; i++) {
		sg->cng_id = htons (clnp_id++);
		iso_gen_csum ((u_int8_t *)h, CLNP_CKSUM_OFF, h->cnf_hdr_len, 1);
		bcopy (pkt, &(pe->pe_packet[i][0]), pe->pe_len);
	}

	pe->pe_tosend = MAX_PING;
	evtimer_set (&(pe->pe_evt), send_ping, pe);
	send_ping (0, 0, (void *)pe);
	return;

ping_fail:
	ifp->if_pe = NULL;
	free (pe);
	ping_fd = 0;
	return;
}



#ifdef __HARD_CODED_TEST_
u_int8_t  test_es [] = {
0x09,0x00,0x2b,0x00,0x00,0x05,0x08,0x00,
0x06,0x0c,0x12,0x01,0x00,0x37,0xfe,0xfe,
0x03,0x82,0x34,0x01,0x00,0x02,0x00,0x2d,
0x00,0x00,0x02,0x14,0x49,0x53,0x49,0x45,
0x4d,0x45,0x4e,0x53,0x41,0x47,0x00,0x00,
0x01,0x08,0x00,0x06,0x0c,0x12,0x01,0x00,
0x14,0x49,0x53,0x49,0x45,0x4d,0x45,0x4e,
0x53,0x41,0x47,0x00,0x00,0x01,0x08,0x00,
0x06,0x0c,0x12,0x01,0x01};
void
do_test_es (struct iface *ifp)
{
	esis_input (ifp, test_es, sizeof(test_es));
	return;
}

u_int8_t  test_is [] = {
0x09,0x00,0x2b,0x00,0x00,0x04,0x00,0xd0,
0x93,0x03,0x31,0x7a,0x00,0x25,0xfe,0xfe,
0x03,0x82,0x22,0x01,0x00,0x04,0x00,0x1f,
0x00,0x00,0x14,0x49,0x53,0x49,0x45,0x4d,
0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
0x08,0x00,0x06,0x0c,0x01,0x01,0x00,0xc6,
0x02,0x00,0x32,0x4d,0x45,0x4e,0x53,0x41,
0x47,0x00,0x00,0x01};
void
do_test_is (struct iface *ifp)
{
	esis_input (ifp, test_is, sizeof(test_es));
	return;
}

u_int8_t  test_rd [] = {
0x09,0x00,0x2b,0x00,0x00,0x05,0x08,0x00,
0x06,0x0c,0x12,0x01,0x00,0x3e,0xfe,0xfe,
0x03,0x82,0x3b,0x01,0x00,0x06,0x00,0x2d,
0x00,0x00,0x14,0x49,0xff,0xfd,0xfe,0x4d,
0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
0x08,0x00,0x06,0x0c,0x12,0x01,0x00,0x06,
0x02,0x03,0x04,0x05,0x06,0x07,0x14,0x49,
0xaa,0xbb,0xcc,0x4d,0x45,0x4e,0x53,0x41,
0x47,0x00,0x00,0x01,0x08,0x00,0x06,0x0c,
0x12,0x01,0x01};
void
do_test_rd (struct iface *ifp)
{
	esis_input (ifp, test_rd, sizeof(test_rd));
	return;
}

u_int8_t  test_ping [] = {
0x00,0x0f,0xb0,0x47,0x55,0x5b,0x00,0xd0,
0x93,0x03,0x31,0x7a,0x00,0x62,0xfe,0xfe,
0x03,0x81,0x3f,0x01,0x30,0xbe,0x00,0x5f,
0x00,0x00,0x14,0x49,0x53,0x49,0x45,0x4d,
0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
0x00,0x0f,0xb0,0x47,0x55,0x5b,0x01,0x14,
0x49,0x53,0x49,0x45,0x4d,0x45,0x4e,0x53,
0x41,0x47,0x00,0x00,0x01,0x00,0x0b,0x5d,
0xd2,0xf2,0xf1,0x55,0x0e,0xb5,0x00,0x00,
0x00,0x5f,0xcd,0x01,0x00,0xc3,0x01,0xc0,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
u_int8_t  b_test_ping [sizeof(test_ping) + 128];
void
do_test_ping (struct iface *ifp)
{
	bcopy (test_ping, b_test_ping, sizeof(test_ping));
	esis_input (ifp, b_test_ping, sizeof(test_ping));
	return;
}

u_int8_t  test_pong[] = {
0x00,0xd0,0x93,0x03,0x31,0x7a,0x00,0x0f,
0xb0,0x47,0x55,0x5b,0x00,0x9e,0xfe,0xfe,
0x03,0x81,0x3c,0x01,0x32,0xbf,0x00,0x9b,
0x00,0x00,0x14,0x49,0x53,0x49,0x45,0x4d,
0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
0x00,0x0b,0x5d,0xd2,0xf2,0xf1,0x55,0x14,
0x49,0x53,0x49,0x45,0x4d,0x45,0x4e,0x53,
0x41,0x47,0x00,0x00,0x01,0x00,0x0f,0xb0,
0x47,0x55,0x5b,0x01,0x00,0x11,0x00,0x00,
0x00,0x9b,0xcd,0x01,0x00,0x81,0x3f,0x01,
0x30,0xbe,0x00,0x5f,0x00,0x00,0x14,0x49,
0x53,0x49,0x45,0x4d,0x45,0x4e,0x53,0x41,
0x47,0x00,0x00,0x01,0x00,0x0f,0xb0,0x47,
0x55,0x5b,0x01,0x14,0x49,0x53,0x49,0x45,
0x4d,0x45,0x4e,0x53,0x41,0x47,0x00,0x00,
0x01,0x00,0x0b,0x5d,0xd2,0xf2,0xf1,0x55,
0x0e,0xb3,0x00,0x00,0x00,0x5f,0xcd,0x01,
0x00,0xc3,0x01,0xc0,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55};

u_int8_t test_mypong[] = {
0x00,0xd0,0x93,0x03,0x31,0x7a,0x00,0x0f,
0xb0,0x47,0x55,0x5b,
0x00,0x9e,
0xfe,0xfe,0x03,
0x81,
//0x3c,
0x39,
0x01,0x32,0xbf,
//0x00,0x9b,
0x00,0x95,
0x00,0x00,
0x14,0x49,0x53,0x49,0x45,0x4d,0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
      0x00,0x0f,0xb0,0x47,0x55,0x5b,0x01,
0x14,0x49,0x53,0x49,0x45,0x4d,0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
      0x00,0x0b,0x5d,0xd2,0xf2,0xf1,0x55,
0x00,0x11,
0x00,0x00,
//0x00,0x9b,
0x00,0x95,
0x81,0x39,0x01,0x40,0x9e,0x00,0x59,
0xb4,0x75,0x14,0x49,0x53,0x49,0x45,0x4d,
0x45,0x4e,0x53,0x41,0x47,0x00,0x00,0x01,
0x00,0x0b,0x5d,0xd2,0xf2,0xf1,0x55,0x14,
0x49,0x53,0x49,0x45,0x4d,0x45,0x4e,0x53,
0x41,0x47,0x00,0x00,0x01,0x00,0x0b,0x5d,
0xd2,0xf2,0xf1,0x55,0x29,0x05,0x00,0x00,
0x00,0x59,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
0x55,0x55};

void
do_test_pong (struct iface *ifp)
{
	esis_input (ifp, test_pong, sizeof(test_pong));
	esis_input (ifp, test_mypong, sizeof(test_mypong));
	return;
}


#endif



