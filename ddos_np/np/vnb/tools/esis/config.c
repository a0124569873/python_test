/*
 * Copyright 2007-2013 6WIND S.A.
 *
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Alain Ritoux, 6WIND
 *		This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the author, of 6WIND nor the names of any
 *    co-contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY 6WIND AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL 6WIND OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <assert.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <string.h>
#include <linux/if_ether.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <event.h>
#include <netgraph.h>
#include <netgraph/ng_osi.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_osi_eth.h>

#include <syslog.h>
#include "esisd.h"


/* List of all managed interfaces */
struct ifhead ifnet;

int debug = 0;

void
dump_hex (int level,
          u_int8_t *start, u_int8_t *end, u_int8_t *db, int ds, int *l)
{
	u_int8_t *p = start;
	int len = 0;
	int i = 0;
	len = snprintf (&db[len], ds-len, "    ");
	while (p < end) {
		len += snprintf (&db[len], ds - len, "%02x", *p++);
		if (p == end) {
			len += snprintf (&db[len], ds -len, "\n");
			if (level) {
				log_msg (level, 0, db);
				len = 0;
			}
		}
		else if ((i & 0xf) == 0x0f)
			if (level) {
				len += snprintf (&db[len], ds -len, "\n");
				log_msg (level, 0, db);
				len = 0;
				len += snprintf (db, ds, "    ");
			}
			else
				len += snprintf (&db[len], ds -len, "\n    ");
		else
			len += snprintf (&db[len], ds - len, ":");
		i++;
	}
	if (l)
		*l = len;
	return;
}

int
parse_mac (u_int8_t *macname, struct mac_addr *mac)
{
	u_int8_t len = 0;
	u_int8_t *plim = macname + strlen (macname);
	u_int8_t *ptr;

	memset(mac, 0, sizeof(*mac));
	for (ptr = macname ; ptr < plim; ) {
		char *nptr;
		long int val = strtol ((const char *)ptr, &nptr, 16);
		ptr+=3;
		mac->mac_val[len++] = (u_int8_t) (val & 0x0ff);
	}
	mac->mac_len = len;
	return 0;
}

void
dump_mac (struct mac_addr *mac, u_int8_t *buf, int ds, int *l)
{
	int i=0;
	int len=0;

	for (i=0; i<(mac->mac_len -1); i++)
		len += snprintf (&buf[len], ds - len, "%02x:", mac->mac_val[i]);
	len += snprintf (&buf[len], ds - len, "%02x", mac->mac_val[i]);
	if (l)
		*l = len;
	return;
}

/* States*/
#define VIRGIN	0
#define GOTONE	1
#define GOTTWO	2
/* Inputs */
#define	DIGIT	(4*0)
#define	END	(4*1)
#define DELIM	(4*2)

int
parse_osi (u_int8_t *osiname, struct osi_addr *osi)
{
	u_int8_t *addr = osiname;
	u_int8_t *cp = osi->osi_val;
	u_int8_t* cplim = cp + 20;
	int byte = 0, state = VIRGIN, new;

	bzero(osi, sizeof(*osi));
	do {
		if ((*addr >= '0') && (*addr <= '9')) {
			new = *addr - '0';
		} else if ((*addr >= 'a') && (*addr <= 'f')) {
			new = *addr - 'a' + 10;
		} else if ((*addr >= 'A') && (*addr <= 'F')) {
			new = *addr - 'A' + 10;
		} else if (*addr == 0)
			state |= END;
		else
			state |= DELIM;
		addr++;
		switch (state /* | INPUT */) {
		case GOTTWO | DIGIT:
			*cp++ = byte; /*FALLTHROUGH*/
		case VIRGIN | DIGIT:
			state = GOTONE; byte = new; continue;
		case GOTONE | DIGIT:
			state = GOTTWO; byte = new + (byte << 4); continue;
		default: /* | DELIM */
			state = VIRGIN; *cp++ = byte; byte = 0; continue;
		case GOTONE | END:
		case GOTTWO | END:
			*cp++ = byte; /* FALLTHROUGH */
		case VIRGIN | END:
			break;
		}
		break;
	} while (cp < cplim);
	osi->osi_len = cp - osi->osi_val;
	return 0;
}

void
dump_osi (struct osi_addr *osi, u_int8_t *buf, int ds, int *l) {
	int i=0;
	int len=0;

	if (osi->osi_len == 0) {
		len += snprintf (&buf[len], ds - len, "none");
	} else if (osi->osi_len == 20) {
		for (i=0; i<3; i++)
			len += snprintf (&buf[len], ds - len, "%02x", osi->osi_val[i]);
		len += snprintf (&buf[len], ds - len, "%02x.", osi->osi_val[i++]);
		for (; i<14; i++)
			len += snprintf (&buf[len], ds - len, "%02x", osi->osi_val[i]);
		len += snprintf (&buf[len], ds - len, "%02x.", osi->osi_val[i++]);
		len += snprintf (&buf[len], ds - len, "%02x", osi->osi_val[i++]);
		len += snprintf (&buf[len], ds - len, "%02x.", osi->osi_val[i++]);
		len += snprintf (&buf[len], ds - len, "%02x", osi->osi_val[i++]);
		len += snprintf (&buf[len], ds - len, "%02x", osi->osi_val[i++]);
		len += snprintf (&buf[len], ds - len, "[%02x]", osi->osi_val[i]);
	}
	else {
		len += snprintf (&buf[len], ds - len, "(%d)", osi->osi_len);
		for (i=0; i<(osi->osi_len -1); i++)
			len += snprintf (&buf[len], ds - len, "%02x.", osi->osi_val[i]);
		len += snprintf (&buf[len], ds - len, "%02x", osi->osi_val[i]);
	}
	if (l)
		*l = len;
	return;
}

u_int8_t eth_ESIS_ESH [6] ={ 0x09, 0x00, 0x2b, 0x00, 0x00, 0x05 };
static u_int8_t eth_ESIS_ISH [6] ={ 0x09, 0x00, 0x2b, 0x00, 0x00, 0x04 };
static int
mcast_register (u_int8_t *name, int cmd)
{
	struct ifreq ifr;
	int s;

	memset(&ifr, 0, sizeof(ifr));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		log_msg (LOG_WARNING, 0, "sys error on Interface %s\n", name);
		return EINVAL;
	}

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	bcopy (eth_ESIS_ESH, ifr.ifr_hwaddr.sa_data, 6);
	if (ioctl(s, cmd, (char*)&ifr) != 0) {
		log_msg (LOG_WARNING, 0, "mcast error on Interface %s\n", name);
		return EINVAL;
	}
	bcopy (eth_ESIS_ISH, ifr.ifr_hwaddr.sa_data, 6);
	if (ioctl(s, cmd, (char*)&ifr) != 0) {
		log_msg (LOG_WARNING, 0, "mcast error on Interface %s\n", name);
		return EINVAL;
	}
	close(s);
	return 0;
}

/*
 * Creates a new I/F, and process allocation stuff.
 * Link it to the lower level, with starting ES-IS
 */
struct iface *
new_iface (char *name, char *ng_name, int *err)
{
	struct iface  *ifp = NULL;
	struct timeval tm;
	union {
		u_int8_t buf[512];
		struct ng_mesg resp;
	} u;

	int size, nports;
	int i, len;
	struct ngm_connect ngc;
	int csock = 0;
	int dsock = 0;
	char raddr[NG_PATHLEN + 1];
	char path[NG_PATHLEN + 1];

	*err = 0;
	memset(&u, 0, sizeof(u));
	/*
	 * Create sockets and connect to netgraph node
	 */
#ifndef _SKIP_VNB
	if (NgMkSockNode(NULL, &csock, &dsock) < 0) {
		*err = ENOTSOCK;
		goto bad_iface;
	}
	snprintf(ngc.path, sizeof(ngc.path), "%s:", ng_name);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), NG_SOCK_HOOK_NAME);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), NG_OSI_ETH_HOOK_DAEMON);
	if (NgSendMsg(csock, ".", NGM_GENERIC_COOKIE,
	     NGM_CONNECT, &ngc, sizeof(ngc)) < 0) {
		*err = ENOTCONN;
		goto bad_iface;
	}
#endif /* _SKIP_VNB */

	if (mcast_register (name, SIOCADDMULTI)) {
		*err = EINVAL;
		goto bad_iface;
	}

	size = sizeof(*ifp);
	ifp = malloc (size);
	if (ifp == NULL) {
		*err = ENOMEM;
		goto bad_iface;
	}
	memset (ifp, 0, size);
	ifp->if_csock = csock;
	ifp->if_dsock = dsock;

	ifp->if_name = malloc (strlen(name)+1);
	if (ifp->if_name == NULL) {
		*err = ENOMEM;
		goto bad_iface;
	}
	strcpy (ifp->if_name, name);

	ifp->if_ngname = malloc (strlen(ng_name)+1);
	if (ifp->if_ngname == NULL) {
		*err = ENOMEM;
		goto bad_iface;
	}
	strcpy (ifp->if_ngname, ng_name);

	LIST_INIT (&ifp->if_an_head);
	LIST_INIT (&ifp->if_es_head);
	LIST_INIT (&ifp->if_is_head);
	LIST_INIT (&ifp->if_rd_head);

	/* socket read (one per interface) */
#ifndef _SKIP_VNB
	event_set(&ifp->if_cs_ev, ifp->if_csock, EV_READ | EV_PERSIST,
	          read_csock_cb, ifp);
	event_add (&ifp->if_cs_ev, NULL);
	event_set(&ifp->if_ds_ev, ifp->if_dsock, EV_READ | EV_PERSIST,
	          read_dsock_cb, ifp);
	event_add (&ifp->if_ds_ev, NULL);
#endif /* _SKIP_VNB */

	/* Announce timer */
	tm.tv_sec  = ES_HELLO_INTERVAL;
	tm.tv_usec = 0;
	evtimer_set (&ifp->if_es_announce, es_announce_cb, ifp);
	evtimer_add (&ifp->if_es_announce, &tm);

	LIST_INSERT_HEAD (&ifnet, ifp, if_link);

	return (ifp);

bad_iface:
	if (csock)
		close (csock);
	if (dsock)
		close (dsock);
	if (ifp) {
		if (ifp->if_name)
			free (ifp->if_name);
		if (ifp->if_ngname)
			free (ifp->if_ngname);
		free (ifp);
	}
	return (NULL);
}

/*
 * Retrieves interface by name
 */
struct iface *
get_ifp (char *ifname)
{
    struct iface *ifp = 0;
    LIST_FOREACH (ifp, &ifnet, if_link) {
        if (strcmp (ifp->if_name, ifname) == 0)
            break;
    }
    return (ifp);
}

/*
 * Set iface MAC addr
 */
int
set_if_mac (u_int8_t *ifname, u_int8_t *macname)
{
	struct iface *ifp = get_ifp (ifname);
	if (!ifp)
		return EINVAL;

	return (parse_mac (macname, &ifp->if_mac));
}

/*
 * Add an ES announce to an interface i.e. an osi address
 */
int
add_es_announce (u_int8_t *ifname, u_int8_t *osiname)
{
	struct iface *ifp = get_ifp (ifname);
	struct osi_addr add;
	struct an_entry *an;
	int err;

	if (!ifp)
		return EINVAL;
	err = parse_osi (osiname, &add);
	if (err)
		return err;
	LIST_FOREACH (an, &(ifp->if_an_head), an_link) {
        if (bcmp (&(an->an_osi), &add, sizeof(add)) == 0)
            break;
    }
	if (an) {
		an->an_refcount++;
		return 0;
	}
	an = malloc (sizeof *an);
	if (!an)
		return ENOMEM;
	bcopy (&add, &(an->an_osi), sizeof (add));
	an->an_refcount=1;
	LIST_INSERT_HEAD (&(ifp->if_an_head), an, an_link);
	/* Triggers an immediate announce */
	evtimer_del (&ifp->if_es_announce);
	es_announce_cb (0, 0, ifp);
	return 0;
}

/*
 * Removes an ES announce to an interface i.e. an osi address
 */
int
remove_es_announce (u_int8_t *ifname, u_int8_t *osiname)
{
	struct iface *ifp = get_ifp (ifname);
	struct osi_addr add;
	struct an_entry *an;
	int err;

	if (!ifp)
		return EINVAL;
	err = parse_osi (osiname, &add);
	LIST_FOREACH (an, &(ifp->if_an_head), an_link) {
        if (bcmp (&(an->an_osi), &add, sizeof(add)) == 0)
            break;
    }
	if (!an)
		return EINVAL;
	if (--an->an_refcount)
		return 0;
	LIST_REMOVE (an, an_link);
	free (an);
	return 0;
}

/*
 * Interface Removal
 */
int
iface_delete (int fd, char *ifname)
{
	struct iface *ifp = get_ifp (ifname);
	struct es_entry *es;
	struct is_entry *is;
	struct rd_entry *rd;
	struct an_entry *an;

	if (!ifp)
		return EINVAL;

	/* Remove ES and IS hello mcast */
	mcast_register (ifname, SIOCDELMULTI);

	/* Announce timer */
	evtimer_del (&ifp->if_es_announce);

	/* Remove all ES/IS/RD/AN stuff */
	flush (fd, ifp, 1);

	/* free pinger stuff */
	if (ifp->if_pe) {
		evtimer_del (&ifp->if_pe->pe_evt);
		free (ifp->if_pe);
	}

	/* socket read (one per interface) */
#ifndef _SKIP_VNB
	event_del (&ifp->if_cs_ev);
	close (ifp->if_csock);
	event_del (&ifp->if_ds_ev);
	close (ifp->if_dsock);
#endif /* _SKIP_VNB */

	/* Remove iface itself */
	LIST_REMOVE (ifp, if_link);
	log_msg (LOG_DEBUG, 0, "Interface %s removed\n", ifp->if_name);
	free (ifp);
	return 0;
}


struct _parsed {
	char *word;
	int  keyword;
};

#define MAX_WORDS 50
struct _parsed parsed_line [MAX_WORDS];
int nb_words;
enum {
	K_NEW = 1,
	K_DELETE,
	K_ANNOUNCEADD,
	K_ANNOUNCEDEL,
	K_STATIC_ESADD,
	K_STATIC_ESDEL,
	K_STATIC_ISADD,
	K_STATIC_ISDEL,
	K_STATIC_RDADD,
	K_STATIC_RDADD_FULL,
	K_STATIC_RDDEL,
	K_SHOW,
	K_SETPROMPT,
	K_DEBUG,
	K_NODEBUG,
	K_PING,
	K_CKSUM,
	K_NOCKSUM,
	K_FLUSH,
#ifdef __HARD_CODED_TEST_
	K_TEST,
	K_DOESHELLO,
	K_DOISHELLO,
	K_DOREDIRECT,
	K_PONG,
#endif
	K_LAST
};

void parse (char *line)
{
	struct _parsed *ap;
	char *pc;
	/*
	 * Removes all comments
	 */
	pc = (char *)strchr(line, ';');
	if (pc)
		*pc = 0;

	/*
	 * splits into words
	 */
	nb_words = 0;
	for (ap = parsed_line ; (ap->word = (char *)strsep(&line, " \t\n")) != NULL ; ) {
		if (*ap->word != '\0') {
			/* we could probably have some thing more efficient here.. */
			if (strcmp (ap->word, "new") == 0)
				ap->keyword = K_NEW;
			else if (strcmp (ap->word, "delete") == 0)
				ap->keyword = K_DELETE;
			else if (strcmp (ap->word, "announce-add") == 0)
				ap->keyword = K_ANNOUNCEADD;
			else if (strcmp (ap->word, "announce-del") == 0)
				ap->keyword = K_ANNOUNCEDEL;
			else if (strcmp (ap->word, "static-es-add") == 0)
				ap->keyword = K_STATIC_ESADD;
			else if (strcmp (ap->word, "static-es-del") == 0)
				ap->keyword = K_STATIC_ESDEL;
			else if (strcmp (ap->word, "static-is-add") == 0)
				ap->keyword = K_STATIC_ISADD;
			else if (strcmp (ap->word, "static-is-del") == 0)
				ap->keyword = K_STATIC_ISDEL;
			else if (strcmp (ap->word, "static-rd-add") == 0)
				ap->keyword = K_STATIC_RDADD;
			else if (strcmp (ap->word, "static-rd-full") == 0)
				ap->keyword = K_STATIC_RDADD_FULL;
			else if (strcmp (ap->word, "static-rd-del") == 0)
				ap->keyword = K_STATIC_RDDEL;
			else if (strcmp (ap->word, "show") == 0)
				ap->keyword = K_SHOW;
			else if (strcmp (ap->word, "flush") == 0)
				ap->keyword = K_FLUSH;
			else if (strcmp (ap->word, "prompt") == 0)
				ap->keyword = K_SETPROMPT;
			else if (strcmp (ap->word, "ping") == 0)
				ap->keyword = K_PING;
			else if (strcmp (ap->word, "debug") == 0) {
				debug = 1;
				nb_words = 0;
				return;
			}
			else if (strcmp (ap->word, "nodebug") == 0) {
				debug = 0;
				nb_words = 0;
				return;
			}
			else if (strcmp (ap->word, "cksum") == 0) {
				skip_cksum = 0;
				nb_words = 0;
				return;
			}
			else if (strcmp (ap->word, "nocksum") == 0) {
				skip_cksum = 1;
				nb_words = 0;
				return;
			}
#ifdef __HARD_CODED_TEST_
			else if (strcmp (ap->word, "test") == 0)
				ap->keyword = K_TEST;
			else if (strcmp (ap->word, "es") == 0)
				ap->keyword = K_DOESHELLO;
			else if (strcmp (ap->word, "is") == 0)
				ap->keyword = K_DOISHELLO;
			else if (strcmp (ap->word, "rd") == 0)
				ap->keyword = K_DOREDIRECT;
			else if (strcmp (ap->word, "pong") == 0)
				ap->keyword = K_PONG;
#endif
			else
				ap->keyword = 0;
			if (++ap >= &parsed_line[MAX_WORDS])
				break;
			nb_words++;
		}
	}
	return;
}

/* Configuration for "es-is" options */
void
do_config (int nline, int fd)
{
	struct iface *ifp = NULL;
	int err=0;
	char *unknown;

	if (nb_words < 1)
		return;

	if (nb_words >= 2) {
		ifp = get_ifp (parsed_line[1].word);
		if (parsed_line[0].keyword &&
		(parsed_line[0].keyword != K_NEW) &&
		(parsed_line[0].keyword != K_SHOW) &&
		(parsed_line[0].keyword != K_FLUSH) &&
		(parsed_line[0].keyword != K_SETPROMPT) &&
		ifp == NULL) {
			display_console (fd, "unknown interface %s in line #%d\n",
				parsed_line[1].word, nline);
			return;
		}
	}
	switch (parsed_line[0].keyword) {
	case K_NEW: {
		if (nb_words != 3)
			goto incor_wn;
		if (ifp) {
			display_console(fd, "interface %s already exists (line #)%d\n",
				 parsed_line[1].word, nline);
			return;
		}
		ifp = new_iface (parsed_line[1].word, parsed_line[2].word, &err);
		if (!ifp) {
			log_msg (LOG_WARNING, 0, "create interface %s error. errno #%d\n",
				parsed_line[1].word, err);
			goto cmd_failed;
		}
		break;
		}
	case K_DELETE: {
		if (nb_words != 2)
			goto incor_wn;
		iface_delete (fd, parsed_line[1].word);
		break;
	}
	case K_ANNOUNCEADD: {
		if (nb_words != 3)
			goto incor_wn;
		if (add_es_announce (parsed_line[1].word, parsed_line[2].word))
			goto cmd_failed;
		break;
	}
	case K_ANNOUNCEDEL: {
		if (nb_words != 3)
			goto incor_wn;
		if (remove_es_announce (parsed_line[1].word, parsed_line[2].word))
			goto cmd_failed;
		break;
	}
	case K_SHOW:
	case K_FLUSH: {
		if (nb_words != 2)
			goto incor_wn;
		if ((ifp == NULL) &&  (strcmp (parsed_line[1].word, "all") != 0)) {
			display_console(fd, "unknown interface %s (line #%d)\n",
			                parsed_line[1].word, nline);
			return;
		}
		if (parsed_line[0].keyword == K_SHOW)
			show (fd, ifp);
		else
			flush (fd, ifp, 0);
		break;
	}
	case K_SETPROMPT: {
		if (nb_words == 1)
			set_prompt (NULL);
		else
			set_prompt (parsed_line[1].word);
		break;
	}
	case K_STATIC_ESADD:
	case K_STATIC_ISADD: {
		struct osi_addr  osi;
		struct mac_addr  mac;
		u_int16_t hold = 0;
		if (nb_words < 4)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &osi);
		parse_mac (parsed_line[3].word, &mac);
		if (nb_words == 5)
			hold = atoi (parsed_line[4].word);
		if (parsed_line[0].keyword == K_STATIC_ESADD)
			receive_es_hello (ifp, &osi, &mac, hold);
		else
			receive_is_hello (ifp, &osi, &mac, hold);
		break;
	}
	case K_STATIC_RDADD: {
		struct osi_addr  tgt;
		struct mac_addr  mac;
		u_int16_t hold = 0;
		if (nb_words < 4)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &tgt);
		parse_mac (parsed_line[3].word, &mac);
		if (nb_words == 5)
			hold = atoi (parsed_line[4].word);
		receive_redirect (ifp, &tgt, &mac, NULL, hold);
		break;
	}
	case K_STATIC_RDADD_FULL: {
		struct osi_addr  osi_tgt;
		struct mac_addr  mac;
		struct osi_addr  osi_gw;
		u_int16_t hold = 0;
		if (nb_words < 5)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &osi_tgt);
		parse_mac (parsed_line[3].word, &mac);
		parse_osi (parsed_line[3].word, &osi_gw);
		if (nb_words == 5)
			hold = atoi (parsed_line[4].word);
		receive_redirect (ifp, &osi_tgt, &mac, &osi_gw, hold);
		break;
	}
	case K_STATIC_ESDEL: {
		struct osi_addr  osi;
		if (nb_words != 3)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &osi);
		remove_es_hello (ifp, &osi);
		break;
	}
	case K_STATIC_ISDEL: {
		struct osi_addr  osi;
		if (nb_words != 3)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &osi);
		remove_is_hello (ifp, &osi);
		break;
	}
	case K_STATIC_RDDEL: {
		struct osi_addr  osi;
		if (nb_words != 3)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &osi);
		remove_redirect (ifp, &osi);
		break;
	}
	case K_PING: {
		struct osi_addr  osi;
		if (nb_words != 3)
			goto incor_wn;
		parse_osi (parsed_line[2].word, &osi);
		pinger (fd, ifp, &osi);
		break;
	}
#ifdef __HARD_CODED_TEST_
	case K_TEST: {
		if (nb_words != 3)
			goto incor_wn;
		switch (parsed_line[2].keyword) {
		case K_DOESHELLO:
			do_test_es (ifp);
			break;
		case K_DOISHELLO:
			do_test_is (ifp);
			break;
		case K_DOREDIRECT:
			do_test_rd (ifp);
			break;
		case K_PING:
			do_test_ping (ifp);
			break;
		case K_PONG:
			do_test_pong (ifp);
			break;
		default:
			unknown = parsed_line[2].word;
			goto unknown_word;
			break;
		}
		break;
	}
#endif
	default:
		unknown = parsed_line[0].word;
		goto unknown_word;
	}
	return;
unknown_word:
	display_console(fd, "unknown/unexpected word <<%s>> in line #%d\n",
	         unknown, nline);
	return;
incor_wn:
	display_console(fd, "incorrect argument number for cmd %s in line #%d\n",
	         parsed_line[0].word, nline);
	return;
cmd_failed:
	display_console(fd, "command %s in line #%d failed\n",
	         parsed_line[0].word, nline);
	return;
}

u_int8_t dump_buf1 [SZ_DBUF];
u_int8_t dump_buf2 [SZ_DBUF];
u_int8_t dump_buf3 [SZ_DBUF];
void
show (int fd, struct iface *ifp_show)
{
	struct iface  *ifp;
	struct an_entry *an;
	struct es_entry *es;
	struct is_entry *is;
	struct rd_entry *rd;

	LIST_FOREACH (ifp, &ifnet, if_link) {
		if (ifp_show && (ifp_show != ifp))
			continue;
		display_console (fd, "ES-IS Status for interface %s \n", ifp->if_name);
		display_console (fd, "  Hello to announce :");
		if (LIST_FIRST(&ifp->if_an_head) == NULL)
			display_console (fd, " none\n");
		else
			display_console (fd, "\n");
		LIST_FOREACH (an, &ifp->if_an_head, an_link) {
			int i;
			struct osi_addr osi = an->an_osi;
			for (i=0; i<2; i++) {
				if (!i)
					osi.osi_val[osi.osi_len-1] = NSEL_NON_OSI;
				else
					osi.osi_val[osi.osi_len-1] = NSEL_OSI;
				dump_osi (&osi, dump_buf1, SZ_DBUF,NULL);
				display_console (fd, "  - %s ", dump_buf1);
				if (an->an_refcount>1)
					display_console (fd, "(%d)\n", an->an_refcount);
				else
					display_console (fd, "\n");
			}
		}
		display_console (fd, "  ES Hello received :");
		if (LIST_FIRST(&ifp->if_es_head) == NULL)
			display_console (fd, " none\n");
		else
			display_console (fd, "\n");
		LIST_FOREACH (es, &ifp->if_es_head, es_link) {
			dump_osi (&(es->es_osi), dump_buf1, SZ_DBUF, NULL);
			dump_mac (&(es->es_mac), dump_buf2, SZ_DBUF, NULL);
			display_console (fd, "  - OSI %s\n    --> MAC %s",
			                 dump_buf1, dump_buf2);
			if (es->es_hold) {
				time_t t;
				int elapsed;
				time (&t);
				display_console (fd, " (%d/%d)\n",
				            es->es_hold + es->es_date - t, es->es_hold);
			}
			else
				display_console (fd, " permanent\n");
		}
		display_console (fd, "  IS Hello received :");
		if (LIST_FIRST(&ifp->if_is_head) == NULL)
			display_console (fd, " none\n");
		else
			display_console (fd, "\n");
		LIST_FOREACH (is, &ifp->if_is_head, is_link) {
			dump_osi (&(is->is_osi), dump_buf1, SZ_DBUF, NULL);
			dump_mac (&(is->is_mac), dump_buf2, SZ_DBUF, NULL);
			display_console (fd, "  - OSI %s\n    --> MAC %s",
			                 dump_buf1, dump_buf2);
			if (is->is_hold) {
				time_t t;
				int elapsed;
				time (&t);
				display_console (fd, " (%d/%d)\n",
				            is->is_hold + is->is_date - t, is->is_hold);
			}
			else
				display_console (fd, " permanent\n");
		}
		display_console (fd, "  RD Hello received :");
		if (LIST_FIRST(&ifp->if_rd_head) == NULL)
			display_console (fd, " none\n");
		else
			display_console (fd, "\n");
		LIST_FOREACH (rd, &ifp->if_rd_head, rd_link) {
			dump_osi (&(rd->rd_es_osi), dump_buf1, SZ_DBUF, NULL);
			dump_mac (&(rd->rd_is_mac), dump_buf2, SZ_DBUF, NULL);
			dump_osi (&(rd->rd_is_osi), dump_buf3, SZ_DBUF, NULL);
			display_console (fd, "  - TGT %s\n     --> MAC %s",
			                 dump_buf1, dump_buf2);
			if (rd->rd_hold) {
				time_t t;
				int elapsed;
				time (&t);
				display_console (fd, " (%d/%d)\n",
				            rd->rd_hold + rd->rd_date - t, rd->rd_hold);
			}
			else
				display_console (fd, " permanent\n");
			display_console (fd, "     [GW %s]\n", dump_buf3);
		}
    }
}

void
flush (int fd, struct iface *ifp_flush, int all)
{
	struct iface  *ifp;
	struct es_entry *es, *es_next;
	struct is_entry *is, *is_next;
	struct rd_entry *rd, *rd_next;

	LIST_FOREACH (ifp, &ifnet, if_link) {
		if (ifp_flush && (ifp_flush != ifp))
			continue;
		for (es = LIST_FIRST(&ifp->if_es_head); es ; es = es_next) {
			es_next = LIST_NEXT (es, es_link);
			if (es->es_hold)
				evtimer_del (&(es->es_evt));
			if ((es->es_hold)  || all)
				es_entry_aging (0, 0, es);
		}
		for (is = LIST_FIRST(&ifp->if_is_head); is ; is = is_next) {
			is_next = LIST_NEXT (is, is_link);
			if (is->is_hold)
				evtimer_del (&(is->is_evt));
			if ((is->is_hold) || all )
				is_entry_aging (0, 0, is);
		}
		for (rd = LIST_FIRST(&ifp->if_rd_head); rd ; rd = rd_next) {
			rd_next = LIST_NEXT (rd, rd_link);
			if (rd->rd_hold)
				evtimer_del (&(rd->rd_evt));
			if ((rd->rd_hold) || all)
				rd_entry_aging (0, 0, rd);
		}
	}
}
