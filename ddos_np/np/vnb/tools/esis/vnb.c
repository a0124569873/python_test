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
#include <netgraph.h>
#include <netgraph/ng_osi.h>
#include <linux/if_ether.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_osi_eth.h>
#include <syslog.h>
#include "esisd.h"

/* Nothing expected on the Control Socket from VNB node */
static u_int8_t buf_cs_read[2048];
void read_csock_cb (int fd, short event, void *param)
{
	/* Just purge socket */
    NgRecvData(fd, buf_cs_read, sizeof(buf_cs_read), NULL);
	return;
}

void notify_es (int cmd, struct es_entry *es)
{
	struct iface *ifp = es->es_ifp;
	char path[NG_PATHLEN + 1];

	if ((cmd == OSI_DEL) || (cmd == OSI_CHANGE)) {
		struct ng_osi_eth_osi    os;

		dump_osi (&(es->es_osi), dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0,
		   "Removing ES on %s : OSI %s\n", ifp->if_name, dump_buf1);

		os.ngoe_osi_len = es->es_osi.osi_len;
		bcopy (es->es_osi.osi_val, os.ngoe_osi_val, es->es_osi.osi_len);

#ifndef _SKIP_VNB
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_OSI_ETH_COOKIE,
		   NGM_OSI_ETH_DEL_ES, &os, sizeof(os)) < 0)
			log_msg(LOG_NOTICE, errno,
			  "notify_es_del(%d): error in NgSendMsg %d\n", sizeof(os), errno);
#endif /* _SKIP_VNB */
	}

	if ((cmd == OSI_ADD) || (cmd == OSI_CHANGE)) {
		struct ng_osi_eth_resol  er;

		dump_osi (&(es->es_osi), dump_buf1, SZ_DBUF, NULL);
		dump_mac (&(es->es_mac), dump_buf2, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0,
		   "Adding ES on %s : OSI %s --> MAC %s\n",
		   ifp->if_name, dump_buf1, dump_buf2);

		er.ngoe_osi_len = es->es_osi.osi_len;
		bcopy (es->es_osi.osi_val, er.ngoe_osi_val, es->es_osi.osi_len);
		bcopy (es->es_mac.mac_val, er.ngoe_mac_val, 6);

#ifndef _SKIP_VNB
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_OSI_ETH_COOKIE,
		   NGM_OSI_ETH_ADD_ES, &er, sizeof(er)) < 0)
			log_msg(LOG_NOTICE, errno,
			  "notify_es_add(%d): error in NgSendMsg %d\n", sizeof(er), errno);
#endif /* _SKIP_VNB */
	}
}

void notify_is (int cmd, struct is_entry *is)
{
	struct iface *ifp = is->is_ifp;
	char path[NG_PATHLEN + 1];

	if ((cmd == OSI_DEL) || (cmd == OSI_CHANGE)) {
		struct ng_osi_eth_osi    os;

		dump_osi (&(is->is_osi), dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0,
		   "Removing IS on %s : OSI %s\n", ifp->if_name, dump_buf1);

		os.ngoe_osi_len = is->is_osi.osi_len;
		bcopy (is->is_osi.osi_val, os.ngoe_osi_val, is->is_osi.osi_len);

#ifndef _SKIP_VNB
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_OSI_ETH_COOKIE,
		   NGM_OSI_ETH_DEL_IS, &os, sizeof(os)) < 0)
			log_msg(LOG_NOTICE, errno,
			        "notify_is_del: error in NgSendMsg %d\n", errno);
#endif /* _SKIP_VNB */
	}

	if ((cmd == OSI_ADD) || (cmd == OSI_CHANGE)) {
		struct ng_osi_eth_resol  er;

		dump_osi (&(is->is_osi), dump_buf1, SZ_DBUF, NULL);
		dump_mac (&(is->is_mac), dump_buf2, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0,
		   "Adding IS on %s : OSI%s --> MAC %s\n",
		   is->is_ifp->if_name, dump_buf1, dump_buf2);

		er.ngoe_osi_len = is->is_osi.osi_len;
		bcopy (is->is_osi.osi_val, er.ngoe_osi_val, is->is_osi.osi_len);
		bcopy (is->is_mac.mac_val, er.ngoe_mac_val, 6);

#ifndef _SKIP_VNB
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_OSI_ETH_COOKIE,
		   NGM_OSI_ETH_ADD_IS, &er, sizeof(er)) < 0)
			log_msg(LOG_NOTICE, errno,
			        "notify_is_add: error in NgSendMsg %d\n", errno);
#endif /* _SKIP_VNB */
	}
}

void notify_rd (int cmd, struct rd_entry *rd)
{
	struct iface *ifp = rd->rd_ifp;
	char path[NG_PATHLEN + 1];

	if ((cmd == OSI_DEL) || (cmd == OSI_CHANGE)) {
		struct ng_osi_eth_osi    os;

		dump_osi (&(rd->rd_es_osi), dump_buf1, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0,
		   "Removing RD on %s : OSI %s\n", ifp->if_name, dump_buf1);

		os.ngoe_osi_len = rd->rd_es_osi.osi_len;
		bcopy (rd->rd_es_osi.osi_val, os.ngoe_osi_val, rd->rd_es_osi.osi_len);

#ifndef _SKIP_VNB
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_OSI_ETH_COOKIE,
		   NGM_OSI_ETH_DEL_RD, &os, sizeof(os)) < 0)
			log_msg(LOG_NOTICE, errno,
			        "notify_rd_del: error in NgSendMsg %d\n", errno);
#endif /* _SKIP_VNB */
	}
	if ((cmd == OSI_ADD) || (cmd == OSI_CHANGE)) {
		struct ng_osi_eth_resol  er;

		dump_osi (&(rd->rd_es_osi), dump_buf1, SZ_DBUF, NULL);
		dump_mac (&(rd->rd_is_mac), dump_buf2, SZ_DBUF, NULL);
		dump_osi (&(rd->rd_is_osi), dump_buf3, SZ_DBUF, NULL);
		log_msg (LOG_DEBUG, 0,
		   "Adding RD on %s : OSI %s --> MAC %s (GW %s)\n",
		   rd->rd_ifp->if_name, dump_buf1, dump_buf2, dump_buf3);

		er.ngoe_osi_len = rd->rd_es_osi.osi_len;
		bcopy (rd->rd_es_osi.osi_val, er.ngoe_osi_val, rd->rd_es_osi.osi_len);
		bcopy (rd->rd_is_mac.mac_val, er.ngoe_mac_val, 6);

#ifndef _SKIP_VNB
		snprintf(path, sizeof(path), "%s%s", ifp->if_ngname, ":");
		if (NgSendMsg(ifp->if_csock, path, NGM_OSI_ETH_COOKIE,
		   NGM_OSI_ETH_ADD_RD, &er, sizeof(er)) < 0)
			log_msg(LOG_NOTICE, errno,
			        "notify_rd_add: error in NgSendMsg %d\n", errno);
#endif /* _SKIP_VNB */
	}
}
