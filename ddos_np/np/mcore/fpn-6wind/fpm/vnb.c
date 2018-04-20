
/*
 * Copyright (c) 2007 6WIND
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <net/if.h>

#include <net/ethernet.h>

#include <ctype.h>
#include <sys/queue.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"
#include "fp-vnb.h"

#include "netgraph.h"
#include <netgraph/ng_message.h>
#include <netgraph/ng_iface.h>

#include "shmem/fpn-shmem.h"
static fp_vnb_shared_mem_t *fp_vnb_shared = NULL;

/* compile-time option to display verbose vnb logs */
//#define FPM_DEBUG_VNB_DUMP

extern void fp_vnb_oosync(uint32_t last_seqnum, uint32_t recv_seqnum);

static int csock;

static void dumphex(const char *data, unsigned int len);

static fp_vnb_shared_mem_t *get_fp_vnb_shared_mem(void)
{
	return fpn_shmem_mmap("fp-vnb-shared", NULL,
			      sizeof(fp_vnb_shared_mem_t));
}

static int fpm_vnb_msghdr(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_vnb_msghdr *req = (struct cp_vnb_msghdr *)request;
	char *arg = "no arg", *path = "no path", *data;
	uint32_t cookie, cmd, seqnum, cpnodeid;
	uint16_t arglen, pathlen;

	if (fp_vnb_shared == NULL) {
		syslog(LOG_ERR, "fp-vnb shared memory not available\n");
		return -1;
	}

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_vnb_msghdr: cookie=%d cmd=%d seqnum=%u arglen=%d pathlen=%d\n",
		       ntohl(req->vnbh_typecookie), ntohl(req->vnbh_cmd), ntohl(req->vnbh_seqnum),
		       ntohs(req->vnbh_arglen), ntohs(req->vnbh_pathlen));

	/* fastpath lost, drop packet to avoid lock in reply reception */
	if (fpn0_status == 0) {
		if (f_verbose)
			syslog(LOG_INFO, "fpn0 down, drop packet\n");
		return 0;
	}

	cookie = ntohl(req->vnbh_typecookie);
	cmd = ntohl(req->vnbh_cmd);
	seqnum = ntohl(req->vnbh_seqnum);
	arglen = ntohs(req->vnbh_arglen);
	pathlen = ntohs(req->vnbh_pathlen);
	cpnodeid = ntohl(req->vnbh_cpnodeid);

	/*
	 * Do not increment sequence number in case of NGM_NULL in order
	 * to detect loss of VNB messages only for messages which manipulates
	 * VNB graph.
	 */
	if (fp_vnb_shared->expected_seqnum) {
		if (seqnum != (fp_vnb_shared->expected_seqnum))
			fp_vnb_oosync(fp_vnb_shared->expected_seqnum, seqnum);
		else if (cookie != NGM_GENERIC_COOKIE || cmd != NGM_NULL)
			fp_vnb_shared->expected_seqnum =
				(seqnum + 1) ? seqnum + 1 : 1;
	}
	else if (cookie != NGM_GENERIC_COOKIE || cmd != NGM_NULL)
		fp_vnb_shared->expected_seqnum = (seqnum + 1) ? seqnum + 1 : 1;

	/* parse vnb message header */
	data = (char *)(req + 1);
	if (arglen) {
		arg = data;
		data += arglen;
	}
	if (pathlen) {
		path = data;
	}

	/* filter interesting stuff */

	if (cookie == NGM_GENERIC_COOKIE && cmd == NGM_ASCII2BINARY) {
		if (f_verbose)
			syslog(LOG_INFO, "ignore ascii2binary\n");
		return 0;
	}

	if (cookie == NGM_GENERIC_COOKIE && cmd == NGM_NULL) {
		if (f_verbose)
			syslog(LOG_DEBUG, "NULL message received\n");
		/* A system of response could be implemented here if needed */
		return 0;
	}

	if (cookie == NGM_GENERIC_COOKIE && cmd == NGM_MKPEER_ID) {
		struct ngm_mkpeer *mkp = (struct ngm_mkpeer *)arg;
		if (f_verbose)
			syslog(LOG_DEBUG, "mkpeer type=%s, ourhook=%s, peerhook=%s\n",
			       mkp->type, mkp->ourhook, mkp->peerhook);
	}

	if (NgSendMsgCPNodeID(csock, path, cookie, cmd, arg, arglen, cpnodeid) < 0) {
		syslog(LOG_ERR, "fpm_vnb_msghdr: cookie=%d cmd %d ERROR (%s)\n",
		       cookie, cmd, strerror(errno));
		dumphex(arg, arglen);
		return -1;
	}

	/* If there is a reply message, this message must be dropped */
	NgDelReplyMsg(csock);

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_vnb_msghdr: cookie=%d cmd %d SUCCESS\n", cookie, cmd);

	return 0;
}

static int fpm_vnb_msghdr_ascii(const uint8_t *request,
                                const struct cp_hdr *hdr)
{
	struct cp_vnb_msghdr *req = (struct cp_vnb_msghdr *)request;
	char *arg = "no arg", *path = "no path", *data;
	uint32_t cookie, cmd, seqnum;
	uint16_t arglen, pathlen;
	uint32_t cpnodeid;

	if (fp_vnb_shared == NULL) {
		syslog(LOG_ERR, "fp-vnb shared memory not available\n");
		return -1;
	}

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_vnb_msghdr_ascii: cookie=%d cmd=%d seqnum=%u arglen=%d pathlen=%d cpnodeid=%d\n",
		       ntohl(req->vnbh_typecookie), ntohl(req->vnbh_cmd), ntohl(req->vnbh_seqnum),
		       ntohs(req->vnbh_arglen), ntohs(req->vnbh_pathlen), ntohl(req->vnbh_cpnodeid));

	/* fastpath lost, drop packet to avoid lock in reply reception */
	if (fpn0_status == 0) {
		if (f_verbose)
			syslog(LOG_INFO, "fpn0 down, drop packet\n");
		return 0;
	}

	cookie = ntohl(req->vnbh_typecookie);
	cmd = ntohl(req->vnbh_cmd);
	seqnum = ntohl(req->vnbh_seqnum);
	arglen = ntohs(req->vnbh_arglen);
	pathlen = ntohs(req->vnbh_pathlen);
	cpnodeid = ntohl(req->vnbh_cpnodeid);

	/*
	 * Do not increment sequence number in case of NGM_NULL in order
	 * to detect loss of VNB messages only for messages which manipulates
	 * VNB graph.
	 */
	if (fp_vnb_shared->expected_seqnum) {
		if (seqnum != (fp_vnb_shared->expected_seqnum))
			fp_vnb_oosync(fp_vnb_shared->expected_seqnum, seqnum);
		else if (cookie != NGM_GENERIC_COOKIE || cmd != NGM_NULL)
			fp_vnb_shared->expected_seqnum =
				(seqnum + 1) ? seqnum + 1 : 1;
	}
	else if (cookie != NGM_GENERIC_COOKIE || cmd != NGM_NULL)
		fp_vnb_shared->expected_seqnum = (seqnum + 1) ? seqnum + 1 : 1;

	/* parse vnb message header */
	data = (char *)(req + 1);
	if (arglen) {
		arg = data;
		data += arglen;
	}
	if (pathlen) {
		path = data;
	}

	/* filter interesting stuff */

	if (cookie == NGM_GENERIC_COOKIE && cmd == NGM_ASCII2BINARY) {
		if (f_verbose)
			syslog(LOG_INFO, "ignore ascii2binary\n");
		return 0;
	}

	if (cookie == NGM_GENERIC_COOKIE && cmd == NGM_NULL) {
		if (f_verbose)
			syslog(LOG_DEBUG, "NULL message received\n");
		/* A system of response could be implemented here if needed */
		return 0;
	}

	if (cookie == NGM_GENERIC_COOKIE && cmd == NGM_MKPEER_ID) {
		if (f_verbose)
			syslog(LOG_DEBUG, "mkpeer %s\n", arg);
	}

	if (NgSendFastAsciiMsg(csock, path, cookie, cmd, arg, arglen, cpnodeid) < 0) {
		syslog(LOG_ERR, "fpm_vnb_msghdr_ascii: path %s cookie=%d cmd %d ERROR (%s)\n",
		       path, cookie, cmd, strerror(errno));
		if (arglen)
			syslog(LOG_ERR, "arg %s arglen %d\n", arg, arglen);
		return -1;
	}

	/* If there is a reply message, this message must be dropped */
	NgDelReplyMsg(csock);

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_vnb_msghdr_ascii: cookie=%d cmd %d SUCCESS\n", cookie, cmd);

	return 0;
}

static int fpm_vnb_dump(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_vnb_dump_msghdr *req = (struct cp_vnb_dump_msghdr *)request;
	size_t size = ntohl(hdr->cphdr_length);
	struct netfpc_vnbdump_msg *netfpc_msg;
#ifdef FPM_DEBUG_VNB_DUMP
	char *buf = (char *)req;
	size_t offset = 0;
	int len = size;
#endif

	netfpc_msg = (struct netfpc_vnbdump_msg *)req;

#ifdef FPM_DEBUG_VNB_DUMP
	syslog(LOG_DEBUG, "FPM: dump msg contains %d attr - len=%d - size=%zd\n",
		ntohl(netfpc_msg->attr_count),
		ntohl(netfpc_msg->len), size);
	buf = (char *)buf + sizeof(struct netfpc_vnbdump_msg);

	syslog(LOG_DEBUG, "FPM: attribute list\n");
	len -= sizeof(struct netfpc_vnbdump_msg);

	while (len > 0) {
		struct cp_vnb_dump_attr *attr;
		size_t attr_len;

		attr = (struct cp_vnb_dump_attr *)(buf + offset);
		attr_len = ntohl(attr->len);

		switch(ntohl(attr->type)) {
		case CMD_VNB_NODE:
		{
			struct ng_nl_node *nlnode = (struct ng_nl_node *) attr->data;
			syslog(LOG_DEBUG, "FPM: node %s[%x] - %s - %u hooks\n",
				nlnode->name, ntohl(nlnode->id), nlnode->type,
				ntohl(nlnode->numhooks));
			break;
		}
		case CMD_VNB_NODE_PRIV:
		{
			struct ng_nl_nodepriv *nlnodepriv = (struct ng_nl_nodepriv *) attr->data;
			syslog(LOG_DEBUG, "FPM: node priv - size %d\n",
				ntohl(nlnodepriv->data_len));
			break;
		}
		case CMD_VNB_HOOK:
		{
			struct ng_nl_hook *nlhook = (struct ng_nl_hook *)attr->data;
			syslog(LOG_DEBUG, "FPM:    hook %s <-> [%x]:%s\n",
				nlhook->name, ntohl(nlhook->peernodeid), nlhook->peername);
			break;
		}
		case CMD_VNB_HOOK_PRIV:
		{
			struct ng_nl_hookpriv *nlhookpriv = (struct ng_nl_hookpriv *) attr->data;
			syslog(LOG_DEBUG, "FPM: hook priv - size %d\n",
				ntohl(nlhookpriv->data_len));
			break;
		}
		case CMD_VNB_STATUS:
		{
			/* struct ng_nl_status *nlstatus = (struct ng_nl_status *) attr->data; */
			syslog(LOG_DEBUG, "FPM: status message\n");
			break;
		}
		default:
			syslog(LOG_DEBUG, "FPM:type=%d len=%d\n", ntohl(attr->type), ntohl(attr->len));
			break;
		}

		offset += FPM_ALIGN4(attr_len + sizeof(*attr));
		len -= FPM_ALIGN4(attr_len + sizeof(*attr));
	}
#endif

	if (s_nfpc >= 0) {
		if (netfpc_send(s_nfpc, netfpc_msg, size,
				0, NETFPC_MSGTYPE_VNBDUMP) < 0) {
			return -1;
		}
	}

	return 0;
}

static void fpm_vnb_init(__attribute__((unused)) int graceful)
{
	fp_vnb_shared = get_fp_vnb_shared_mem();
	if (fp_vnb_shared == NULL) {
		perror("cannot create VNB shared memory");
		return;
	}

	if (NgMkSockNode(vnb_name, &csock, NULL) < 0) {
		perror("cannot create netgraph socket");
		return;
	}

	fpm_register_msg(CMD_VNB_MSGHDR, fpm_vnb_msghdr, NULL);
	fpm_register_msg(CMD_VNB_ASCIIMSG, fpm_vnb_msghdr_ascii, NULL);
	fpm_register_msg(CMD_VNB_DUMP, fpm_vnb_dump, NULL);

	if (fpm_wipe_vnb_nodes && s_nfpc >= 0)
		netfpc_send(s_nfpc, NULL, 0, 0, NETFPC_MSGTYPE_VNB_RESET);
}

static struct fpm_mod fpm_vnb_mod = {
	.name = "vnb",
	.init = fpm_vnb_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_vnb_mod);
}

static void dumphex(const char *data, unsigned int len)
{
	unsigned int i, out, ofs;
# define LINE_LEN 80
	char line[LINE_LEN];	/* space needed 8+16*3+3+16 == 75 */

	ofs = 0;
	while (ofs < len) {

		/* format 1 line in the buffer, then use printk to print them */
		out = snprintf(line, LINE_LEN, "%08X", ofs);
		for (i=0; ofs+i < len && i<16; i++)
			out += snprintf(line+out, LINE_LEN - out, " %02X", (unsigned char)data[ofs+i]);
		for(;i<=16;i++)
			out += snprintf(line+out, LINE_LEN - out, "   ");
		for(i=0; ofs < len && i<16; i++, ofs++) {
			unsigned char c = data[ofs];
			if (!isascii(c) || !isprint(c))
				c = '.';
			out += snprintf(line+out, LINE_LEN - out, "%c", c);
		}
		syslog(LOG_DEBUG, "%s\n", line);
	}
}
