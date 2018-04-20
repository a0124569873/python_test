/*
 * Copyright(c) 2013 6WIND, all rights reserved
 */

#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/audit.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netlink/msg.h>

#include "cm_priv.h"

#ifdef CONFIG_CACHEMGR_AUDIT

static int cm_nlaudit_send_rule(struct nl_sock *nlsock, int type,
				void *data, unsigned int size)
{
	int res = -1;
	struct nl_msg *msg = NULL;

	msg = nlmsg_alloc_simple(type, NLM_F_REQUEST);
	if (!msg)
		goto nla_put_failure;

	if (size && data)
		if (nlmsg_append(msg, data, size, NLMSG_ALIGNTO) < 0)
			goto nla_put_failure;

	do {
		res = nl_send_auto(nlsock, msg);
	} while ((res < 0) && (res == NLE_INTR));

nla_put_failure:
	nlmsg_free(msg);
	return res;
}

int cm_nlaudit_set_pid(struct nl_sock *nlsock)
{
	struct audit_status s;
	int ret;

	memset(&s, 0, sizeof(s));
	s.mask    = AUDIT_STATUS_PID;
	s.pid     = getpid();

	ret = cm_nlaudit_send_rule(nlsock, AUDIT_SET, &s, sizeof (s));
	if (ret < 0) {
		syslog(LOG_ERR, "%s: failed to set AUDIT socket pid (%s)\n",
		       __func__, nl_geterror(ret));
		return -1;
	}

	return 0;
}

int cm_nlaudit_set_enabled(struct nl_sock *nlsock, int enabled)
{
	struct audit_status s;
	int ret;

	memset(&s, 0, sizeof(s));
	s.mask = AUDIT_STATUS_ENABLED;
	s.enabled = enabled;

	ret = cm_nlaudit_send_rule(nlsock, AUDIT_SET, &s, sizeof (s));
	if (ret < 0) {
		syslog(LOG_ERR, "%s: failed to set AUDIT enabled to %d (%s)\n",
		       __func__, enabled, nl_geterror(ret));
		return -1;
	}

	return 0;
}

void cm_nlaudit_rule_init(struct audit_rule_data *rule, int flags, int action)
{
	memset(rule, 0, sizeof(*rule));

	rule->flags = flags;
	rule->action = action;
}

void cm_nlaudit_rule_add_filter(struct audit_rule_data *rule, int field,
				int op, int value)
{
	int idx = rule->field_count;

	rule->fields[idx] = field;
	rule->fieldflags[idx] = op;
	rule->values[idx] = value;
	rule->field_count++;
}

static void cm_nlaudit_dump_rule(struct audit_rule_data *rule)
{
	int i;

	syslog(LOG_DEBUG, "%s: Rule flags 0x%x action 0x%x:\n",
	       __func__, rule->flags, rule->action);

	for (i = 0; i < rule->field_count; i++) {
		syslog(LOG_DEBUG,
		       "fields[%d]=0x%x, fieldflags[%d]=0x%x, values[%d]=0x%x",
		       i, rule->fields[i], i, rule->fieldflags[i],
		       i, rule->values[i]);
	}
}

int cm_nlaudit_rule_add(struct nl_sock *nlsock, struct audit_rule_data *rule)
{
	int ret;

	/*
	 * buflen is always 0 in the rule we configure until now, however
	 * this is the correct way to do it.
	 */
	ret = cm_nlaudit_send_rule(nlsock, AUDIT_ADD_RULE, rule,
				   sizeof (*rule) + rule->buflen);
	if (ret < 0) {
		syslog(LOG_ERR, "%s: failed to add audit rule (%s)\n",
		       __func__, nl_geterror(ret));
		cm_nlaudit_dump_rule(rule);
		return -1;
	}

	return 0;
}

int cm_nlaudit_rule_del(struct nl_sock *nlsock, struct audit_rule_data *rule)
{
	int ret;

	/*
	 * buflen is always 0 in the rule we configure until now, however
	 * this is the correct way to do it.
	 */
	ret = cm_nlaudit_send_rule(nlsock, AUDIT_DEL_RULE, rule,
				   sizeof (*rule) + rule->buflen);
	if (ret < 0) {
		syslog(LOG_ERR, "%s: failed to delete audit rule (%s)\n",
		       __func__, nl_geterror(ret));
		cm_nlaudit_dump_rule(rule);
		return -1;
	}

	return 0;
}

#define NF_MAX_TABLE_NAME_LEN 16

static int cm_nl_parse_audit_nfmsg(char *msg, int msglen, char *table_name,
                                   uint8_t *family)
{
	enum {
		TOKEN_NONE,
		TOKEN_TABLE,
		TOKEN_FAMILY
	} token = TOKEN_NONE;
	char *pstr, *wdstart = NULL;
	int wdlen;
	char fam[4] = "";

	for (pstr = msg ;; pstr++) {
		if (pstr == msg + msglen ||
		    *pstr == '\0' ||
		    *pstr == '=' ||
		    *pstr == ' ') {
			if (wdstart == NULL)
				goto cont;
			wdlen = pstr - wdstart;
			if (token == TOKEN_TABLE) {
				if (wdlen >= NF_MAX_TABLE_NAME_LEN)
					return -1;
				memcpy(table_name, wdstart, wdlen);
				table_name[wdlen] = '\0';
				token = TOKEN_NONE;
			} else if (token == TOKEN_FAMILY) {
				if (wdlen > sizeof(fam) - 1)
					return -1;
				memcpy(fam, wdstart, wdlen);
				*family = atoi(fam);
				token = TOKEN_NONE;
			} else if (wdlen == sizeof("table") -1 &&
			           !strncmp(wdstart, "table", wdlen))
				token = TOKEN_TABLE;
			else if (wdlen == sizeof("family") - 1 &&
			         !strncmp(wdstart, "family", wdlen))
				token = TOKEN_FAMILY;
			wdstart = NULL;
		  cont:
			if (pstr == msg + msglen || *pstr == '\0')
				break;
		}
		else if (wdstart == NULL)
			wdstart = pstr;
	}

	return 0;
}

void cm_nlaudit_dispatch(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	switch (h->nlmsg_type) {
	case AUDIT_NETFILTER_CFG:
        {
		char *nfmsg;
		char table_name[NF_MAX_TABLE_NAME_LEN];
		uint8_t family = 0;
		int msglen;

		nfmsg = nlmsg_data(h);
		msglen = nlmsg_datalen(h);

		if (msglen <= 0) {
			syslog(LOG_ERR, "%s: AUDIT_NETFILTER_CFG bad length %d\n",
			       __FUNCTION__, msglen);
			break;
		}

		memset(table_name, 0, sizeof (table_name));

		if (cm_nl_parse_audit_nfmsg(nfmsg, msglen, table_name, &family) < 0) {
			syslog(LOG_ERR, "%s: AUDIT_NETFILTER_CFG error parsing message\n",
					__FUNCTION__);
			break;
		}

		/* we only dump tables handled by the fast path */
		if (!strcmp(table_name, "filter") ||
		    !strcmp(table_name, "mangle") ||
		    (!strcmp(table_name, "nat") && family == AF_INET)) {

			if (cm_debug_level & CM_DUMP_EXT_NL_RECV)
				syslog(LOG_DEBUG, SPACES" nftable name: [%s], family: %s\n", table_name,
						(family == AF_INET) ? "AF_INET" : "AF_INET6");

			cm_iptc_dump_table_async(h->nlmsg_seq, table_name, family, sock_vrfid);
		}
		break;
        }
	default:
		break;
	}

	return;
}

#endif
