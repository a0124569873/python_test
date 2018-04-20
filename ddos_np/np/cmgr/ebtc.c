/* Copyright 2014 6WIND S.A. */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/netfilter_bridge/ebtables.h>

/* additional ebtables matches */
#include <linux/netfilter_bridge/ebt_ip.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#include <linux/netfilter_bridge/ebt_ip6.h>
#else /* versions <  2.6.37 do (wrongly) not export this header */
#define EBT_IP6_MATCH "ip6"
struct ebt_ip6_info {
	struct in6_addr saddr;
	struct in6_addr daddr;
	struct in6_addr smsk;
	struct in6_addr dmsk;
	__u8  tclass;
	__u8  protocol;
	__u8  bitmask;
	__u8  invflags;
	union {
		__u16 sport[2];
		__u8 icmpv6_type[2];
	};
	union {
		__u16 dport[2];
		__u8 icmpv6_code[2];
	};
};
#endif

#include <event.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"                    /* cm_debug_level */

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
#include "libvrf.h"
#endif

#define EBTC_LOG(level, fmt, args...) do {				\
		syslog(level, "%s: " fmt "\n", __func__, ## args);	\
	} while(0)

#define MAX(a,b) (a) >= (b) ? (a) : (b)

const char *const inetbr_names[] = {
        "PREROUTING", "INPUT", "FORWARD",
        "OUTPUT", "POSTROUTING", "BROUTING",
};

/* Given an index in the hook_prio table, return the matching hook name. */
static int ebtc_hook_name2idx(char *hookname)
{
	int hook = 0;

	while (hook < NF_BR_NUMHOOKS && strcmp(inetbr_names[hook], hookname))
		hook++;
	return hook;
}

/* Returns the number of bits set to 1 in n. */
static unsigned int count_bits(unsigned int n)
{
	unsigned int c; /* c accumulates the total bits set in v */

	for (c = 0; n; c++)
		/* clear the least significant bit set */
		n &= n - 1;
	return c;
}

/* Return 0 if the hook is the last valid one, !0 otherwise.
 * Warning: there's no check on the hook validity.
 */
static int is_last_std_chain(int hook, unsigned int valid_hooks)
{
	return !(valid_hooks >> (hook + 1));
}

/* Insert a newly crafted policy rule (matching any packet),
 * at location *cur_rule in the table's rules array.
 * *cur_rule and table->count are incremented accordingly.
 */
static void add_error(struct cp_ebt_table* table, int *cur_rule)
{
	struct cp_ebt_rule *rule = &table->rules[*cur_rule];

	rule->target.type = CM_EBT_TARGET_TYPE_ERROR;

	(*cur_rule)++;
	table->count++;
}

/* Insert a newly crafted ERROR rule at location *cur_rule in the table's rules
 * array. *cur_rule and table->count are incremented accordingly.
 */
static void add_policy(struct cp_ebt_table* table,
		       int *cur_hook, int *cur_rule, int policy)
{
	struct cp_ebt_rule *rule = &table->rules[*cur_rule];

	rule->target.type = CM_EBT_TARGET_TYPE_STANDARD;
	rule->target.data.standard.verdict = htonl(policy);

	if (*cur_hook < NF_BR_NUMHOOKS) /* only for std chains */
		table->underflow[*cur_hook] = htonl(*cur_rule);

	/* A rule with EBT_NOPROTO unset in the bitmask means there is an ether
	 * protocol to match in the rule. By setting it to 1, we make sure the
	 * dataplane won't try to match a protocol when reading the policy.
	 */
	rule->bitmask |= CM_EBT_NOPROTO;
	rule->bitmask = htonl(rule->bitmask);

	(*cur_rule)++;
	table->count++;
}

/* Returns the number of user-defined chains the kernel returned. */
static int ebtc_count_udc(const struct ebt_entry *e,
			  unsigned int *cnt)
{
	/* Beginning of a chain (an ebt_entries) */
	if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) == 0) {
		struct ebt_entries *entries = (struct ebt_entries *) e;

		int cur_hook = ebtc_hook_name2idx(entries->name);
		if (cur_hook >= NF_BR_NUMHOOKS) /* udc */
			(*cnt)++;
	}
	return 0;
}

/* We filled cp_rules with a jump target with the offset given by the kernel.
 * This value is relative to the the first rule in the kernel view.
 * Translate this number to match the first rule in the udc in our cp_table.
 */
static int ebtc_translate_jumps(const struct ebt_entry *e,
				struct cp_ebt_table *table,
				unsigned int nb_rules, int *cur_rule,
				struct ebt_entries *global_entries)
{
	/* Beginning of a chain (an ebt_entries) */
	if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) == 0) {
		struct ebt_entries *entries = (struct ebt_entries *) e;
		unsigned int offset, udc_first_rule;
		int i;

		unsigned int cur_hook = ebtc_hook_name2idx(entries->name);
		if (cur_hook < NF_BR_NUMHOOKS) {	/* standard chain */
			(*cur_rule)++; /* for the policy */

			if (is_last_std_chain(cur_hook, ntohl(table->valid_hooks)))
				(*cur_rule)++;	/* for the ERROR */
			return 0;
		}

		/* offset is the verdict value the kernel returned for the
		 * current udc.
		 */
		offset = (void *)entries - (void *)global_entries;

		/* *cur_rule should match the first rule number for this udc. */
		udc_first_rule = *cur_rule;

		/*
		 * Translate any rule with verdict "offset" to the udc_first_rule
		 * offset, relative to the cp_table.
		 */
		for (i = 0; i < nb_rules; i++) {
			struct cp_ebt_rule* rule = &table->rules[i];

			/* verdicts have been stored in network order. Use ntohl */
			if ((rule->target.type == CM_EBT_TARGET_TYPE_STANDARD) &&
			    (ntohl(rule->target.data.standard.verdict) == offset))
				rule->target.data.standard.verdict = htonl(udc_first_rule);
		}

		(*cur_rule) += 2; /* for the udc's policy and ERROR */
	} else	/* simple ebt_entry */
		(*cur_rule)++;

	return 0;
}

/* Translate the target and put it in the CP rule.
 * Return 0 if everything went well.
 */
static int ebtc_copy_target(const struct ebt_entry_target *t,
			    struct cp_ebt_rule *rule)
{
	if (!strcmp(t->u.name, EBT_STANDARD_TARGET)) {
		struct ebt_standard_target *stdtarget =
			(struct ebt_standard_target *)t;

		rule->target.type = CM_EBT_TARGET_TYPE_STANDARD;
		rule->target.data.standard.verdict = htonl(stdtarget->verdict);
	} else if (!strcmp(t->u.name, "error"))
		rule->target.type = CM_EBT_TARGET_TYPE_ERROR;
	else {
		EBTC_LOG(LOG_ERR, "Unknown target (%s)", t->u.name);
		return -ESRCH;
	}

	return 0;
}

/* Translate the match and put it in the CP rule.
 * Return 0 most of the time to keep the EBT_MATCH_ITERATE looping.
 */
static int ebtc_copy_match(const struct ebt_entry_match *m,
			   struct cp_ebt_rule *rule)
{
	if (!strcmp(m->u.name, EBT_IP_MATCH)) {
		struct ebt_ip_info *ipinfo = (struct ebt_ip_info *)m->data;
		int i;

		rule->l3_type = CM_EBT_L3_TYPE_IP;

		/* IP addresses are already in network order */
		rule->l3.ipv4.saddr      = ipinfo->saddr;
		rule->l3.ipv4.daddr      = ipinfo->daddr;
		rule->l3.ipv4.smsk       = ipinfo->smsk;
		rule->l3.ipv4.dmsk       = ipinfo->dmsk;

		/* those are uint_8: no need to convert to network order */
		rule->l3.ipv4.tos        = ipinfo->tos;
		rule->l3.ipv4.protocol   = ipinfo->protocol;
		rule->l3.ipv4.bitmask    = ipinfo->bitmask;
		rule->l3.ipv4.invflags   = ipinfo->invflags;

		for (i = 0; i < 2; i++) {
			rule->l3.ipv4.sport[i] = htons(ipinfo->sport[i]);
			rule->l3.ipv4.dport[i] = htons(ipinfo->dport[i]);
		}
	} else if (!strcmp(m->u.name, EBT_IP6_MATCH)) {
		struct ebt_ip6_info *ip6info = (struct ebt_ip6_info *)m->data;
		int i;

		rule->l3_type = CM_EBT_L3_TYPE_IP6;

		/* IPv6 addresses are actually uint_8[16] */
		rule->l3.ipv6.saddr      = ip6info->saddr;
		rule->l3.ipv6.daddr      = ip6info->daddr;
		rule->l3.ipv6.smsk       = ip6info->smsk;
		rule->l3.ipv6.dmsk       = ip6info->dmsk;

		/* those are uint_8: no need to convert to network order */
		rule->l3.ipv6.tclass     = ip6info->tclass;
		rule->l3.ipv6.protocol   = ip6info->protocol;
		rule->l3.ipv6.bitmask    = ip6info->bitmask;
		rule->l3.ipv6.invflags   = ip6info->invflags;

		for (i = 0; i < 2; i++) {
			rule->l3.ipv6.sport[i] = htons(ip6info->sport[i]);
			rule->l3.ipv6.icmpv6_type[i] = ip6info->icmpv6_type[i];

			rule->l3.ipv6.dport[i] = htons(ip6info->dport[i]);
			rule->l3.ipv6.icmpv6_code[i] = ip6info->icmpv6_code[i];
		}
	} else {
		EBTC_LOG(LOG_ERR, "Unknown match type (%s)", m->u.name);
		return -ESRCH;
	}

	return 0;
}

/* Translate the entry and put it in the CP rule.
 * It is assumed that the table has a correct valid_hooks value set.
 * Return 0 most of the time to keep the EBT_ENTRY_ITERATE looping.
 */
static int ebtc_copy_entry(const struct ebt_entry *e,
			   struct cp_ebt_table *table,
			   int *cur_hook, int *cur_rule,
			   int *add_error_rule, int *add_policy_rule,
			   int *policy)
{
	/* Beginning of a chain (an ebt_entries) */
	if ((e->bitmask & EBT_ENTRY_OR_ENTRIES) == 0) {
		struct ebt_entries *entries = (struct ebt_entries *) e;

		/* Complete the previous (if existing) chain with policy and
		 * ERROR rules.
		 */
		if (*add_policy_rule) {
			add_policy(table, cur_hook, cur_rule, *policy);
			*add_policy_rule = 0;
		}
		if (*add_error_rule) {
			add_error(table, cur_rule);
			*add_error_rule = 0;
		}

		*cur_hook = ebtc_hook_name2idx(entries->name);

		if (*cur_hook < NF_BR_NUMHOOKS) {	/* standard chain */
			if (! (ntohl(table->valid_hooks) & (1 << *cur_hook))) {
				EBTC_LOG(LOG_ERR,
					 "Received entries for invalid hook %s",
					 entries->name);
				return -EINVAL;
			}

			table->hook_entry[*cur_hook] = htonl(*cur_rule);
			/* underflow will be set when creating the policy. */

			/* this is a standard chain. make sure to add a policy
			 * rule when reaching the end of this chain's rules.
			 */
			*add_policy_rule = 1;
			*policy = entries->policy;

			/* A single ERROR rule should be set at the end of all
			 * std chains' rules.
			 */
			if (is_last_std_chain(*cur_hook, ntohl(table->valid_hooks)))
				*add_error_rule = 1;

		} else	/* user-defined chain */
			*add_error_rule = 1;

		/* for udc and std chains alike: add a policy rule */
		*add_policy_rule = 1;
		*policy = entries->policy;

	} else {	/* An entry */
		struct cp_ebt_rule *rule;
		struct ebt_entry_target *t;

		rule = &table->rules[*cur_rule];

		rule->bitmask = htonl(e->bitmask);
		rule->invflags = htonl(e->invflags);
		/* ethproto is already in network order */
		rule->ethproto = e->ethproto;

		memcpy(rule->in, e->in, sizeof(rule->in));
		memcpy(rule->logical_in, e->logical_in,
		       sizeof(rule->logical_in));
		memcpy(rule->out, e->out, sizeof(rule->out));
		memcpy(rule->logical_out, e->logical_out,
		       sizeof(rule->logical_out));

		memcpy(rule->sourcemac, e->sourcemac, sizeof(rule->sourcemac));
		memcpy(rule->sourcemsk, e->sourcemsk, sizeof(rule->sourcemsk));
		memcpy(rule->destmac, e->destmac, sizeof(rule->destmac));
		memcpy(rule->destmsk, e->destmsk, sizeof(rule->destmsk));

		if (EBT_MATCH_ITERATE(e, ebtc_copy_match, rule) < 0) {
			EBTC_LOG(LOG_ERR, "Failed to copy match");
			return -EINVAL;
		}

		/* Compute the target address */
		t = (struct ebt_entry_target *)(((char *)e) + e->target_offset);

		if (ebtc_copy_target(t, rule) < 0) {
			EBTC_LOG(LOG_ERR, "Failed to copy target");
			return -EINVAL;
		}

		(*cur_rule)++;
	}
	return 0;
}

/* Start sync of a given ebtable from the kernel towards the fast path.
 *
 * First, request the kernel to dump us the required table.
 * Then, translate that table into a cp_ebt_table and transmit it to the fpm
 * to update the fast path accordingly.
 *
 * In order to be a valid callback for libvrf_iterate, the second argument
 * is a (void *), while it actually contains a (char *).
 */
static void ebtc_dump_ebtable(int vrfid, void *data)
{
	struct ebt_replace repl;
	int sockfd = 0;
	char *entries = NULL;
	char *tablename = (char *)data;
	socklen_t size = 0;
	struct ebt_counter *counters = NULL;
	struct cp_ebt_table *table = NULL;
	uint8_t tbname_len;
	unsigned int udc, nb_rules;
	int cur_hook, cur_rule, add_error_rule, add_policy_rule, policy;


	memset(&repl, 0, sizeof(struct ebt_replace));

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	/* ebtc_dump_ebtable creates sockets, we change vrf here to
	 * avoid code duplication.
	 */
	if (vrfid && (libvrf_change(vrfid) < 0)) {
		EBTC_LOG(LOG_ERR, "libvrf_change failed for vrf %d", vrfid);
		return;
	}
#endif

	tbname_len = strlen(tablename);
	if (tbname_len >= EBT_TABLE_MAXNAMELEN) {
		EBTC_LOG(LOG_ERR, "wrong tablename length (%d, max: %d)",
			 (int)strlen(tablename), EBT_TABLE_MAXNAMELEN);
		goto out;
	}

	/* socket used to query the kernel for ebtables information */
	sockfd = socket(AF_INET, SOCK_RAW, PF_INET);
	if (sockfd < 0) {
		EBTC_LOG(LOG_ERR, "socket(): %s", strerror(errno));
		goto out;
	}

	/* First, we need to know how many entries there are, to query the
	 * kernel with the appropriate struct size.
	 */
	size = sizeof(repl);
	strncpy(repl.name, tablename, tbname_len);
	if (getsockopt(sockfd, IPPROTO_IP, EBT_SO_GET_INFO, &repl, &size)) {
		if (errno != ENOPROTOOPT)
			EBTC_LOG(LOG_ERR, "getsockopt(EBT_SO_GET_INFO): %s",
				strerror(errno));
		/* else, the appropriate kernel module has not been loaded:
		 * don't synchronize.
		 */

		goto out;
	}

	if ( !(entries = (char *) calloc(1, repl.entries_size)) ) {
		syslog(LOG_ERR,
		       "%s Not enough memory to hold ebtables entries",
		       __func__);
		goto out;
	}
	repl.entries = entries;

	if ( !(counters = (struct ebt_counter *) malloc (
		       repl.nentries * sizeof(struct ebt_counter)))) {
		EBTC_LOG(LOG_ERR, "Not enough memory for ebtables counters");
		goto out;
	}
	repl.counters = counters;
	repl.num_counters = repl.nentries;

	size += repl.num_counters * sizeof(struct ebt_counter) +
		repl.entries_size;

	/* Query the kernel to return repl filled with all ebtables entries. */
	if (getsockopt(sockfd, IPPROTO_IP, EBT_SO_GET_ENTRIES, &repl, &size)) {
		EBTC_LOG(LOG_ERR, "getsockopt(EBT_SO_GET_ENTRIES): %s",
			 strerror(errno));
		goto out;
	}

	udc = 0;
	if (EBT_ENTRY_ITERATE((char *)repl.entries, repl.entries_size,
			      ebtc_count_udc, &udc) < 0) {
		EBTC_LOG(LOG_ERR, "failed to count number of udc");
		goto out;
	}

	nb_rules = repl.nentries
		+ count_bits(repl.valid_hooks) /* nb of policy rules for std chains */
		+ 1                            /* trailing ERROR rule after std chains */
		+ udc * 2                      /* udc need their policy and ERROR rules too */
		;

	size = sizeof(struct cp_ebt_table);
	size += sizeof(struct cp_ebt_rule) * nb_rules;

	if (!(table = (struct cp_ebt_table *)calloc(1, size))) {
		EBTC_LOG(LOG_ERR, "could not alloc memory to dump ebtable");
		goto out;
	}

	/* Fill in our local table struct using information from the kernel. */
	memcpy(table->name, tablename, tbname_len);
	table->count = repl.nentries;
	table->vrfid = htonl(vrfid);
	table->valid_hooks = htonl(repl.valid_hooks);

	cur_hook = 0;
	cur_rule = 0;
	add_error_rule = 0;
	add_policy_rule = 0;
	policy = 0;

	/* fill the cp_ebt_table with rules from the kernel */
	if (EBT_ENTRY_ITERATE((char *)repl.entries, repl.entries_size,
			      ebtc_copy_entry, table, &cur_hook, &cur_rule,
			      &add_error_rule, &add_policy_rule, &policy) < 0)
	{
		EBTC_LOG(LOG_ERR, "failed to parse entry for table %s",
			 tablename);
		goto out;
	}

	/* The last ebt_entries has no policy/error rule at the end yet.
	 * Fix that.
	 */
	if (add_policy_rule)
		add_policy(table, &cur_hook, &cur_rule, policy);
	if (add_error_rule)
		add_error(table, &cur_rule);

	cur_rule = 0;
	/* update rules that jump to a udc with adequate offsets. */
	if (EBT_ENTRY_ITERATE((char *)repl.entries, repl.entries_size,
			      ebtc_translate_jumps, table, nb_rules,
			      &cur_rule, (struct ebt_entries *)entries) < 0)
	{
		EBTC_LOG(LOG_ERR, "failed to translate jump targets from"
			 " verdict value (offset) to rule idx in table->rules");
		goto out;
	}

	/* Translate count for network transmission, now that all rules have
	 * been accounted for.
	 */
	table->count = htonl(table->count);

	cm2cp_ebt_update(table);

out:

	if (table)
		free(table);
	if (counters)
		free(counters);
	if (entries)
		free(entries);
	if (sockfd > 0)
		close(sockfd);

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	if (vrfid && (libvrf_back() < 0)) {
		EBTC_LOG(LOG_ERR, "libvrf_back failed for vrf %d", vrfid);
	}
#endif
}

/* Initiate the synchronization of all known ebtables tables. */
static void ebtc_dump_ebtables(void)
{
	char *tablenames[] = { "filter", "broute", NULL};
	int i;

	for (i=0; tablenames[i]; i++) {
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
		libvrf_iterate(ebtc_dump_ebtable, tablenames[i]);
#else
		ebtc_dump_ebtable(0, tablenames[i]);
#endif
	}
}

/* Every few seconds (see main.c:tv_ebt_timer), call ebtc_dump_ebtables
 * to fetch ebtables information from the kernel and update the fast path
 * information accordingly.
 *
 * Argument list is there only for compatibility with libevent timers.
 * None are actually used.
 */
void cm_ebtc_update_timer(int sock, short evtype, void *data)
{
	ebtc_dump_ebtables();

	/* Reset the timer for next call */
	event_del(ev_ebt_timer);
	evtimer_add(ev_ebt_timer, &tv_ebt_timer);
}
