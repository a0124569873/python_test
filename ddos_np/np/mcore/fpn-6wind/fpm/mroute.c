/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <net/if.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"

/*
 * +---+---+      +---+      +---+
 * |min|   |......|val|......|max|
 * +---+---+      +---+      +---+
 *                  ^
 *                  |
 *         pop<--boot_index-->push
 */
#ifdef CONFIG_MCORE_MULTICAST6
static uint16_t free_entry_stack6[FP_MFC6_COLLISION];
static uint16_t bottom_index6 = FP_MFC6_COLLISION;
#endif

#ifdef CONFIG_MCORE_MULTICAST4
static uint16_t free_entry_stack[FP_MFC_COLLISION];
static uint16_t bottom_index = FP_MFC_COLLISION;
#endif

static int
fpm_mroute_add(const uint8_t *request, const struct cp_hdr *hdr);
static int
fpm_mroute_del(const uint8_t *request, const struct cp_hdr *hdr);

static void fpm_mroute_init(__attribute__((unused)) int graceful)
{
	int i;

	fpm_register_msg(CMD_MCAST_ADD_MFC, fpm_mroute_add, NULL);
	fpm_register_msg(CMD_MCAST_DEL_MFC, fpm_mroute_del, NULL);

#ifdef CONFIG_MCORE_MULTICAST4
	for (i = 0; i < FP_MFC_COLLISION; i++)
		free_entry_stack[i] = FP_MFC_MAX - i;
#endif

#ifdef CONFIG_MCORE_MULTICAST6
	for (i = 0; i < FP_MFC6_COLLISION; i++)
		free_entry_stack6[i] = FP_MFC6_MAX - i;
#endif

	return;
}

#ifdef CONFIG_MCORE_MULTICAST4
static uint16_t pop_free_entry(void)
{
	if (bottom_index == 0)
		return 0;
	return free_entry_stack[--bottom_index];
}

static void push_free_entry(uint16_t id)
{
	free_entry_stack[bottom_index++] = id;
	return;
}

static uint32_t fp_add_mroute4(uint32_t origin, uint32_t mcastgrp, uint32_t iif,
                               uint32_t *oifs)
{
	fp_mfc_entry_t *c = NULL;
	uint16_t line, cur;

	line = FP_MFC_HASH(mcastgrp, origin);
	c = &fp_shared->fp_mfc_table[line];
	/*
	 * If this is a new hash line write all parameters and end with input vif
	 * a free entry must always have input vif and next ptr set to null.
	 */
	if (c->iif == FP_IIF_UNUSED && c->next == FP_NEXT_UNUSED) {
		c->origin = origin;
		c->mcastgrp = mcastgrp;
		memcpy(c->oifs, oifs, sizeof(c->oifs));
		c->iif = iif;
		return 0;
	}

	/*
	 * If a route already exists, it is just a matter of inserting a
	 * new next-hop, else, a full route creation is needed.
	 */
	for (cur = line; cur != FP_NEXT_UNUSED; cur = c->next) {
		c = &fp_shared->fp_mfc_table[cur];
		/* Look for (S,G) with the same upstream */
		if (c->origin == origin &&
		    c->mcastgrp == mcastgrp) {
			/* update the output interface list */
			memcpy(c->oifs, oifs, sizeof(c->oifs));
			c->iif = iif;
			return 0;
		}
	}

	/*
	 * If this was a collision entry go to the last entry, then pop
	 * free entry stack index and set it in next ptr field of previous
	 * lookup entry. Finally fill the new entry and end with input vif.
	 */
	line = pop_free_entry();
	if (!line)
		return 1;
	c->next = line;
	c = &fp_shared->fp_mfc_table[line];
	c->origin = origin;
	c->mcastgrp = mcastgrp;
	memcpy(c->oifs, oifs, sizeof(c->oifs));
	c->iif = iif;

	return 0;
}

static uint32_t fp_del_mroute4(uint32_t origin, uint32_t mcastgrp)
{
	fp_mfc_entry_t *c = NULL, *pre = NULL;
	uint16_t line, next;

	line = FP_MFC_HASH(mcastgrp, origin);
	c = &fp_shared->fp_mfc_table[line];
	next = 1;
	while (next != FP_NEXT_UNUSED) {
		/* Look for (S,G) */
		if (c->origin == origin && c->mcastgrp == mcastgrp)
			break;
		next = c->next;
		if (next != FP_NEXT_UNUSED) {
			pre = c;
			c = &fp_shared->fp_mfc_table[next];
		}
	}

	/* no entry found */
	if (next == FP_NEXT_UNUSED)
		return 0;

	if (c->next == FP_NEXT_UNUSED) {
		/* this is the last entry (next ptr is null) */
		if (pre != NULL) {
			/* if this is a colllision hash line: push index in free entry stack
			 * else this is a base hash line, nothing to do. */
			push_free_entry(pre->next);
			pre->next = FP_NEXT_UNUSED;
		}
		c->iif = FP_IIF_UNUSED;
		c->bytes = 0;
		c->pkt = 0;
	} else {
		/* there is a next entry */
		if (pre == NULL) {
			/* this is the first hash line, copy next entry in this entry, 
			 * ending with input vif. then delete next hash line
			 * (see previous delete process). */
			next = c->next;
			c->origin = fp_shared->fp_mfc_table[next].origin;
			c->mcastgrp = fp_shared->fp_mfc_table[next].mcastgrp;
			c->next = fp_shared->fp_mfc_table[next].next;
			c->iif = fp_shared->fp_mfc_table[next].iif;

			/* delete: first set input vif to null */
			fp_shared->fp_mfc_table[next].iif = FP_IIF_UNUSED;
			fp_shared->fp_mfc_table[next].next = FP_NEXT_UNUSED;
			fp_shared->fp_mfc_table[next].bytes = 0;
			fp_shared->fp_mfc_table[next].pkt = 0;
			push_free_entry(next);
		} else {
			/* If this is a collision hash line, copy next ptr
			 * in previous next ptr entry to relink hash table,
			 * set next ptr of entry to be freed at null then
			 * push the new free index into the free entry stack. */
			next = pre->next;
			c->iif = FP_IIF_UNUSED;
			pre->next = c->next;
			c->next = FP_NEXT_UNUSED;
			c->bytes = 0;
			c->pkt = 0;
			push_free_entry(next);
		}
	}
	return 0;
}
#endif /* CONFIG_MCORE_MULTICAST4 */

#ifdef CONFIG_MCORE_MULTICAST6
static uint16_t pop_free_entry6(void)
{
	if (bottom_index6 == 0)
		return 0;
	return free_entry_stack6[--bottom_index6];
}

static void push_free_entry6(uint16_t id)
{
	free_entry_stack6[bottom_index6++] = id;
	return;
}

static uint32_t fp_add_mroute6(fp_in6_addr_t origin, fp_in6_addr_t mcastgrp, uint32_t iif,
                               uint32_t *oifs)
{
	fp_mfc6_entry_t *c = NULL;
	uint16_t line, cur;

	line = FP_MFC6_HASH(mcastgrp, origin);
	c = &fp_shared->fp_mfc6_table[line];
	/*
	 * If this is a new hash line write all parameters and end with input vif
	 * a free entry must always have input vif and next ptr set to null.
	 */
	if (c->iif == FP_IIF_UNUSED && c->next == FP_NEXT_UNUSED) {
		c->origin = origin;
		c->mcastgrp = mcastgrp;
		memcpy(c->oifs, oifs, sizeof(c->oifs));
		c->iif = iif;
		return 0;
	}

	/*
	 * If a route already exists, it is just a matter of inserting a
	 * new next-hop, else, a full route creation is needed.
	 */
	for (cur = line; cur != FP_NEXT_UNUSED; cur = c->next) {
		c = &fp_shared->fp_mfc6_table[cur];
		/* Look for (S,G) with the same upstream */
		if (is_in6_addr_equal(c->origin, origin) &&
		    is_in6_addr_equal(c->mcastgrp , mcastgrp)) {
			/* update the output interface list */
			memcpy(c->oifs, oifs, sizeof(c->oifs));
			c->iif = iif;
			return 0;
		}
	}

	/*
	 * If this was a collision entry go to the last entry, then pop
	 * free entry stack index and set it in next ptr field of previous
	 * lookup entry. Finally fill the new entry and end with input vif.
	 */
	line = pop_free_entry6();
	if (!line)
		return 1;
	c->next = line;
	c = &fp_shared->fp_mfc6_table[line];
	c->origin = origin;
	c->mcastgrp = mcastgrp;
	memcpy(c->oifs, oifs, sizeof(c->oifs));
	c->iif = iif;

	return 0;
}

static uint32_t fp_del_mroute6(fp_in6_addr_t origin, fp_in6_addr_t mcastgrp)
{
	fp_mfc6_entry_t *c = NULL, *pre = NULL;
	uint16_t line, next;

	line = FP_MFC6_HASH(mcastgrp, origin);
	c = &fp_shared->fp_mfc6_table[line];
	next = 1;
	while (next != FP_NEXT_UNUSED) {
		/* Look for (S,G) */
		if (is_in6_addr_equal(c->origin, origin) &&
		    is_in6_addr_equal(c->mcastgrp, mcastgrp))
			break;
		next = c->next;
		if (next != FP_NEXT_UNUSED) {
			pre = c;
			c = &fp_shared->fp_mfc6_table[next];
		}
	}

	/* no entry found */
	if (next == FP_NEXT_UNUSED)
		return 0;

	if (c->next == FP_NEXT_UNUSED) {
		/* this is the last entry (next ptr is null) */
		if (pre != NULL) {
			/* if this is a colllision hash line: push index in free entry stack
			 * else this is a base hash line, nothing to do. */
			push_free_entry6(pre->next);
			pre->next = FP_NEXT_UNUSED;
		}
		c->iif = FP_IIF_UNUSED;
		c->bytes = 0;
		c->pkt = 0;
	} else {
		/* there is a next entry */
		if (pre == NULL) {
			/* this is the first hash line, copy next entry in this entry, 
			 * ending with input vif. then delete next hash line
			 * (see previous delete process). */
			next = c->next;
			c->origin = fp_shared->fp_mfc6_table[next].origin;
			c->mcastgrp = fp_shared->fp_mfc6_table[next].mcastgrp;
			c->next = fp_shared->fp_mfc6_table[next].next;
			c->iif = fp_shared->fp_mfc6_table[next].iif;

			/* delete: first set input vif to null */
			fp_shared->fp_mfc6_table[next].iif = FP_IIF_UNUSED;
			fp_shared->fp_mfc6_table[next].next = FP_NEXT_UNUSED;
			fp_shared->fp_mfc6_table[next].bytes = 0;
			fp_shared->fp_mfc6_table[next].pkt = 0;
			push_free_entry6(next);
		} else {
			/* If this is a collision hash line, copy next ptr
			 * in previous next ptr entry to relink hash table,
			 * set next ptr of entry to be freed at null then
			 * push the new free index into the free entry stack. */
			next = pre->next;
			c->iif = FP_IIF_UNUSED;
			pre->next = c->next;
			c->next = FP_NEXT_UNUSED;
			c->bytes = 0;
			c->pkt = 0;
			push_free_entry6(next);
		}
	}
	return 0;
}
#endif /* CONFIG_MCORE_MULTICAST6 */

int fpm_mroute_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_mfc_add *req = (struct cp_mfc_add *)request;
	uint16_t i;
	int res;

	FPN_BUILD_BUG_ON(CM_MAXMIFS != FP_MAXVIFS);
	if (req->cpmfc_family == AF_INET) {
#ifdef CONFIG_MCORE_MULTICAST4
		if (f_verbose) {
			syslog(LOG_DEBUG, "%s: (%u.%u.%u.%u, %u.%u.%u.%u) Incoming if 0x%08x\n",
			       __FUNCTION__, FP_NIPQUAD(req->cpmfc_src4.s_addr),
			       FP_NIPQUAD(req->cpmfc_grp4.s_addr), ntohl(req->cpmfc_iif));

			syslog(LOG_DEBUG, "Outgoing if list:");
			for (i = 0; i < CM_MAXMIFS && req->cpmfc_oif[i]; i++)
				syslog(LOG_DEBUG, " 0x%08x", ntohl(req->cpmfc_oif[i]));
			syslog(LOG_DEBUG, "\n");
		}
		res = fp_add_mroute4(req->cpmfc_src4.s_addr, req->cpmfc_grp4.s_addr,
		                     req->cpmfc_iif, req->cpmfc_oif);
		if (res) {
			syslog(LOG_ERR, "%s: failed\n", __FUNCTION__);
			return EXIT_FAILURE;
		}
#endif /* CONFIG_MCORE_MULTICAST4 */
		return EXIT_SUCCESS;
	} else if (req->cpmfc_family == AF_INET6) {
#ifdef CONFIG_MCORE_MULTICAST6
		fp_in6_addr_t src, grp;
		if (f_verbose) {
			syslog(LOG_DEBUG, "%s: (" FP_NIP6_FMT "," FP_NIP6_FMT ") Incoming if 0x%08x\n",
			       __FUNCTION__, NIP6(req->cpmfc_src6),
			       NIP6(req->cpmfc_grp6), ntohl(req->cpmfc_iif));

			syslog(LOG_DEBUG, "Outgoing if list:");
			for (i = 0; i < CM_MAXMIFS && req->cpmfc_oif[i]; i++)
				syslog(LOG_DEBUG, " 0x%08x", ntohl(req->cpmfc_oif[i]));
			syslog(LOG_DEBUG, "\n");
		}
		memcpy(&src, &req->cpmfc_src6, sizeof(src));
		memcpy(&grp, &req->cpmfc_grp6, sizeof(grp));
		res = fp_add_mroute6(src, grp, req->cpmfc_iif, req->cpmfc_oif);
		if (res) {
			syslog(LOG_ERR, "%s: failed\n", __FUNCTION__);
			return EXIT_FAILURE;
		}
#endif /* CONFIG_MCORE_MULTICAST6 */
		return EXIT_SUCCESS;
	} else {
		syslog(LOG_ERR, "%s: invalid family = %d\n", __FUNCTION__, req->cpmfc_family);
		return EXIT_FAILURE;
	}
}

int fpm_mroute_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_mfc_delete *req = (struct cp_mfc_delete *)request;
	int res;

	if (req->cpmfc_family == AF_INET) {
#ifdef CONFIG_MCORE_MULTICAST4
		if (f_verbose)
			syslog(LOG_DEBUG, "%s: (%u.%u.%u.%u, %u.%u.%u.%u)\n",
			       __FUNCTION__, FP_NIPQUAD(req->cpmfc_src4.s_addr),
			       FP_NIPQUAD(req->cpmfc_grp4.s_addr));
		res = fp_del_mroute4(req->cpmfc_src4.s_addr, req->cpmfc_grp4.s_addr);
		if (res) {
			syslog(LOG_ERR, "%s: failed\n", __FUNCTION__);
			return EXIT_FAILURE;
		}
#endif /* CONFIG_MCORE_MULTICAST4 */
		return EXIT_SUCCESS;
	} else if (req->cpmfc_family == AF_INET6) {
#ifdef CONFIG_MCORE_MULTICAST6
		fp_in6_addr_t src, grp;
		if (f_verbose)
			syslog(LOG_DEBUG, "%s: (" FP_NIP6_FMT "," FP_NIP6_FMT ")\n",
			       __FUNCTION__, NIP6(req->cpmfc_src6),
			       NIP6(req->cpmfc_grp6));
		memcpy(&src, &req->cpmfc_src6, sizeof(src));
		memcpy(&grp, &req->cpmfc_grp6, sizeof(grp));
		res = fp_del_mroute6(src, grp);
		if (res) {
			syslog(LOG_ERR, "%s: failed\n", __FUNCTION__);
			return EXIT_FAILURE;
		}
#endif /* CONFIG_MCORE_MULTICAST6 */
		return EXIT_SUCCESS;
	} else {
		syslog(LOG_ERR, "%s: invalid family = %d\n", __FUNCTION__, req->cpmfc_family);
		return EXIT_FAILURE;
	}
}

static struct fpm_mod fpm_mroute_mod = {
	.name = "mroute",
	.init = fpm_mroute_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_mroute_mod);
}
