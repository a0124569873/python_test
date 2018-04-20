/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */

#ifndef __FP_MROUTE_LOOKUP_H__
#define __FP_MROUTE_LOOKUP_H__

#include "fp-track-debug.h"

#ifdef CONFIG_MCORE_MULTICAST4
static inline fp_mfc_entry_t *fp_mfc_lookup(uint32_t origin, uint32_t mcastgrp)
{
	fp_mfc_entry_t *c;
	uint16_t line;
	uint16_t next = FP_NEXT_UNUSED;

	if (origin && mcastgrp) {
		line = FP_MFC_HASH(mcastgrp, origin);
		c = &fp_shared->fp_mfc_table[line];
		next = 1;
		while (next != FP_NEXT_UNUSED) {
			FPN_TRACK();
			if (c->iif != FP_IIF_UNUSED &&
			    c->origin == origin &&
			    c->mcastgrp == mcastgrp)
				return c;
			next = c->next;
			if (next != FP_NEXT_UNUSED)
				c = &fp_shared->fp_mfc_table[next];
		}
	}

	/* If no cache entry has been found, look for a (*,G) entry */
	if (next == FP_NEXT_UNUSED && mcastgrp) {
		line = FP_MFC_HASH(mcastgrp, 0);
		c = &fp_shared->fp_mfc_table[line];
		next = 1;
		while (next != FP_NEXT_UNUSED) {
			FPN_TRACK();
			/* mfc_origin == 0 will match any origin */
			if (c->iif != FP_IIF_UNUSED &&
			    c->origin == 0 &&
			    c->mcastgrp == mcastgrp)
				return c;
			next = c->next;
			if (next != FP_NEXT_UNUSED)
				c = &fp_shared->fp_mfc_table[next];
		}
	}

	/* If no cache entry has been found, look for a (*,*) entry, where */
	/* the vifi is part of the dest list                               */
	if (next == FP_NEXT_UNUSED) {
		line = FP_MFC_HASH(0, 0);
		c = &fp_shared->fp_mfc_table[line];
		next = 1;
		while (next != FP_NEXT_UNUSED) {
			FPN_TRACK();
			/* mfc_origin == 0 will match any origin */
			if (c->iif != FP_IIF_UNUSED &&
			    c->origin == 0 &&
			    c->mcastgrp == 0)
				return c;
			next = c->next;
			if (next != FP_NEXT_UNUSED)
				c = &fp_shared->fp_mfc_table[next];
		}
	}
	return NULL;
}
#endif

#ifdef CONFIG_MCORE_MULTICAST6
static inline fp_mfc6_entry_t *fp_mfc6_lookup(fp_in6_addr_t origin, fp_in6_addr_t mcastgrp)
{
	static fp_in6_addr_t zero_addr =
		{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}};
	fp_mfc6_entry_t *c;
	uint16_t line;
	uint16_t next = FP_NEXT_UNUSED;

	if (!is_in6_addr_null(origin) &&
	    !is_in6_addr_null(mcastgrp)) {
		line = FP_MFC6_HASH(mcastgrp, origin);
		c = &fp_shared->fp_mfc6_table[line];
		next = 1;
		while (next != FP_NEXT_UNUSED) {
			if (c->iif != FP_IIF_UNUSED &&
			    is_in6_addr_equal(c->origin, origin) &&
			    is_in6_addr_equal(c->mcastgrp, mcastgrp))
				return c;
			next = c->next;
			if (next != FP_NEXT_UNUSED)
				c = &fp_shared->fp_mfc6_table[next];
		}
	}

	/* If no cache entry has been found, look for a (*,G) entry */
	if (next == FP_NEXT_UNUSED && !is_in6_addr_null(mcastgrp)) {
		line = FP_MFC6_HASH(mcastgrp, zero_addr);
		c = &fp_shared->fp_mfc6_table[line];
		next = 1;
		while (next != FP_NEXT_UNUSED) {
			/* mfc_origin == 0 will match any origin */
			if (c->iif != FP_IIF_UNUSED &&
			    is_in6_addr_null(c->origin) &&
			    is_in6_addr_equal(c->mcastgrp, mcastgrp))
				return c;
			next = c->next;
			if (next != FP_NEXT_UNUSED)
				c = &fp_shared->fp_mfc6_table[next];
		}
	}

	/* If no cache entry has been found, look for a (*,*) entry, where */
	/* the vifi is part of the dest list                               */
	if (next == FP_NEXT_UNUSED) {
		line = FP_MFC6_HASH(zero_addr, zero_addr);
		c = &fp_shared->fp_mfc6_table[line];
		next = 1;
		while (next != FP_NEXT_UNUSED) {
			/* mfc_origin == 0 will match any origin */
			if (c->iif != FP_IIF_UNUSED &&
			    is_in6_addr_null(c->origin) &&
			    is_in6_addr_null(c->mcastgrp))
				return c;
			next = c->next;
			if (next != FP_NEXT_UNUSED)
				c = &fp_shared->fp_mfc6_table[next];
		}
	}
	return NULL;
}
#endif

#endif /* __FP_MROUTE_LOOKUP_H__ */
