/*
 * Copyright (C) 2011 6WIND, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* 6WIND_GPL */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/types.h>
#include <linux/spinlock.h>

#include <linux/cdev.h>

#include <linux/netfilter/nfnetlink_conntrack.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/fpm-nfct.h>
#ifdef CONFIG_MCORE_NF_CT_CPEID
#include <net/netfilter/nf_nat_lsn.h>
#endif

#include <linux/jhash.h>

#include "fp.h"
#include "fp-nfct.h"
#include "fp-netfilter.h"
#include "shmem/fpn-shmem.h"

/* free room lock initialization */
static u32 next_ct_available = 0;

DEFINE_SPINLOCK(fpm_free_room_lock);

/* hash table locks initialization */
#define FP_NF_CT_LOCK_CACHE_ORDER 20
#define FP_NF_CT_LOCK_TABLE_SIZE  (1 << FP_NF_CT_LOCK_CACHE_ORDER)
#define FP_NF_CT_LOCK_TABLE_MASK  (FP_NF_CT_LOCK_TABLE_SIZE - 1)

static spinlock_t fpm_nfct_lock_table[FP_NF_CT_LOCK_TABLE_SIZE];

static int fpm_nfct_do_del(struct fp_nfct_entry *nfct, u32 fp_nfct_index, u8 cpe_del);

static inline spinlock_t *fpm_nfct_get_lock_from_hash(u32 hash)
{
	return &fpm_nfct_lock_table[(hash & FP_NF_CT_LOCK_TABLE_MASK)];
}

#ifdef CONFIG_MCORE_NF_CT_CPEID
static spinlock_t fpm_nfct_cpelock_table[FP_NF_CT_LOCK_TABLE_SIZE];

static inline spinlock_t *fpm_nfct_get_cpelock_from_hash(u32 hash)
{
	return &fpm_nfct_cpelock_table[(hash & FP_NF_CT_LOCK_TABLE_MASK)];
}
#endif

/*
 * Access to shared memory of the Fast Path running on the local blade.
 * Used in co-localized role and in distributed fp bladerole.
 * Board-specific mappings.
 */
shared_mem_t *fp_shared;

static void __init local_fp_shared_mem_map(void)
{
	fp_shared = fpn_shmem_mmap("fp-shared", NULL, sizeof(shared_mem_t));
}

/* Dump function for debug */
#if 0
static void fpm_nfct_print(struct fp_nfct_entry *nfct, u32 index)
{
	printk("#%d/#%08x", index, ntohl(nfct->uid));
	printk("\t%u ",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);
	printk("\t" FP_NIPQUAD_FMT ":%u -> " FP_NIPQUAD_FMT ":%u ",
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport),
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport));
	printk("| " FP_NIPQUAD_FMT ":%u -> " FP_NIPQUAD_FMT ":%u",
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport),
		      FP_NIPQUAD(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst),
		      ntohs(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport));
#ifdef CONFIG_MCORE_VRF
	printk("\tVR%u",
		      nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid);
#endif
	printk("\t%s%s%s%s%s\n",
	       nfct->flag & FP_NFCT_FLAG_UPDATE ? " [HIT]" : "",
	       nfct->flag & FP_NFCT_FLAG_SNAT ? " [SNAT]" : "",
	       nfct->flag & FP_NFCT_FLAG_DNAT ? " [DNAT]" : "",
	       nfct->flag & FP_NFCT_FLAG_ASSURED ? " [ASSURED]" : "",
	       nfct->flag & FP_NFCT_FLAG_END ? " [END]" : "");
}
#endif

/* XXX: find a way to share this code */
void fpm_nfct_init_shm(void)
{
	u32 i;

	memset(&fp_shared->fp_nf_ct, 0, sizeof(fp_shared->fp_nf_ct));
	/* The hash_next starting value is supposed to be 'undefined', represented by FP_NF_CT_MAX */
	for (i = 0; i < FP_NF_CT_MAX; i++) {
		fp_shared->fp_nf_ct.fp_nfct[i].tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
		fp_shared->fp_nf_ct.fp_nfct[i].tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
		fp_shared->fp_nf_ct.fp_nfct[i].next_available = i+1;
#ifdef CONFIG_MCORE_NF_CT_CPEID
		fp_shared->fp_nf_ct.fp_nfct[i].hash_next_cpeid = FP_NF_CT_MAX;
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[i], FP_NF_CT_MAX);
#endif
	}
	/* The algorithm supposes that hash table is initialized to FP_NF_CT_MAX for all entries */
	for (i = 0; i < FP_NF_CT_HASH_SIZE; i++)
		fp_shared->fp_nf_ct.fp_nfct_hash[i].s.index = FP_NF_CT_MAX;

#ifdef CONFIG_MCORE_NF_CT_CPEID
	for (i = 0; i < FP_NF_CT_HASH_CPEID_SIZE; i++)
		fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[i] = FP_NF_CT_MAX;
#endif
}

/* XXX: find a way to share code for hash add/del function */
/* Add index to hash table, and manage collisions */
static inline void fpm_nfct_add_hash(uint32_t hash, union fp_nfct_tuple_id id)
{
	fp_nfct_id_to_tuple(id)->hash_next.u32 = fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32;
	fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32 = id.u32;
}

/* Del index from hash table, and manage collisions */
static inline void fpm_nfct_del_hash(uint32_t hash, struct fp_nfct_tuple_h *tuple)
{
	union fp_nfct_tuple_id next;
	struct fp_nfct_tuple_h *prev;

	if (fp_shared->fp_nf_ct.fp_nfct_hash[hash].s.index != FP_NF_CT_MAX)
		prev = fp_nfct_id_to_tuple(fp_shared->fp_nf_ct.fp_nfct_hash[hash]);
	else
		return;
	next = tuple->hash_next;

	/* Remove in head */
	if (prev == tuple) {
		fp_shared->fp_nf_ct.fp_nfct_hash[hash].u32 = next.u32;
		return;
	}

	/* Look for the element just before the one pointed by index */
	while (prev->hash_next.s.index != FP_NF_CT_MAX && fp_nfct_id_to_tuple(prev->hash_next) != tuple)
		prev = fp_nfct_id_to_tuple(prev->hash_next);

	/* Remove index from chaining */
	if (prev->hash_next.s.index != FP_NF_CT_MAX)
		prev->hash_next.u32 = next.u32;
}

#ifdef CONFIG_MCORE_NF_CT_CPEID
/* Add index to cpeid hash table and manage collisions */
static inline void fpm_nfct_add_hash_cpeid(uint32_t hash, uint32_t index)
{
	uint32_t next;

	next = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash];
	fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash] = index;

	fp_shared->fp_nf_ct.fp_nfct[index].hash_next_cpeid = next;
	/* Set prev index to invalid value (add is done in head) */
	FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[index],
				     FP_NF_CT_MAX);

	/*
	 * Update prev index of the next element to new element index
	 * only if our element is not the only one.
	 */
	if (next < FP_NF_CT_MAX)
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[next], index);
}

/* Del index from hash table, and manage collisions */
static void fpm_nfct_del_hash_cpeid(uint32_t hash, uint32_t index)
{
	uint32_t next, prev;

	prev = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash];
	next = fp_shared->fp_nf_ct.fp_nfct[index].hash_next_cpeid;

	/* Remove in head */
	if (prev == index) {
		fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash] = next;
		/* Update prev index of the next if it exists */
		if (next < FP_NF_CT_MAX)
			FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[next], FP_NF_CT_MAX);
		return;
	}

	/* Get the element just before the one pointed by index */
	prev = FP_NF_CT_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[index]);

	/* Remove index from chaining */
	fp_shared->fp_nf_ct.fp_nfct[prev].hash_next_cpeid = next;
	/* Update prev idnex of the next if it exists */
	if (next < FP_NF_CT_MAX)
		FP_NF_CT_SET_HASH_PREV_CPEID(fp_shared->fp_nf_ct.fp_nfct[next], prev);
}
#endif


/* Flush function */

static void __fpm_nfct_flush(void)
{
	u32 fp_nfct_index;

	for (fp_nfct_index = 0; fp_nfct_index < FP_NF_CT_MAX ; fp_nfct_index++) {
		struct fp_nfct_entry *nfct = &(fp_shared->fp_nf_ct.fp_nfct[fp_nfct_index]);

		/* conntrack is not valid anymore, return */
		if (!(nfct->flag & FP_NFCT_FLAG_VALID))
			continue;

		fpm_nfct_do_del(nfct, fp_nfct_index, 1);
	}
}

static void fpm_nfct_flush(void)
{
	__fpm_nfct_flush();
}


/* Add function */

static int __fpm_nfct_add(struct nf_conn *ct)
{
	struct nf_conntrack_tuple *orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	struct nf_conntrack_tuple *reply = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	struct fp_nfct_entry *nfct;
	union fp_nfct_tuple_id id = { .u32 = 0 };
	u32 hash, hash_reply;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	u32 hash_cpeid = 0;
#endif
	u32 i = 0;
	u16 vrfid = 0;
	spinlock_t *lock;

#ifdef CONFIG_MCORE_VRF
	vrfid = orig->dst.vrfid & FP_VRFID_MASK;
#endif

	if (ct->fp_nfct_index != (u_int32_t)-1) {
		nfct = &(fp_shared->fp_nf_ct.fp_nfct[ct->fp_nfct_index]);
		if ((ct->status & IPS_ASSURED))
			nfct->flag |= FP_NFCT_FLAG_ASSURED;
		return 0;
	}

	/* get free room, if no, get out */
	spin_lock_bh(&fpm_free_room_lock);
	if (fp_shared->fp_nf_ct.fp_nfct_count == FP_NF_CT_MAX) {
		spin_unlock_bh(&fpm_free_room_lock);
		if (net_ratelimit())
			printk("%s: table is full\n", __func__);
		return -1;
	}
	i = next_ct_available;
	id.s.index = i;
	nfct = &(fp_shared->fp_nf_ct.fp_nfct[i]);
	next_ct_available = nfct->next_available;
	fp_shared->fp_nf_ct.fp_nfct_count++;
	spin_unlock_bh(&fpm_free_room_lock);

	ct->fp_nfct_index = i;

	/* copy useful fields */
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src = orig->src.u3.ip;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst = orig->dst.u3.ip;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport = orig->src.u.all;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport = orig->dst.u.all;
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto = orig->dst.protonum;
#ifdef CONFIG_MCORE_VRF
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid = vrfid;
#endif
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dir = FP_NF_IP_CT_DIR_ORIGINAL;

	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src = reply->src.u3.ip;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst = reply->dst.u3.ip;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport = reply->src.u.all;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport = reply->dst.u.all;
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto = reply->dst.protonum;
#ifdef CONFIG_MCORE_VRF
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].vrfid = vrfid;
#endif
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dir = FP_NF_IP_CT_DIR_REPLY;
	nfct->uid = htonl(ct->uid);

	if ((ct->status & IPS_SRC_NAT))
		nfct->flag |= FP_NFCT_FLAG_SNAT;
	if ((ct->status & IPS_DST_NAT))
		nfct->flag |= FP_NFCT_FLAG_DNAT;
	if ((ct->status & IPS_ASSURED))
		nfct->flag |= FP_NFCT_FLAG_ASSURED;

	/* hash tables */
	hash = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
			    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
			    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
			    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
			    vrfid, nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);

	hash_reply = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
				  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
				  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
				  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
				  vrfid, nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

#ifdef CONFIG_MCORE_NF_CT_CPEID
	if (ct->status & IPS_FROM_CPE_BIT)
		nfct->flag |= FP_NFCT_FLAG_FROM_CPE;
	if (ct->status & IPS_TO_CPE_BIT)
		nfct->flag |= FP_NFCT_FLAG_TO_CPE;
#endif

	/* last step: mark the entry as valid */
	nfct->flag |= FP_NFCT_FLAG_VALID;

	/* add to the hash table */
	lock = fpm_nfct_get_lock_from_hash(hash);
	id.s.dir = FP_NF_IP_CT_DIR_ORIGINAL;
	spin_lock_bh(lock);
	fpm_nfct_add_hash(hash, id);
	spin_unlock_bh(lock);

	lock = fpm_nfct_get_lock_from_hash(hash_reply);
	id.s.dir = FP_NF_IP_CT_DIR_REPLY;
	spin_lock_bh(lock);
	fpm_nfct_add_hash(hash_reply, id);
	spin_unlock_bh(lock);

#ifdef CONFIG_MCORE_NF_CT_CPEID
	/* If we have both flags, we use FROM_CPE to recognize the conntrack */
	if (ct->status & IPS_FROM_CPE_BIT) {
		hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src);
		lock = fpm_nfct_get_cpelock_from_hash(hash_cpeid);
		spin_lock_bh(lock);
		fpm_nfct_add_hash_cpeid(hash_cpeid, i);
		spin_unlock_bh(lock);
	} else if (ct->status & IPS_TO_CPE_BIT) {
		hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src);
		lock = fpm_nfct_get_cpelock_from_hash(hash_cpeid);
		spin_lock_bh(lock);
		fpm_nfct_add_hash_cpeid(hash_cpeid, i);
		spin_unlock_bh(lock);
	}
#endif

	/* for debug, print element */
	/* fpm_nfct_print(&fp_shared->fp_nf_ct.fp_nfct[i], i); */

	/* success */
	return 0;
}

static void fpm_nfct_add(struct nf_conn *ct)
{
	unsigned long status = ct->status;

	/* filter the same way as we do in cache manager */
	/* nat conntracks */
	if ((status & IPS_NAT_MASK)) {
		if ((status & IPS_CONFIRMED) &&
		    (nf_ct_protonum(ct) == IPPROTO_TCP ||
		     nf_ct_protonum(ct) == IPPROTO_UDP ||
		     nf_ct_protonum(ct) == IPPROTO_ESP ||
		     nf_ct_protonum(ct) == IPPROTO_AH)) {
			__fpm_nfct_add(ct);
		}
	} else {
	/* stateful filtering conntracks */
		if (((status & IPS_SEEN_REPLY) && (status & IPS_ASSURED)) &&
		    (nf_ct_protonum(ct) == IPPROTO_TCP ||
		     nf_ct_protonum(ct) == IPPROTO_UDP ||
		     nf_ct_protonum(ct) == IPPROTO_SCTP ||
		     nf_ct_protonum(ct) == IPPROTO_GRE ||
		     nf_ct_protonum(ct) == IPPROTO_ESP ||
		     nf_ct_protonum(ct) == IPPROTO_AH)) {
			__fpm_nfct_add(ct);
		}
	}
}


/* Del function */

static int fpm_nfct_do_del(struct fp_nfct_entry *nfct, u32 fp_nfct_index, u8 cpe_del)
{
	u32 hash, hash_reply;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	u32 hash_cpeid;
	uint8_t flags = 0;
#endif
	u16 vrfid = 0;
	spinlock_t *lock;

#ifdef CONFIG_MCORE_NF_CT_CPEID
	flags = nfct->flag;
#endif
	/* invalidate entry */
	nfct->flag = 0;

#ifdef CONFIG_MCORE_VRF
	vrfid = nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].vrfid;
#endif

	/* calculate the hash tables */
	hash = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src,
			    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dst,
			    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].sport,
			    nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].dport,
			    vrfid, nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].proto);

	hash_reply = fp_nfct_hash(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src,
				  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dst,
				  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].sport,
				  nfct->tuple[FP_NF_IP_CT_DIR_REPLY].dport,
				  vrfid, nfct->tuple[FP_NF_IP_CT_DIR_REPLY].proto);

	/* remove from hash tables */
	lock = fpm_nfct_get_lock_from_hash(hash);
	spin_lock_bh(lock);
	fpm_nfct_del_hash(hash, &nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL]);
	nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].hash_next.s.index = FP_NF_CT_MAX;
	spin_unlock_bh(lock);

	lock = fpm_nfct_get_lock_from_hash(hash_reply);
	spin_lock_bh(lock);
	fpm_nfct_del_hash(hash_reply, &nfct->tuple[FP_NF_IP_CT_DIR_REPLY]);
	nfct->tuple[FP_NF_IP_CT_DIR_REPLY].hash_next.s.index = FP_NF_CT_MAX;
	spin_unlock_bh(lock);

	memset(nfct->counters, 0, sizeof(nfct->counters));

	if (!cpe_del)
		goto skip_cpe;

#ifdef CONFIG_MCORE_NF_CT_CPEID
	/* If we have both flags, we use FROM_CPE to recognize the conntrack */
	if (flags & FP_NFCT_FLAG_FROM_CPE) {
		hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src);
		lock = fpm_nfct_get_cpelock_from_hash(hash_cpeid);
		spin_lock_bh(lock);
		fpm_nfct_del_hash_cpeid(hash_cpeid, fp_nfct_index);
		nfct->hash_next_cpeid = FP_NF_CT_MAX;
		spin_unlock_bh(lock);
	} else if (flags & FP_NFCT_FLAG_TO_CPE) {
		hash_cpeid = fp_nfct_hash_cpeid(nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src);
		lock = fpm_nfct_get_cpelock_from_hash(hash_cpeid);
		spin_lock_bh(lock);
		fpm_nfct_del_hash_cpeid(hash_cpeid, fp_nfct_index);
		nfct->hash_next_cpeid = FP_NF_CT_MAX;
		spin_unlock_bh(lock);
	}
#endif

skip_cpe:
	/* free room */
	spin_lock_bh(&fpm_free_room_lock);
	fp_shared->fp_nf_ct.fp_nfct_count--;
	nfct->next_available = next_ct_available;
	next_ct_available = fp_nfct_index;
	spin_unlock_bh(&fpm_free_room_lock);

	return 0;
}

static int __fpm_nfct_del(struct nf_conn *ct)
{
	struct fp_nfct_entry *nfct = NULL;

	/* conntrack was not added in fastpath, return */
	if (ct->fp_nfct_index == (u_int32_t)-1)
		return -1;

	nfct = &(fp_shared->fp_nf_ct.fp_nfct[ct->fp_nfct_index]);

	/* conntrack is not valid anymore, return */
	if (!(nfct->flag & FP_NFCT_FLAG_VALID))
		return -1;

	return fpm_nfct_do_del(nfct, ct->fp_nfct_index, 1);
}

static void fpm_nfct_del(struct nf_conn *ct)
{
	__fpm_nfct_del(ct);
}

#if 0
static void fpm_nfct_dump_nfct(int count)
{
	int i;
	for (i = 0; i < FP_NF_CT_MAX && count > 0; i++, count--) {
		if (fp_shared->fp_nf_ct.fp_nfct[i].flag & FP_NFCT_FLAG_VALID)
			fpm_nfct_print(&fp_shared->fp_nf_ct.fp_nfct[i], i);
	}
}
#endif

int fpm_nfct_conntrack_event(unsigned int type, struct nf_conn *ct)
{
	if (type == IPCTNL_MSG_CT_DELETE) {
		if (!ct)
			fpm_nfct_flush();
		else
			fpm_nfct_del(ct);
	} else if (type == IPCTNL_MSG_CT_NEW)
		fpm_nfct_add(ct);

	return 0;
}
EXPORT_SYMBOL(fpm_nfct_conntrack_event);

#ifdef CONFIG_MCORE_NF_CT_CPEID
static int fpm_nfct_compare_bycpe(const struct nf_nat_lsn_cpe *cpe, const struct fp_nfct_entry *nfct)
{
	if ((nfct->flag & FP_NFCT_FLAG_FROM_CPE) &&
	    ((uint32_t)(cpe->cpehash.ipaddr) == nfct->tuple[FP_NF_IP_CT_DIR_ORIGINAL].src))
		return 0;
	if ((nfct->flag & FP_NFCT_FLAG_TO_CPE) &&
	    ((cpe->cpehash.ipaddr) == nfct->tuple[FP_NF_IP_CT_DIR_REPLY].src))
		return 0;
	return 1;
}

int fpm_nfct_flush_bycpe(const struct nf_nat_lsn_cpe *cpe)
{
	uint32_t hash_cpeid;
	uint32_t fp_nfct_index;
	struct fp_nfct_entry *nfct;
	spinlock_t *cpe_lock;

	hash_cpeid = fp_nfct_hash_cpeid((uint32_t)(cpe->cpehash.ipaddr));
	cpe_lock = fpm_nfct_get_cpelock_from_hash(hash_cpeid);
	spin_lock_bh(cpe_lock);
	fp_nfct_index = fp_shared->fp_nf_ct.fp_nfct_hash_cpeid[hash_cpeid];

	while (fp_nfct_index < FP_NF_CT_MAX) {
		nfct = &fp_shared->fp_nf_ct.fp_nfct[fp_nfct_index];

		if (!(nfct->flag & FP_NFCT_FLAG_VALID) ||
		    fpm_nfct_compare_bycpe(cpe, nfct)) {
			fp_nfct_index = nfct->hash_next_cpeid;
			continue;
		}

		fpm_nfct_do_del(nfct, fp_nfct_index, 0);

		fpm_nfct_del_hash_cpeid(hash_cpeid, fp_nfct_index);
		fp_nfct_index = nfct->hash_next_cpeid;
		nfct->hash_next_cpeid = FP_NF_CT_MAX;
	}
	spin_unlock_bh(cpe_lock);

	return 0;
}

int fpm_cpe_conntrack_event(unsigned int type, struct nf_nat_lsn_cpe *cpe)
{
	if (type == NF_LSN_CPE_DEL)
		fpm_nfct_flush_bycpe(cpe);
	return 0;
}
EXPORT_SYMBOL(fpm_cpe_conntrack_event);
#endif

static int __init fpm_nfct_init(void)
{
	int i;

	printk(KERN_INFO "%s\n", __FUNCTION__);
	/* release shared mem */
	local_fp_shared_mem_map();

	/* locks init */
	for (i = 0; i < FP_NF_CT_LOCK_TABLE_SIZE; i++)
		spin_lock_init(&fpm_nfct_lock_table[i]);
#ifdef CONFIG_MCORE_NF_CT_CPEID
	for (i = 0; i < FP_NF_CT_LOCK_TABLE_SIZE; i++)
		spin_lock_init(&fpm_nfct_cpelock_table[i]);
#endif
	spin_lock_init(&fpm_free_room_lock);

	/* re-init nfct shared mem */
	fpm_nfct_init_shm();

	/* register this module functions */
	fpm_nfct_event_register(fpm_nfct_conntrack_event);
#ifdef CONFIG_MCORE_NF_CT_CPEID
	fpm_cpe_event_register(fpm_cpe_conntrack_event);
#endif
#if 0
	fpm_nfct_dump_nfct(10);
#endif

	return 0;
}

static void __exit fpm_nfct_exit(void)
{
	/* unregister module functions */
	fpm_nfct_event_register(fpm_nfct_null_hdlr);
#ifdef CONFIG_MCORE_NF_CT_CPEID
	fpm_cpe_event_register(fpm_cpe_null_hdlr);
#endif

	printk(KERN_INFO "%s\n", __FUNCTION__);
}

module_init(fpm_nfct_init);
module_exit(fpm_nfct_exit);

MODULE_DESCRIPTION("FPM-NFCT");
MODULE_LICENSE("GPL");
