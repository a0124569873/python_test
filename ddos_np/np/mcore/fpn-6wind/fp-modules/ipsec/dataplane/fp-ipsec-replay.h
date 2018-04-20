/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FP_IPSEC_REPLAY_H__
#define __FP_IPSEC_REPLAY_H__

#include "fpn.h"
#include "fp-var.h"
#include "fp-log.h"

#define TRACE_IPSEC_REPLAY(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC_REPL, "%s():" fmt "\n",		\
		       __FUNCTION__, ## args);				\
} while(0)

#ifdef CONFIG_MCORE_MULTIBLADE
void ipsec_sa_sync(fp_sa_entry_t *sa);
void ipsec_replaywin_get_send(struct mbuf *mbuf);
void ipsec_replaywin_reply_send(struct mbuf *mbuf, uint8_t bladeid, uint16_t count);
void ipsec_mergereplay(struct fp_replaywin_msg *msg, uint32_t sa_index);
void ipsec_replaywin_reply_recv(struct mbuf *mbuf, uint16_t count);
#ifdef CONFIG_MCORE_IPSEC_IPV6
void ipsec6_sa_sync(fp_v6_sa_entry_t *sa);
void ipsec6_replaywin_get_send(struct mbuf *mbuf);
void ipsec6_replaywin_reply_send(struct mbuf *mbuf, uint8_t bladeid, uint16_t count);
void ipsec6_mergereplay(struct fp_replaywin6_msg *msg, uint32_t sa_index);
void ipsec6_replaywin_reply_recv(struct mbuf *mbuf, uint16_t count);
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */
#endif /* CONFIG_MCORE_MULTIBLADE */

/*
 * Check and update anti-replay window and sequence number.
 * Seql:    incoming sequence number in ah/esp header.
 * replay:  anti-replay structure in sa.
 * index:   index in sa_ctx[]/sa6_ctx[].
 * is_ipv6: 1 stands for IPv6, 0 stands for IPv4.
 * update:  0 performs replay check before ICV verification.
 *          1 performs replay check and updates bitmap after ICV verification.
 * Seqh:    if not null, return high 32bit of sequence number.
 *
 * 0 is returned if packet allowed.
 * 1 if packet is not permitted.
 *
 * based on RFC 2401.
 * ESN part on RFC 4303 paragraph A.2.2.
 */
static inline int ipsec_chk_update_replay(uint32_t Seql,
					void *sa,
					struct secreplay *replay,
					uint32_t index,
					int esn,
					int is_ipv6,
					int update,
					uint32_t *Seqh)
{
	fpn_spinlock_t *lock;
	uint64_t Seq, T;
	uint32_t W, bitnr, nr, ret = 1;
	uint32_t bmp_len = (replay->wsize + 31)/32;
#ifdef CONFIG_MCORE_MULTIBLADE
	int send = 0;
#endif

	TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "");
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (is_ipv6)
		lock = &sa6_ctx[index].lock;
	else
#endif
		lock = &sa_ctx[index].lock;
	fpn_spinlock_lock(lock);

	W = replay->wsize;
	T = replay->seq;
	if (!esn) {
		/* sequence number of 0 is invalid if ESN flag is not set */
		if (!Seql)
			goto fail;
		Seq = (uint64_t)Seql;
	} else {
		uint32_t Th = (uint32_t)(T >> 32);
		uint32_t Tl = (uint32_t)T;

		/*
		 * Case A: Tl >= (W - 1). In this case,  the window is within
		 *                        one sequence number subspace.
		 *
		 * Th+1                        *********
		 * Th              ======******
		 *      --0--------+-----+-----0--------+-----------0--
		 *                Bl      Tl            Bl
		 *                                 (Bl+2^32) mod 2^32
		 *
		 * Case B: Tl < (W - 1). In this case, the window spans
		 *                       two sequence number subspaces.
		 *
		 * Th                          ===***************
		 * Th-1                     ===
		 *      --0-----------------+--0--+--------------+--0--
		 *                          Bl    Tl            Bl
		 *                                          (Bl+2^32) mod 2^32
		 */

		/*
		 * Under Case A: If Seql <  Bl (where Bl = Tl - W + 1),
		 *               then Seqh = Th + 1
		 */
		if ((Tl >= W - 1) && (Seql < Tl - W + 1)) {
			Seq = (((uint64_t)(Th + 1)) << 32) + Seql;
			if (Seqh)
				*Seqh = Th + 1;
		/*
		 * Under Case B: If Seql >= Bl (where Bl = Tl - W + 1),
		 *               then Seqh = Th - 1
		 */
		} else if ((Tl < W - 1) && (Seql >= Tl - W + 1)) {
			if (Th == 0)
				goto fail;

			Seq = (((uint64_t)(Th - 1)) << 32) + Seql;
			if (Seqh)
				*Seqh = Th - 1;
		}
		/*
		 * Under Case A: If Seql >= Bl (where Bl = Tl - W + 1),
		 *               then Seqh = Th
		 * Under Case B: If Seql <  Bl (where Bl = Tl - W + 1),
		 *               then Seqh = Th
		 */
		else {
			Seq = ((uint64_t)Th << 32) + Seql;
			if (Seqh)
				*Seqh = Th;
		}
	}

	if (Seq > T) {
		if (!update)
			goto pass;

		/*
		 * (Seq - T) bits are dropped from the low end of the window.
		 * (Seq - T) bits are added to the high end of the window.
		 * The new bits between T and the top bit are set to indicate that
		 * no packets with those sequence numbers have been received yet.
		 */
		if (Seq - T >= W)
			memset(replay->bmp, 0, bmp_len*sizeof(uint32_t));
		else
			for (uint64_t i = T; i < Seq - 1; i++) {
				bitnr = i % W;
				nr = bitnr >> 5;
				bitnr = bitnr & 0x1F;
				replay->bmp[nr] &= ~(1U << bitnr);
			}

		/*
		 * The top bit is set to indicate that a packet with that sequence
		 * number has been received and authenticated.
		 */
		bitnr = (Seq - 1) % W;
		nr = bitnr >> 5;
		bitnr = bitnr & 0x1F;
		replay->bmp[nr] |= (1U << bitnr);

		/* T is set to the new sequence number. */
		replay->seq = Seq;
	} else if (T - Seq <= W - 1){
		/*
		 * check the corresponding bit in the window to see if
		 * this Seql has already been seen.  If yes, reject the packet.
		 */
		bitnr = (Seq - 1) % W;
		nr = bitnr >> 5;
		bitnr = bitnr & 0x1F;
		if (replay->bmp[nr] & (1U << bitnr))
			goto fail;

		/* If no, set the corresponding bit */
		if (update)
			replay->bmp[nr] |= (1U << bitnr);
	} else
		/* If outside of the window, reject the packet. */
		goto fail;

pass:
	ret = 0;

#ifdef CONFIG_MCORE_MULTIBLADE
	if (++replay->last_sync >= fp_shared->ipsec.sa_replay_sync_threshold) {
		replay->last_sync = 0;
		send = 1;
	}
#endif

fail:
	fpn_spinlock_unlock(lock);

#ifdef CONFIG_MCORE_MULTIBLADE
	if (send) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "sync IPsec replay window");
#ifdef CONFIG_MCORE_IPSEC_IPV6
		if (is_ipv6)
			ipsec6_sa_sync(sa);
		else
#endif
			ipsec_sa_sync(sa);
	}
#endif
	return ret;
}

static inline int ipsec_chk_max_oseq(struct secreplay *replay, int esn)
{
	if (esn)
		return (replay->oseq == ~(uint64_t)0);
	return (replay->oseq >= ~(uint32_t)0);
}

#if defined(CONFIG_MCORE_FPE_VFP)
/*
 * increment an SA output sequence number atomically
 * on architectures without complex fpn_atomic64_t types
 * (use a lock instead)
 *
 * replay:  anti-replay structure in sa
 * index:   index in sa_ctx[]/sa6_ctx[]
 * is_ipv6: 1 stands for IPv6, 0 stands for IPv4
 *
 * return sequence number(uint64_t)
 */
static inline uint64_t ipsec_inc_oseq(struct secreplay *replay, uint32_t index, int is_ipv6)
{
	fpn_spinlock_t *lock;
	uint64_t oseq;

	TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "");
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (is_ipv6)
		lock = &sa6_ctx[index].lock;
	else
#endif
		lock = &sa_ctx[index].lock;
	fpn_spinlock_lock(lock);

	oseq = ++replay->oseq;

	fpn_spinlock_unlock(lock);

	return oseq;
}
#else
/*
 * increment an SA output sequence number atomically
 * on architectures where an uint64_t can be casted to an fpn_atomic64_t
 *
 * replay:  anti-replay structure in sa
 *
 * return sequence number(uint64_t)
 */
static inline uint64_t ipsec_inc_oseq(struct secreplay *replay)
{
	fpn_atomic64_t *p;

	TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "");

	p = (void *)&replay->oseq;
	return fpn_atomic_add_return64(p, 1);
}
#endif
#endif
