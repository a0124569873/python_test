/*
 * Copyright(c) 2012 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-ipsec-common.h"
#include "fp-ipsec-replay.h"
#include "fp-ipsec-lookup.h"
#ifdef CONFIG_MCORE_IPSEC_IPV6
#include "fp-ipsec6-lookup.h"
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
#include "fp-fpib.h"
#endif

#ifdef CONFIG_MCORE_MULTIBLADE
void ipsec_sa_sync(fp_sa_entry_t *sa)
{
	struct mbuf *m;
	struct fp_ether_header *ether;
	struct fptunhdr *fptun;
	struct fp_replaywin_msg *replay;
	int lastbladeid;
	int bladeid;
	uint32_t bmp_len = (sa->replay.wsize + 31)/32;

	m = m_alloc();
	if (m == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Alloc mbuf failed");
		return;
	}

	ether = (struct fp_ether_header*) m_prepend(m,
			   sizeof(struct fp_ether_header)
			 + sizeof(struct fptunhdr)
			 + sizeof(struct fp_replaywin_msg)
			 + sizeof(uint32_t)*bmp_len);
	if (ether == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Prepend fptun header to mbuf failed");
		m_freem(m);
		return;
	}

	ether->ether_type = htons(ETH_P_FPTUN);

	fptun = (struct fptunhdr *)(ether + 1);
	fptun->fptun_cmd      = FPTUN_IPV4_REPLAYWIN;
	fptun->fptun_exc_class= FPTUN_EXC_REPLAYWIN;
	fptun->fptun_mtags    = 0;
	fptun->fptun_version  = FPTUN_VERSION;
	fptun->fptun_vrfid    = htons(sa->vrfid);
	fptun->fptun_proto    = sa->proto;
	fptun->fptun_blade_id = 0;
	fptun->fptun_ifuid    = 0;

	replay = (struct fp_replaywin_msg *)(fptun + 1);
	replay->dst    = sa->dst4;
	replay->spi    = sa->spi;
	replay->proto  = sa->proto;
	replay->vrfid  = htonl(sa->vrfid);
	replay->oseq = htonll(sa->replay.oseq);
	replay->seq = htonll(sa->replay.seq);
	replay->bmp_len = htonl(bmp_len);
	memcpy(replay->bmp, sa->replay.bmp, bmp_len*sizeof(uint32_t));

	/* XXX use broadcast */
	for (lastbladeid = 0, bladeid = 1; bladeid <= FP_BLADEID_MAX; bladeid++) {
		struct mbuf *newm;
		if (fp_shared->fp_blade_id == bladeid)
			continue;
		if (!fp_shared->fp_blades[bladeid].blade_active)
			continue;

		if (lastbladeid == 0) {
			lastbladeid = bladeid;
		} else {
			TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPsec replay sync message to blade %d, oseq 0x%"PRIx64", seq 0x%"PRIx64"",
					lastbladeid, sa->replay.oseq, sa->replay.seq);
			fptun->fptun_blade_id = lastbladeid;
			newm = m_dup(m);
			if (fp_fpib_forward(newm, lastbladeid) == FP_DROP)
				m_freem(newm);
			lastbladeid = bladeid;
		}
	}

	if (lastbladeid == 0) {
		m_freem(m);
	} else {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPsec replay sync message to blade %d", lastbladeid);
		fptun->fptun_blade_id = lastbladeid;
		if (fp_fpib_forward(m, lastbladeid) == FP_DROP)
			m_freem(m);
	}
}

void ipsec_replaywin_get_send(struct mbuf *mbuf)
{
	struct fp_ether_header *ether;
	struct fptunhdr *fptun;
	fp_replaywin_sync_header_t *sync_hdr;
	int bladeid, lastbladeid;
	uint16_t replay_msg_count;

	replay_msg_count = m_len(mbuf) / sizeof(uint32_t);
	ether = (struct fp_ether_header *) m_prepend(mbuf,
			  sizeof(struct fp_ether_header)
			+ sizeof(struct fptunhdr)
			+ sizeof(fp_replaywin_sync_header_t));
	if (ether == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Prepend fptun header to mbuf failed");
		return;
	}
	ether->ether_type = htons(ETH_P_FPTUN);

	fptun = (struct fptunhdr *)(ether + 1);
	fptun->fptun_cmd      = FPTUN_IPV4_REPLAYWIN_GET;
	fptun->fptun_exc_class= FPTUN_EXC_REPLAYWIN;
	fptun->fptun_mtags    = 0;
	fptun->fptun_version  = FPTUN_VERSION;
	fptun->fptun_vrfid    = 0;
	fptun->fptun_proto    = 0;
	fptun->fptun_blade_id = 0;
	fptun->fptun_ifuid     = 0;

	sync_hdr = (fp_replaywin_sync_header_t *)(fptun + 1);
	sync_hdr->src_blade_id  = fp_shared->fp_blade_id;
	sync_hdr->version       = 1;
	sync_hdr->request_count = replay_msg_count;

	/* forward the whole sync request msg to other blades */
	for (lastbladeid = 0, bladeid = 1; bladeid <= FP_BLADEID_MAX; bladeid++) {
		struct mbuf *newm;
		if (fp_shared->fp_blade_id == bladeid)
			continue;
		if (!fp_shared->fp_blades[bladeid].blade_active)
			continue;

		if (lastbladeid == 0) {
			lastbladeid = bladeid;
		} else {
			TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPsec replay sync get message to blade %d", lastbladeid);
			fptun->fptun_blade_id = lastbladeid;
			newm = m_dup(mbuf);
			if (fp_fpib_forward(newm, lastbladeid) == FP_DROP) {
				TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "failed to send replay sync get message to blade %d", lastbladeid);
				m_freem(newm);
			}
			lastbladeid = bladeid;
		}
	}

	if (lastbladeid == 0) {
		m_freem(mbuf);
	} else {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPsec replay sync get message to blade %d", lastbladeid);
		fptun->fptun_blade_id = lastbladeid;
		if (fp_fpib_forward(mbuf, lastbladeid) == FP_DROP)
			m_freem(mbuf);
	}
}

void ipsec_replaywin_reply_send(struct mbuf *mbuf, uint8_t bladeid, uint16_t count)
{
	struct mbuf *m;
	struct fp_ether_header *ether;
	struct fptunhdr *fptun;
	fp_replaywin_sync_header_t *sync_hdr;
	uint32_t sync_msg;
	uint32_t *request;
	fp_replaywin_msg_t *replay;
	fp_sa_entry_t *sa;
	uint16_t i, missing_count = 0;
	int msg_size = sizeof(uint32_t);
	int offset = 0;
	fp_sad_t *sad = fp_get_sad();
	uint32_t bmp_len;

	m = m_alloc();
	if (m == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Alloc mbuf failed");
		return;
	}

	ether = (struct fp_ether_header *) m_prepend(m,
			  sizeof(struct fp_ether_header)
			+ sizeof(struct fptunhdr)
			+ sizeof(fp_replaywin_sync_header_t));

	if (ether == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Prepend fptun header to mbuf failed");
		m_freem(m);
		return;
	}

	ether->ether_type = htons(ETH_P_FPTUN);

	fptun = (struct fptunhdr *)(ether + 1);
	fptun->fptun_cmd      = FPTUN_IPV4_REPLAYWIN_REPLY;
	fptun->fptun_exc_class= FPTUN_EXC_REPLAYWIN;
	fptun->fptun_mtags    = 0;
	fptun->fptun_version  = FPTUN_VERSION;
	fptun->fptun_vrfid    = 0;
	fptun->fptun_proto    = 0;
	fptun->fptun_blade_id = bladeid;
	fptun->fptun_ifuid    = 0;

	sync_hdr = (fp_replaywin_sync_header_t *)(fptun + 1);
	sync_hdr->src_blade_id  = fp_shared->fp_blade_id;
	sync_hdr->version       = 1;
	sync_hdr->request_count = count;

	if (likely(m_is_contiguous(mbuf)))
		request = mtod(mbuf, uint32_t *);
	else
		request = &sync_msg;

	for (i = 0; i < count; i++) {
		if (unlikely(!m_is_contiguous(mbuf))) {
			m_copytobuf(request, mbuf, offset, msg_size);
			offset += msg_size;
		}

		if (*request >= FP_MAX_SA_ENTRIES ||
		    sad->table[*request].state == FP_SA_STATE_UNSPEC) {
			/* SA not found, ignore the replay window msg */
			TRACE_IPSEC_REPLAY(FP_LOG_NOTICE, "SA with index %d not found",
					   ntohl(*request));
			missing_count++;
			if (likely(m_is_contiguous(mbuf)))
				request++;
			continue;
		}

		sa = &sad->table[*request];

		bmp_len = (sa->replay.wsize + 31)/32;
		replay = (fp_replaywin_msg_t *) m_append(m,
					 sizeof(fp_replaywin_msg_t) + bmp_len*sizeof(uint32_t));
		if (replay == NULL) {
			TRACE_IPSEC_REPLAY(FP_LOG_NOTICE, "Append fp_replaywin_msg to mbuf failed");
			missing_count += count - i;
			break;
		}
		/* SA found, build replay window reply */
		replay->dst    = sa->dst4;
		replay->spi    = sa->spi;
		replay->proto  = sa->proto;
		replay->vrfid  = htonl(sa->vrfid);
		replay->oseq   = htonll(sa->replay.oseq);
		replay->seq   = htonll(sa->replay.seq);
		replay->bmp_len = htonl(bmp_len);
		memcpy(replay->bmp, sa->replay.bmp, bmp_len*sizeof(uint32_t));

		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG,"oseq=0x%"PRIx64",seq=0x%"PRIx64"",
					sa->replay.oseq, sa->replay.seq);
		if (likely(m_is_contiguous(mbuf)))
			request++;

	}
	/* No SA found, no need to send the reply msg */
	if (missing_count == count) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "None of the requested SAs found in the local fastpath");
		m_freem(m);
		return;
	}
	/* trim the space not used in mbuf */
	if (missing_count)
		sync_hdr->request_count -= missing_count;

	/* send the reply window msg back */ 
	if (fp_fpib_forward(m, bladeid) == FP_DROP) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Failed to send replay sync message to blade %d", bladeid);
		m_freem(m);
	}

}

#ifdef CONFIG_MCORE_IPSEC_IPV6
void ipsec6_sa_sync(fp_v6_sa_entry_t *sa)
{
	struct mbuf *m;
	struct fp_ether_header *ether;
	struct fptunhdr *fptun;
	struct fp_replaywin6_msg *replay;
	int lastbladeid;
	int bladeid;
	uint32_t bmp_len = (sa->replay.wsize + 31)/32;

	m = m_alloc();
	ether = (struct fp_ether_header*) m_prepend(m,
			  sizeof(struct fp_ether_header)
			+ sizeof(struct fptunhdr)
			+ sizeof(struct fp_replaywin6_msg)
			+ bmp_len*sizeof(uint32_t));

	if (ether == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Prepend fptun head to mbuf fail");
		m_freem(m);
		return;
	}

	ether->ether_type = htons(ETH_P_FPTUN);

	fptun = (struct fptunhdr *)(ether + 1);
	fptun->fptun_cmd      = FPTUN_IPV6_REPLAYWIN;
	fptun->fptun_exc_class= FPTUN_EXC_REPLAYWIN;
	fptun->fptun_mtags    = 0;
	fptun->fptun_version  = FPTUN_VERSION;
	fptun->fptun_vrfid    = htons(sa->vrfid);
	fptun->fptun_proto    = sa->proto;
	fptun->fptun_blade_id = 0;
	fptun->fptun_ifuid    = 0;

	replay = (struct fp_replaywin6_msg *)(fptun + 1);
	replay->dst    = sa->dst6;
	replay->spi    = sa->spi;
	replay->proto  = sa->proto;
	replay->vrfid  = htonl(sa->vrfid);
	replay->oseq = htonll(sa->replay.oseq);
	replay->seq = htonll(sa->replay.seq);
	replay->bmp_len = htonl(bmp_len);
	memcpy(replay->bmp, sa->replay.bmp, bmp_len*sizeof(uint32_t));

	/* XXX use broadcast */
	for (lastbladeid = 0, bladeid = 1; bladeid <= FP_BLADEID_MAX; bladeid++) {
		struct mbuf *newm;
		if (fp_shared->fp_blade_id == bladeid)
			continue;
		if (!fp_shared->fp_blades[bladeid].blade_active)
			continue;

		if (lastbladeid == 0) {
			lastbladeid = bladeid;
		} else {
			TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPv6 IPsec replay sync message to blade %d", lastbladeid);
			fptun->fptun_blade_id = lastbladeid;
			newm = m_dup(m);
			if (fp_fpib_forward(newm, lastbladeid) == FP_DROP)
				m_freem(newm);
			lastbladeid = bladeid;
		}
	}

	if (lastbladeid == 0) {
		m_freem(m);
	} else {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPv6 IPsec replay sync message to blade %d", lastbladeid);
		fptun->fptun_blade_id = lastbladeid;
		if (fp_fpib_forward(m, lastbladeid) == FP_DROP)
			m_freem(m);
	}
}

void ipsec6_replaywin_get_send(struct mbuf *mbuf)
{
	struct fp_ether_header *ether;
	struct fptunhdr *fptun;
	fp_replaywin_sync_header_t *sync_hdr;
	int bladeid, lastbladeid;
	uint16_t replay_msg_count;

	replay_msg_count = m_len(mbuf) / sizeof(uint32_t);
	ether = (struct fp_ether_header*) m_prepend(mbuf,
				  sizeof(struct fp_ether_header)
				+ sizeof(struct fptunhdr)
				+ sizeof(fp_replaywin_sync_header_t));

	if (ether == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Prepend fptun head to mbuf fail");
		return;
	}

	ether->ether_type = htons(ETH_P_FPTUN);

	fptun = (struct fptunhdr *)(ether + 1);
	fptun->fptun_cmd      = FPTUN_IPV6_REPLAYWIN_GET;
	fptun->fptun_exc_class= FPTUN_EXC_REPLAYWIN;
	fptun->fptun_mtags    = 0;
	fptun->fptun_version  = FPTUN_VERSION;
	fptun->fptun_vrfid    = 0;
	fptun->fptun_proto    = 0;
	fptun->fptun_blade_id = 0;
	fptun->fptun_ifuid    = 0;

	sync_hdr = (fp_replaywin_sync_header_t *)(fptun + 1);
	sync_hdr->src_blade_id  = fp_shared->fp_blade_id;
	sync_hdr->version       = 1;
	sync_hdr->request_count = replay_msg_count;

	/* forward the whole sync requet msg to other blades */
	for (lastbladeid = 0, bladeid = 1; bladeid <= FP_BLADEID_MAX; bladeid++) {
		struct mbuf *newm;
		if (fp_shared->fp_blade_id == bladeid)
			continue;
		if (!fp_shared->fp_blades[bladeid].blade_active)
			continue;

		if (lastbladeid == 0) {
			lastbladeid = bladeid;
		} else {
			TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPsec replay sync get message to blade %d", lastbladeid);
			fptun->fptun_blade_id = lastbladeid;
			newm = m_dup(mbuf);
			if (fp_fpib_forward(newm, lastbladeid) == FP_DROP) {
				TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "failed to send replay sync get message to blade %d", lastbladeid);
				m_freem(newm);
			}
			lastbladeid = bladeid;
		}
	}

	if (lastbladeid == 0) {
		m_freem(mbuf);
	} else {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "send IPsec replay sync get message to blade %d", lastbladeid);
		fptun->fptun_blade_id = lastbladeid;
		if (fp_fpib_forward(mbuf, lastbladeid) == FP_DROP)
			m_freem(mbuf);
	}
}

void ipsec6_replaywin_reply_send(struct mbuf *mbuf, uint8_t bladeid, uint16_t count)
{
	struct mbuf *m;
	struct fp_ether_header *ether;
	struct fptunhdr *fptun;
	fp_replaywin_sync_header_t *sync_hdr;
	uint32_t sync_msg;
	uint32_t *request;
	fp_replaywin6_msg_t *replay;
	fp_v6_sa_entry_t *sa;
	uint16_t i, missing_count = 0;
	int msg_size = sizeof(uint32_t);
	int offset = 0;
	fp_sad6_t *sad = fp_get_sad6();
	uint32_t bmp_len;

	m = m_alloc();
	if (m == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Alloc  mbuf fail");
		return;
	}

	ether = (struct fp_ether_header*) m_prepend(m,
			  sizeof(struct fp_ether_header)
			+ sizeof(struct fptunhdr)
			+ sizeof(fp_replaywin_sync_header_t));

	if (ether == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "Prepend fptun head to mbuf fail");
		m_freem(m);
		return;
	}
	ether->ether_type = htons(ETH_P_FPTUN);

	fptun = (struct fptunhdr *)(ether + 1);
	fptun->fptun_cmd      = FPTUN_IPV6_REPLAYWIN_REPLY;
	fptun->fptun_exc_class= FPTUN_EXC_REPLAYWIN;
	fptun->fptun_mtags    = 0;
	fptun->fptun_version  = FPTUN_VERSION;
	fptun->fptun_vrfid    = 0;
	fptun->fptun_proto    = 0;
	fptun->fptun_blade_id = bladeid;
	fptun->fptun_ifuid    = 0;

	sync_hdr = (fp_replaywin_sync_header_t *)(fptun + 1);
	sync_hdr->src_blade_id  = fp_shared->fp_blade_id;
	sync_hdr->version       = 1;
	sync_hdr->request_count = count;

	replay = (fp_replaywin6_msg_t *) m_append(m,
				 count * sizeof(fp_replaywin6_msg_t));
	if (replay == NULL) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "failed to append %d fp_replaywin6_msg to mbuf", count);
		m_freem(m);
		return;
	}

	if (likely(m_is_contiguous(mbuf))) 
		request = mtod(mbuf, uint32_t *);
	else
		request = &sync_msg;

	for (i = 0; i < count; i++) {

		if (unlikely(!m_is_contiguous(mbuf))) { 
			m_copytobuf(request, mbuf, offset, msg_size);
			offset += msg_size;
		}

		if (*request >= FP_MAX_IPV6_SP_ENTRIES ||
		    sad->table[*request].state == FP_SA_STATE_UNSPEC) {
			/* SA not found, ignore the replay window msg */
			TRACE_IPSEC_REPLAY(FP_LOG_NOTICE, "SA with index %d not found",
					   ntohl(*request));
			missing_count++;
			if (likely(m_is_contiguous(mbuf)))
				request++;
			continue;
		}

		sa = &sad->table[*request];

		bmp_len = (sa->replay.wsize + 31)/32;
		replay = (fp_replaywin6_msg_t *) m_append(m,
					 sizeof(fp_replaywin6_msg_t) + bmp_len*sizeof(uint32_t));
		if (replay == NULL) {
			TRACE_IPSEC_REPLAY(FP_LOG_NOTICE, "failed to append fp_replaywin_msg to mbuf");
			missing_count += count -i;
			break;
		}
		/* SA found */
		replay->dst    = sa->dst6;
		replay->spi    = sa->spi;
		replay->proto  = sa->proto;
		replay->vrfid  = htonl(sa->vrfid);
		replay->oseq   = htonll(sa->replay.oseq);
		replay->seq   = htonll(sa->replay.seq);
		replay->bmp_len = htonl(bmp_len);
		memcpy(replay->bmp, sa->replay.bmp, bmp_len*sizeof(uint32_t));

		if (likely(m_is_contiguous(mbuf))) 
			request++;
	}
	/* No SA found, no need to send the reply msg */
	if (missing_count == count) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "None of the requested SAs found in the local fastpath");
		m_freem(m);
		return;
	}
	/* trim the space not used in mbuf */
	if (missing_count) {
		m_trim(m, missing_count * sizeof (fp_replaywin6_msg_t));
		sync_hdr->request_count -= missing_count;
	}

	/* send the reply window msg back */ 
	if (fp_fpib_forward(m, bladeid) == FP_DROP) {
		TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "failed to send replay sync message to blade %d", bladeid);
		m_freem(m);
	}
}
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */

void ipsec_mergereplay(fp_replaywin_msg_t *msg, uint32_t sa_index)
{
	uint64_t i, oseq, seq;
	uint32_t bitnr, nr;
	fpn_spinlock_t *lock;
	struct secreplay *replay;
	uint32_t bmp_len;
	fp_sad_t *sad = fp_get_sad();
	fp_sa_entry_t *sa = &sad->table[sa_index];

	oseq = ntohll(msg->oseq);
	seq = ntohll(msg->seq);

	replay = &sa->replay;
	lock = &sa_ctx[sa_index].lock;

	fpn_spinlock_lock(lock);

	TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "begin sa info oseq=0x%"PRIx64",seq=0x%"PRIx64"",
			replay->oseq, replay->seq);
	bmp_len = (replay->wsize + 31)/32;

	if (oseq > replay->oseq)
		replay->oseq = oseq;

	if (replay->wsize == 0) {
		fpn_spinlock_unlock(lock);
		return;
	}

	/* remote seqnum greater than old one */
	if (seq > replay->seq) {
		if (seq - replay->seq < replay->wsize) {
			for (i = replay->seq; i < seq - 1; i++) {
				bitnr = i % replay->wsize;
				nr = bitnr >> 5;
				bitnr = bitnr & 0x1F;
				replay->bmp[nr] &=  ~(1U << bitnr);
			}
			for (i = 0; i < bmp_len; i++)
				replay->bmp[i] |= msg->bmp[i];
		} else
			memcpy(replay->bmp, msg->bmp, bmp_len*sizeof(uint32_t));

		replay->seq = seq;
		goto end;
	}

	/* remote seqnum lower than old one */
	if (replay->seq - seq < replay->wsize) {
		if (replay->seq != seq)
			for (i = seq; i < replay->seq - 1; i++) {
				bitnr = i % replay->wsize;
				nr = bitnr >> 5;
				bitnr = bitnr & 0x1F;
				msg->bmp[nr] &=  ~(1U << bitnr);
			}
		for (i = 0; i < bmp_len; i++)
			replay->bmp[i] |= msg->bmp[i];
	}

end:
	TRACE_IPSEC_REPLAY(FP_LOG_DEBUG, "end sa info oseq=0x%"PRIx64",seq=0x%"PRIx64"",
			replay->oseq, replay->seq);

	sa->sync_state = FP_SA_STATE_SYNC_RECVD;
	fpn_spinlock_unlock(lock);
}

void ipsec_replaywin_reply_recv(struct mbuf *mbuf, uint16_t count)
{
	fp_replaywin_msg_t  *replay;
	fp_sad_t *sad = fp_get_sad();
	uint32_t sa_index;
	struct {
		fp_replaywin_msg_t msg;
		uint32_t bmp[FP_SECREPLAY_ESN_WORDS];
	}sync_msg;
	int i;
	int offset = 0;

	if (likely(m_is_contiguous(mbuf)))
		replay = mtod(mbuf, fp_replaywin_msg_t *);
	else
		replay = (fp_replaywin_msg_t *)&sync_msg;

	for (i = 0; i < count; i++) {
		if (unlikely(!m_is_contiguous(mbuf))) {
			fp_replaywin_msg_t *tmp =
				(fp_replaywin_msg_t *)(mtod(mbuf, char*) + offset);
			int msg_size =
				sizeof(fp_replaywin_msg_t) + sizeof(uint32_t)*ntohl(tmp->bmp_len);
			m_copytobuf(replay, mbuf, offset, msg_size);
			offset += msg_size;
		}

		sa_index = __fp_sa_get(sad, replay->spi, replay->dst, replay->proto, ntohl(replay->vrfid));
		if (sa_index == 0) {
			/* SA not found, just ignore it */
			TRACE_IPSEC_REPLAY(FP_LOG_NOTICE, "FPTUN unknown SA spi 0x%08x",
						ntohl(replay->spi));
			if (likely(m_is_contiguous(mbuf)))
				replay = (fp_replaywin_msg_t *)
					((char *)replay + sizeof(fp_replaywin_msg_t) + ntohl(replay->bmp_len)*sizeof(uint32_t));
			continue;
		}
		/* SA found, sync the replay information */
		ipsec_mergereplay(replay, sa_index);
		if (likely(m_is_contiguous(mbuf)))
			replay = (fp_replaywin_msg_t *)
				((char *)replay + sizeof(fp_replaywin_msg_t) + ntohl(replay->bmp_len)*sizeof(uint32_t));
	}
}

#ifdef CONFIG_MCORE_IPSEC_IPV6
void ipsec6_mergereplay(fp_replaywin6_msg_t *msg, uint32_t sa_index)
{
	uint64_t i, oseq, seq;
	uint32_t bitnr, nr;
	fpn_spinlock_t *lock;
	struct secreplay *replay;
	uint32_t bmp_len;
	fp_sad6_t *sad = fp_get_sad6();
	fp_v6_sa_entry_t *sa = &sad->table[sa_index];

	oseq = ntohll(msg->oseq);
	seq = ntohll(msg->seq);

	replay = &sa->replay;
	lock = &sa6_ctx[sa_index].lock;

	fpn_spinlock_lock(lock);

	if (oseq > replay->oseq)
		replay->oseq = oseq;

	/* replay check disabled : stop here */
	if (replay->wsize == 0) {
		fpn_spinlock_unlock(lock);
		return;
	}

	bmp_len = (replay->wsize + 31)/32;
	/* remote seqnum greater than old one */
	if (seq > replay->seq) {
		if (seq - replay->seq < replay->wsize) {
			for (i = replay->seq; i < seq - 1; i++) {
				bitnr = i % replay->wsize;
				nr = bitnr >> 5;
				bitnr = bitnr & 0x1F;
				replay->bmp[nr] &=  ~(1U << bitnr);
			}
			for (i = 0; i < bmp_len; i++)
				replay->bmp[i] |= msg->bmp[i];
		} else
			memcpy(replay->bmp, msg->bmp, bmp_len*sizeof(uint32_t));

		replay->seq = seq;
		goto end;
	}

	/* remote seqnum lower than old one */
	if (replay->seq - seq < replay->wsize) {
		if (replay->seq != seq)
			for (i = seq; i < replay->seq - 1; i++) {
				bitnr = i % replay->wsize;
				nr = bitnr >> 5;
				bitnr = bitnr & 0x1F;
				msg->bmp[nr] &=  ~(1U << bitnr);
			}
		for (i = 0; i < bmp_len; i++)
			replay->bmp[i] |= msg->bmp[i];
	}
end:
	sa->sync_state = FP_SA_STATE_SYNC_RECVD;
	fpn_spinlock_unlock(lock);
}

void ipsec6_replaywin_reply_recv(struct mbuf *mbuf, uint16_t count)
{
	fp_replaywin6_msg_t  *replay;
	struct {
		fp_replaywin6_msg_t msg;
		uint32_t bmp[FP_SECREPLAY_ESN_WORDS];
	}sync_msg;
	fp_sad6_t *sad = fp_get_sad6();
	uint32_t sa_index;
	int i;
	int msg_size = sizeof(fp_replaywin6_msg_t);
	int offset = 0;

	if (likely(m_is_contiguous(mbuf)))
		replay = mtod(mbuf, fp_replaywin6_msg_t *);
	else
		replay = (fp_replaywin6_msg_t *)&sync_msg;

	for (i = 0; i < count; i++) {
		if (unlikely(!m_is_contiguous(mbuf))) {
			fp_replaywin6_msg_t *tmp =
				(fp_replaywin6_msg_t *)(mtod(mbuf, char*) + offset);
			int msg_size =
				sizeof(fp_replaywin6_msg_t) + ntohl(tmp->bmp_len)*sizeof(uint32_t);
			m_copytobuf(replay, mbuf, offset, msg_size);
			offset += msg_size;
		}

		sa_index = __fp_v6_sa_get(sad, replay->spi, (uint8_t *)replay->dst.fp_s6_addr, replay->proto, ntohl(replay->vrfid));
		/* SA not found, just ignore it */
		if (sa_index == 0) {
			TRACE_IPSEC_REPLAY(FP_LOG_NOTICE, "FPTUN unknown SA spi 0x%08x",
					ntohl(replay->spi));
			if (likely(m_is_contiguous(mbuf)))
				replay = (fp_replaywin6_msg_t *)
					((char *)replay + msg_size + ntohl(replay->bmp_len)*sizeof(uint32_t));
			continue;
		}

		/* SA found, sync the SA */
		ipsec6_mergereplay(replay, sa_index);

		if (likely(m_is_contiguous(mbuf)))
			replay = (fp_replaywin6_msg_t *)
				((char *)replay + msg_size + ntohl(replay->bmp_len)*sizeof(uint32_t));
	}
}
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */
#endif	/* CONFIG_MCORE_MULTIBLADE */
