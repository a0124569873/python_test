/*-
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)bpf_filter.c	8.1 (Berkeley) 6/10/93
 *
 * Copyright(c) 2008 6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-bpf_filter.h"
#include "fp-log.h"
#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
#include "shmem/fpn-shmem.h"
#include "fp-tap-capture.h"
#endif

#define TRACE_BPF(level, fmt, args...) do {			\
		FP_LOG(level, TAP, fmt "\n", ## args);		\
} while(0)

#ifndef  CONFIG_MCORE_ARCH_X86
#define BPF_ALIGN
#endif

#ifndef BPF_ALIGN
#define EXTRACT_SHORT(p)	((uint16_t)ntohs(*(uint16_t *)p))
#define EXTRACT_LONG(p)		(ntohl(*(uint32_t *)p))
#else
#define EXTRACT_SHORT(p)\
	((uint16_t)\
		((uint16_t)*((u_char *)p+0)<<8|\
		 (uint16_t)*((u_char *)p+1)<<0))
#define EXTRACT_LONG(p)\
		((uint32_t)*((u_char *)p+0)<<24|\
		 (uint32_t)*((u_char *)p+1)<<16|\
		 (uint32_t)*((u_char *)p+2)<<8|\
		 (uint32_t)*((u_char *)p+3)<<0)
#endif


/*
 * Execute the filter program starting at pc on the packet p
 * wirelen is the length of the original packet
 * buflen is the amount of data present
 */
#define FP_BPF_CHECK_LEN(test, size) \
	do { \
		if (test) { \
			if (m_copytobuf(buffer, m, k, size) != size) \
				return (0); \
			data = buffer; \
		} else \
			if (unlikely((data = m_off(m, k, u_char *)) == NULL)) \
				return (0); \
	} while(0)
static u_int
fp_bpf_filter(struct mbuf *m, fp_filter_t *filter, u_int wirelen, u_int buflen)
{
	fp_filter_t *pc = &filter[0];	
	uint32_t A = 0, X = 0;
	bpf_u_int32 k;
	uint32_t mem[BPF_MEMWORDS];
	u_char *data, buffer[sizeof(int32_t)];

	--pc;
	while (1) {
		FPN_TRACK();
		++pc;
		switch (pc->code) {
		default:
			return (0);
		case BPF_RET|BPF_K:
			return ((u_int)pc->k);

		case BPF_RET|BPF_A:
			return ((u_int)A);

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			FP_BPF_CHECK_LEN(k > buflen || sizeof(int32_t) > buflen - k, sizeof(int32_t));
#ifdef BPF_ALIGN
			if (((fpn_uintptr_t)data & 3) != 0)
				A = EXTRACT_LONG(data);
			else
#endif
				A = ntohl(*(int32_t *)data);
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			FP_BPF_CHECK_LEN(k > buflen || sizeof(int16_t) > buflen - k, sizeof(int16_t));
			A = EXTRACT_SHORT(data);
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
			FP_BPF_CHECK_LEN(k >= buflen, sizeof(u_char));
			A = *data;
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			FP_BPF_CHECK_LEN(pc->k > buflen ||
			                 X > buflen - pc->k ||
			                 sizeof(int32_t) > buflen - k,
					 sizeof(int32_t));
#ifdef BPF_ALIGN
			if (((fpn_uintptr_t)data & 3) != 0)
				A = EXTRACT_LONG(data);
			else
#endif
				A = ntohl(*(int32_t *)data);
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			FP_BPF_CHECK_LEN(X > buflen ||
			                 pc->k > buflen - X ||
			                 sizeof(int16_t) > buflen - k,
					 sizeof(int16_t));
			A = EXTRACT_SHORT(data);
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			FP_BPF_CHECK_LEN(pc->k >= buflen ||
			                 X >= buflen - pc->k,
					 sizeof(u_char));
			A = *data;
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			FP_BPF_CHECK_LEN(k >= buflen, sizeof(u_char));
			X = (*data & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;

		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += (A >= pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += (A == pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;

		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;

		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;

		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return (0);
			A /= X;
			continue;

		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;

		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;

		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;

		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;

		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;

		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;

		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			A = -A;
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}
#undef FP_BPF_CHECK_LEN

#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
static FPN_DEFINE_SHARED(struct fp_tap_pkt *, fp_circ_buf);
static FPN_DEFINE_SHARED(fpn_spinlock_t, fp_cap_lock);

static inline void fp_circular_capture(struct mbuf *m)
{
	struct fp_tap_pkt *pkt;
	uint64_t pkt_total_size;
	static uint32_t cookie = 0xA0A0;


	/* map pkt shared memory */
	if (fp_shared->cap_cookie != cookie) {
		uint64_t size = fp_shared->cap_buf_size;

		fp_circ_buf = fpn_shmem_mmap(CAP_SHM_NAME, NULL, size);
		if (fp_circ_buf == NULL) {
			TRACE_BPF(FP_LOG_DEBUG, "failed mapping %s of size %lu\n",
				  CAP_SHM_NAME, size);
			return;
		}
		cookie = fp_shared->cap_cookie;
	}

	/* get the size of a packet */
	pkt_total_size = sizeof(struct fp_tap_pkt) + fp_shared->cap_pkt_len;

	fpn_spinlock_lock(&fp_cap_lock);

	/* get the pointer to the packet */
	if (fp_shared->cap_buf_offset + pkt_total_size < fp_shared->cap_buf_size) {
		pkt = (struct fp_tap_pkt *) ((char *) fp_circ_buf +
					     fp_shared->cap_buf_offset);
	}
	/* if offset is out of buffer bounds, only wrap if mode is "circular" */
	else if (fp_shared->cap_wrap == 1) {
		pkt = (struct fp_tap_pkt *) fp_circ_buf;
		fp_shared->cap_buf_offset = 0;
	}
	else
		pkt = NULL;

	fp_shared->cap_buf_offset += pkt_total_size;
	fpn_spinlock_unlock(&fp_cap_lock);

	if (pkt != NULL) {
		pkt->timestamp = fpn_get_clock_cycles();
		m_copytobuf(pkt->data, m, 0, fp_shared->cap_pkt_len);
		pkt->pkt_len = m_len(m);
	}
}
#endif

void fp_bpf_filter_input(struct mbuf *m, fp_ifnet_t *ifp, int proto)
{
	fp_bpf_filter_t *bpf, *base;
	int i, ret;

	TRACE_BPF(FP_LOG_DEBUG, "ifuid is 0x%08x", ntohl(ifp->if_ifuid));
	base = fp_ifnet2bpf(ifp);
again:
	for (i = 0; i < FP_BPF_MAXINSTANCE; i++) {
		FPN_TRACK();
		bpf = &base[i];

		if (unlikely(!bpf->num))
			continue;

		ret = fp_bpf_filter(m, bpf->filters, m_len(m), m_headlen(m));
		TRACE_BPF(FP_LOG_DEBUG, "BPF filter (instance: %u) returns %d", i, ret);
		if (unlikely(ret == 0))
			continue;

#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
		if (unlikely(fp_shared->conf.w32.do_func & FP_CONF_DO_TAP_CIRC_BUF))
			fp_circular_capture(m);
		else
#endif
			fp_prepare_tap_exception(m, ifp, proto);
		return;
	}

	/* Check entry 0, which is used for interface 'any' */
	if ((void *)base != (void *)&fp_shared->fp_bpf_filters[0]) {
		FPN_TRACK();
		base = fp_shared->fp_bpf_filters[0];
		goto again;
	}
}

void fp_bpf_init(void)
{
	uint32_t idx, i;

	for (idx = 0; idx < FP_MAX_IFNET; idx++)
		for (i = 0; i < FP_BPF_MAXINSTANCE; i++)
			fp_shared->fp_bpf_filters[idx][i].num = 0;
#ifdef CONFIG_MCORE_TAP_CIRCULAR_BUFFER
	fpn_spinlock_init(&fp_cap_lock);
	fp_shared->cap_buf_size = 0;
	fp_shared->cap_pkt_len = 0;
#endif
}
