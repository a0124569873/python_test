/*
 * Copyright  2011-2013 6WIND S.A.
 */

/**
 * Netfilter mark specific header
 *
 * Source code including this header must define two constant befort include:
 *   KT_NFMARK_MASK_WIDTH
 *   KT_NFMARK_SHIFT
 */

#ifndef _NFMARK_H
#define _NFMARK_H

#ifdef __FastPath__
#include <fp-mbuf-mtag.h>
#endif

/*
 * KT_NFMARK_WIDTH and KT_NFMARK_SHIFT can be defined in the source code,
 * prior inclusion of this header
 */
#ifndef KT_NFMARK_WIDTH
#define KT_NFMARK_WIDTH 3 /* default value */
#endif
#ifndef KT_NFMARK_SHIFT
#define KT_NFMARK_SHIFT 0 /* default value */
#endif

#define KT_NFMARK_UNSHIFT_MASK ((1 << KT_NFMARK_WIDTH) - 1)
#define KT_NFMARK_MASK (KT_NFMARK_UNSHIFT_MASK << KT_NFMARK_SHIFT)

#ifdef __LinuxKernelVNB__

#if defined(HAVE_KTABLES)
#define ng_get_kt_ptr(table) kt_get_table_ptr(table)
#endif

/*
 * Be warn that skb->mark is in host byte order, and _mark, in m_tag, is
 * in network byte order
 */
#define ng_pkt_get_mark(skb) ((skb->mark & KT_NFMARK_MASK) >>	\
				KT_NFMARK_SHIFT)
#define ng_pkt_set_mark(skb, value) do {				\
		skb->mark = (skb->mark & ~KT_NFMARK_MASK) |		\
			((value & KT_NFMARK_UNSHIFT_MASK) << KT_NFMARK_SHIFT );\
	} while (0)

#elif defined(__FastPath__)
#if defined(HAVE_KTABLES)
#define ng_get_kt_ptr(table) fp_shared->ktables[table]

#if !defined(CONFIG_MCORE_M_TAG)
#error "CONFIG_MCORE_M_TAG is needed"
#endif /*CONFIG_MCORE_M_TAG*/

#endif /*HAVE_KTABLES*/

#if defined(CONFIG_MCORE_M_TAG)
#define NFM_TAG_NAME "nfm"
VNB_DECLARE_SHARED(int32_t, vnb_nfm_tag_type);

static inline int ng_pkt_mark_init(const char * func)
{
	vnb_nfm_tag_type = m_tag_type_register(NFM_TAG_NAME);
	if (vnb_nfm_tag_type < 0) {
		log(LOG_ERR, "VNB: %s failed (register mtag)\n", func);
		return EINVAL;
	}
	return 0;
}

static inline int ng_pkt_get_mark(struct mbuf *m)
{
	uint32_t _mark = 0;

	m_tag_get(m, vnb_nfm_tag_type, &_mark);

	return ((ntohl(_mark) & KT_NFMARK_MASK) >> KT_NFMARK_SHIFT);
}

static inline void ng_pkt_set_mark(struct mbuf *m, uint32_t value)
{
	uint32_t _mark = 0;

	if (m_tag_get(m, vnb_nfm_tag_type, &_mark) == 0)
		_mark = ntohl(_mark);

	_mark = (_mark & ~KT_NFMARK_MASK) |
		((value & KT_NFMARK_UNSHIFT_MASK) << KT_NFMARK_SHIFT);
	m_tag_add(m, vnb_nfm_tag_type, htonl(_mark));
}

#endif /* CONFIG_MCORE_M_TAG */
#endif /* __FastPath__ */
#endif /* _NFMARK_H */

