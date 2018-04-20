/*
 * Copyright(c) 2008 6WIND
 */
#include "fpn.h"
#include "fpn-mbuf.h"
#include "fpn-hexdump.h"

/*
 * Copy len bytes from source mbuf m, at offset off, to memory area
 * dest. The memory areas should not overlap.
 *   o If off > m_len(m), packet and destination buffer are not modified.
 *   o If len > (m_len(m)-off), only (m_len(m)-off) bytes are copied.
 * The function returns the number of copied bytes.
 */
uint32_t __m_copytobuf(void *dest, const struct mbuf *m, uint32_t off, uint32_t len)
{
	const struct sbuf *s;
	uint32_t dst_off=0;
	uint32_t copylen;

	m_check(m);
	if (unlikely(len == 0))
		return 0;

	M_FOREACH_SEGMENT(m, s) {
		if (off >= s_len(s)) {
			off -= s_len(s);
			continue;
		}
		copylen = s_len(s) - off;
		if (len < copylen)
			copylen = len;
		fpn_memcpy(dest+dst_off, s_data(s, char *)+off, copylen);
		dst_off += copylen;
		off = 0;
		len -= copylen;
		if (len == 0)
			break;
	}
	return dst_off;
}

#ifndef HAVE_ARCH_MDUP
struct mbuf *m_dup(const struct mbuf *m)
{
	struct mbuf *m2;
	const struct sbuf *s;
	struct sbuf *last_seg = NULL, *s2 = NULL;
	uint32_t copylen;

	m_check(m);
	m2 = m_alloc();
	if(unlikely(m2 == NULL))
		return NULL;

	M_FOREACH_SEGMENT(m, s) {
		/* skip empty segments */
		if (s_len(s) == 0)
			continue;

		/* special case for first segment */
		if (s2 == NULL) {
			s2 = m_first_seg(m2);
		}

		else {
			s2 = __m_add_seg(m2, last_seg);
			if (s2 == NULL) {
				m_freem(m2);
				return NULL;
			}
		}

		copylen = s_len(s);
		/* check copylen against segment length */
		if (copylen > (s_headroom(s2) + s_tailroom(s2))) {
			m_freem(m2);
			return NULL;
		}

		if (copylen > s_tailroom(s2)) {
			__s_prepend(s2, copylen - s_tailroom(s2));
			__s_append(s2, s_tailroom(s2));
		}
		else {
			__s_append(s2, copylen);
		}

		fpn_memcpy(s_data(s2, char *), s_data(s, char *), copylen);
		__m_set_len(m2, m_len(m2) + copylen);
		last_seg = s2;
	}
	m_set_input_port(m2, m_input_port(m));

	/* copy mbuf_priv */
	fpn_memcpy(mtopriv(m2,void *), mtopriv(m,void *),
	       FPN_MBUF_PRIV_COPY_SIZE);

	m_check(m2);
	return m2;
}
#endif /* HAVE_ARCH_MDUP */

static inline void s_dump(const struct sbuf *s)
{
	fpn_printf("  == sbuf at [%p]: len=%d, headroom=%d, tailroom=%d\n",
		s, s_len(s), s_headroom(s), s_tailroom(s));
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	fpn_printf("                   data=%p, users=%d, parent=%p\n",
		s_data(s, char *), __s_get_users(s), __s_get_parent(s));
#endif
}

uint32_t __m_copyfrombuf(struct mbuf *m, uint32_t off, const void *src, uint32_t len)
{
	uint32_t copylen = 0;
	uint32_t src_off = 0;
	uint32_t extend;
	struct sbuf *s, *last_seg = NULL;

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	/* m_copyfrombuf() is currently not supported on clones */
	if (m_is_shared(m))
		return 0;
#endif

	m_check(m);
	if (unlikely(len == 0))
		return 0;

	/* overrides previous data */
	M_FOREACH_SEGMENT(m, s) {
		last_seg = s;
		if (off > s_len(s)) {
			if (s_next(m, s) != NULL)
				off -= s_len(s);
			continue;
		}

		/* copy in existing data */
		copylen = s_len(s) - off;
		if (len < copylen)
			copylen = len;
		fpn_memcpy(s_data(s, char *)+off, src + src_off, copylen);

		src_off += copylen;
		len -= copylen;

		/* finished */
		if (len == 0)
			return src_off;

		/* no next buffer, we will append data at this offset */
		if (s_next(m, s) == NULL)
			off = s_len(s);
		else
			off = 0;
	}

	s = last_seg;

	/* append some non-initialized data */
	while (off > s_tailroom(s) + s_len(s)) {
		off -= (s_tailroom(s) + s_len(s));
		extend = s_tailroom(s);
		__s_append(s, extend);
		/* __m_set_len must be called after adjusting segments */
		__m_set_len(m, m_len(m) + extend);
		last_seg = s;
		s = __m_add_seg(m, last_seg);
		if (s == NULL) {
			m_freem(m);
			return src_off;
		}
	}

	/* write new data in new segments */
	while (len > 0) {
		if (s_tailroom(s) == 0) {
			last_seg = s;
			s = __m_add_seg(m, last_seg);
			if (s == NULL) {
				m_freem(m);
				return src_off;
			}
		}

		copylen = s_tailroom(s) + s_len(s) - off;
		if (len < copylen)
			copylen = len;
		extend = copylen + off - s_len(s);
		__s_append(s, extend);
		__m_set_len(m, m_len(m) + extend);
		fpn_memcpy(s_data(s, char *) + off, src + src_off, copylen);
		src_off += copylen;
		len -= copylen;
		off = 0;
	}

	return src_off;
}

struct mbuf *m_copypack(const struct mbuf *m, uint32_t off, uint32_t len)
{
	struct mbuf *m2;
	const struct sbuf *s = NULL;
	struct sbuf *last_seg = NULL, *s2 = NULL;
	uint32_t copylen, totallen = 0;
	void *src, *dst;

	FPN_ASSERT(off + len <= m_len(m));

	m_check(m);
	m2 = m_alloc();
	if (unlikely(m2 == NULL))
		return NULL;

	last_seg = s2 = m_first_seg(m2);
	s = m_first_seg(m);

	/* Optimize copy of a single segment mbuf */
	if (likely(len + off <= s_len(s) && len <= s_tailroom(s2))) {
		__s_append(s2, len);
		fpn_memcpy(s_data(s2, char *), s_data(s, char *) + off, len);
		totallen = len;
		__m_set_len(m2, totallen);
		goto common_end;
	}

	M_FOREACH_SEGMENT(m, s) {
		/* skip empty segments */
		if (unlikely(s_len(s) == 0))
			continue;

		/* while we have data in src segments, append it in dst
		 * segments */
		while (off < s_len(s) && len != 0) {

			if (unlikely(s_tailroom(s2) == 0 &&
				(s2 = __m_add_seg(m2, last_seg)) == NULL)) {
				m_freem(m2);
				return NULL;
			}

			copylen = s_len(s) - off;
			if (unlikely(copylen > len))
				copylen = len;
			if (unlikely(copylen > s_tailroom(s2)))
				copylen = s_tailroom(s2);
			src = s_data(s, char *) + off;
			dst = s_data(s2, char *) + s_len(s2);
			__s_append(s2, copylen);
			fpn_memcpy(dst, src, copylen);
			totallen += copylen;
			off += copylen;
			last_seg = s2;
			len -= copylen;
			__m_set_len(m2, totallen);
		}

		if (len == 0)
			break;
		off -= s_len(s);
	}
 common_end:
	m_set_input_port(m2, m_input_port(m));

	/* copy mbuf_priv */
	fpn_memcpy(mtopriv(m2,void *), mtopriv(m,void *),
	       FPN_MBUF_PRIV_COPY_SIZE);

	m_check(m2);
	return m2;
}

//#define FP_M_SPLIT_DEBUG 1
#if defined FP_M_SPLIT_DEBUG && FP_M_SPLIT_DEBUG == 1
#define TRACE_M_SPLIT(fmt, args...) do {\
	fpn_printf(fmt "\n", ## args); \
} while (0)
#else
#define TRACE_M_SPLIT(x...) do {} while(0)
#endif

struct mbuf *m_split(struct mbuf *m, uint32_t off)
{
	uint32_t copylen;
	struct mbuf *m2 = NULL;
	struct sbuf *s;
	struct sbuf *splitted_segment = m_first_seg(m);
	struct sbuf *s2prev = NULL, *sprev = NULL;
	uint32_t newlen = off;
	unsigned int i = 0;

	m_check(m);

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	/* m_split() is currently not supported on clones */
	if (m_is_shared(m))
		return NULL;
#endif

	/* m_split() must not be used on mbufs linked with nextpkt */
	FPN_ASSERT(m_nextpkt(m) == NULL);

	if (unlikely(off == 0 || off >= m_len(m)))
		return NULL;

	M_FOREACH_SEGMENT(m, s) {
		TRACE_M_SPLIT("-------------- s = %p, s_len(s) = %d\n", s, s_len(s));
		if (off != 0 && off >= s_len(s)) {
			TRACE_M_SPLIT("skip = off: %d -> %d\n", off, off - s_len(s));
			off -= s_len(s);
			sprev = s;
			i++;
			continue;
		}
		if (m2 == NULL) {
			m2 = m_alloc();
			if(unlikely(m2 == NULL))
				return NULL;
			copylen = s_len(s) - off;
			TRACE_M_SPLIT("Alloc new mbuf m2=%p: copylen = %d\n", m2, copylen);
			m_copyfrombuf(m2, 0, s_data(s, char *) + off, copylen);
			s2prev = m_last_seg(m2);
			__s_trim(s, s_len(s) - off);
			off = 0;
			i++;
			splitted_segment = s;
			TRACE_M_SPLIT("After mlen(m2) = %d. Splitted_Segment = %p\n", m_len(m2), s);
			continue;
		}
		TRACE_M_SPLIT("Append segment %p to m2. mlen(m2) = %d\n", s, m_len(m2));
		__m_append_seg(m2, s2prev, s);
		TRACE_M_SPLIT("mlen(m2) = %d\n", m_len(m2));
		s2prev = s;
		M_TRACK_UPDATE_SEG(m, -1);
	}
	TRACE_M_SPLIT("Finished, mlen(m2) = %d\n", m_len(m2));
	__s_set_next(m, splitted_segment, NULL);
	__m_set_len(m, newlen);
	__m_set_seg_count(m, i);

	/* delete last segment if its size is 0 */
	if (s_len(splitted_segment) == 0) {
		TRACE_M_SPLIT("delete segment %p, after %p\n", splitted_segment, sprev);
		__m_del_seg(m, sprev);
	}

	/* copy input port */
	m_set_input_port(m2, m_input_port(m));

	/* copy mbuf_priv */
	fpn_memcpy(mtopriv(m2,void *), mtopriv(m,void *),
	       FPN_MBUF_PRIV_COPY_SIZE);

	m_check(m);
	m_check(m2);
	return m2;
}

/* called by m_trim(), do support jumbo-frame */
uint32_t __m_trim(struct mbuf *m, uint32_t len)
{
	struct sbuf *s = m_first_seg(m);

	m_check(m);
	if (unlikely(len >= m_len(m)))
		return 0;

	if (likely(s_next(m, s) == NULL)) {
		__s_trim(s, len);
		__m_set_len(m, m_len(m) - len);
	} else {
		uint32_t slen = 0;
		struct sbuf *next;

		/*
		 * When the (mbuf length - first segments size)
		 * is less or equal than the trim length,
		 * we can remove all next segments.
		 */
		M_FOREACH_SEGMENT(m, s) {
			slen += s_len(s);
			if ((m_len(m) - slen) <= len)
				break ;
		}

		/* Remove all next segments and count their size */
		slen = 0;
		while ((next = s_next(m, s))) {
			slen += s_len(next);
			__m_del_seg(m, s);
		}

		/* Trim remaining bytes in new last segment */
		if (likely(slen != len)) {
			__s_trim(s, len - slen);
			__m_set_len(m, m_len(m) - (len - slen));
		}
	}

	m_check(m);
	return len;
}

static const uint32_t m_max_protohdr = 64;

/* __m_pullup() do support jumbo-frame */
struct mbuf *__m_pullup(struct mbuf *m, uint32_t len)
{
	struct sbuf *s, *s_prev;
	char *src, *dst;
	uint32_t copy, need, wish;
	const uint32_t headroom = 128; /* per-arch ? */

	m_check(m);
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	/* m_pullup() is currently not supported on clones */
	if (m_is_shared(m)) {
		m_freem(m);
		return NULL;
	}
#endif

	if (unlikely(len > m_len(m))) {
		m_freem(m);
		return NULL;
	}

	s = m_first_seg(m);
	need = len - s_len(s);
	/* make tailroom if need */
	if (unlikely(s_tailroom(s) < need)) {
		int diff = s_headroom(s) - headroom;
		if (diff >= (int)(need - s_tailroom(s))) {
			copy = s_len(s);
			__s_prepend(s, diff);
			if (copy != 0) { /* seg could be empty */
				src = s_data(s, char *) + diff;
				dst = s_data(s, char *);
				memmove(dst, src, copy);
			}
			__s_trim(s, diff);
		} else {
			/* not enough tailroom in any cases, give up */
			m_freem(m);
			return NULL;
		}
	}
	FPN_ASSERT(s_tailroom(s) >= need);

	/* up to m_max_protohdr bytes if possible */
	wish = FPN_MIN(s_tailroom(s),FPN_MAX(need, FPN_MIN(m_max_protohdr, m_len(m))));

	/* Start copy at tail */
	dst = s_data(s, char *) + s_len(s);

	/* track previous in case we remove empty segment */
	s_prev = s;

	while ((s = s_next(m, s)) != NULL && wish != 0) {
		copy = FPN_MIN(s_len(s), wish);

		if (copy) {
			src = s_data(s, char *);
			fpn_memcpy(dst, src, copy);
			__s_append(m_first_seg(m), copy);
			__s_adj(s, copy); /* updated s->len */
			dst += copy;
			wish -= copy;
		}

		/* if no data remain in s, we can remove it, else we
		 * have to resize it */
		if (s_len(s) == 0) {
			__m_del_seg(m, s_prev);
			/* don't update s_prev, and set s to previous
			 * segment */
			s = s_prev;
		} else
			s_prev = s;
	}

	/* check that we have enough data in first segment */
	if  (m_headlen(m) < len) {
		m_freem(m);
		return NULL;
	}

	m_check(m);
	return m;
}

struct mbuf *m_shrink(struct mbuf *m)
{
	struct sbuf *s, *s_dst, *s_prev = NULL;
	void *src, *dst;
	uint32_t copy, diff;
	uint32_t headroom = 128; /* per-arch ? */

	m_check(m);
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	/* m_pullup() is currently not supported on clones */
	if (m_is_shared(m)) {
		m_freem(m);
		return NULL;
	}
#endif

	/* the segment in which we add data: if len != 0, s_dst is
	 * always the first segment because exit the loop as soon as
	 * it is full */
	s = s_dst = m_first_seg(m);

	do {
		/* move data at the beginning of s if too much headroom */
		if (s == s_dst) {
			if (s_headroom(s) > headroom) {
				diff = s_headroom(s) - headroom;
				copy = s_len(s);
				__s_prepend(s, diff);
				if (copy != 0) {
					src = s_data(s, char *) + diff;
					dst = s_data(s, char *);
					memmove(dst, src, copy);
				}
				__s_trim(s, diff);
			}
			headroom = 0;
			s_prev = s;
			continue;
		}

		/* s != s_dst */

		/* copy bytes from s to s_dst */
		copy = s_len(s);
		if (copy != 0) {
			if (copy > s_tailroom(s_dst))
				copy = s_tailroom(s_dst);
			src = s_data(s, char *);
			dst = s_data(s_dst, char *) + s_len(s_dst);
			fpn_memcpy(dst, src, copy);
			__s_append(s_dst, copy);
			__s_adj(s, copy);
		}

		/* if no data remain in s, we can remove it, else we
		 * have to resize it */
		if (0 == s_len(s)) {
			__m_del_seg(m, s_prev);
			/* don't update s_prev, and set s to previous
			 * segment */
			s = s_prev;
		} else
			s_prev = s;

		/* no room remain in s_dst, now we will add data in
		 * the next segment */
		if (s_tailroom(s_dst) == 0)
			s_dst = s_next(m, s_dst);

	} while ((s = s_next(m, s)) != NULL);

	m_check(m);
	return m;
}

char *__m_adj2(struct mbuf *m, uint32_t len)
{
	struct sbuf *s, *prev = NULL, *first = NULL;
	uint32_t adj;
	char *d;

	/* mbuf too short, return */
	if (unlikely(len > m_len(m)))
		return NULL;

	__m_set_len(m, m_len(m) - len);

	/* remove data in segments, and delete empty segments if
	 * possible (api does not allow to remove the first segment) */
	M_FOREACH_SEGMENT(m, s) {

		/* remove data */
		adj = len;
		if (adj > s_len(s))
			adj = s_len(s);
		__s_adj(s, adj);
		len -= adj;

		/* if segment is empty and it is not the first one */
		if ((s_len(s) == 0) && prev != NULL) {
			__m_del_seg(m, prev);
			s = prev;
		}
		else {
			if (prev == NULL)
				first = s;
			prev = s;
		}
		/* no more data to remove, exit the loop */
		if (len == 0)
			break;
	}

	d = s_data(first, char *);
	__m_set_data(m, d);
	return d;
}

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
/*
 * remove len bytes from start of a shared mbuf
 *
 * may return an mbuf with an empty first segment
 */
char *__m_adj2_clone(struct mbuf *m, uint32_t len)
{
	struct sbuf *s;
	struct sbuf *sfirst;
	uint32_t adjusted;

	m_check(m);

	if (unlikely(len > m_len(m)))
		return NULL;

	adjusted = m_len(m) - len;

	sfirst = m_first_seg(m);

	/* case 1: only first segment needs to be adjusted */
	if (len <= s_len(sfirst)) {
		__s_adj(sfirst, len);
		__m_set_len(m, adjusted);
		m_check(m);
		return mtod(m, char *);
	}

	/* case 2: data must also be removed from next segments */

	/* start by emptying first segment */
	len -= s_len(sfirst);
	__s_adj(sfirst, s_len(sfirst));

	/* then for each segment, remove min(len, s_len(s)) */
	/* emptied segments are deleted as we go along */
	while (len) {
		s = s_next(m, sfirst);

		/* if len >= s_len(s), delete segment */
		if (len >= s_len(s)) {
			len -= s_len(s);
			__m_del_seg(m, sfirst);
		}
		/* else remove first bytes of segment and s_adj2 is completed */
	  	else {
			__s_adj(s, len);
			break;
		}
	}

	__m_set_len(m, adjusted);

	m_check(m);
	return mtod(m, char *);
}

/*
 * clone a full mbuf
 *
 * Create an mbuf made of an empty segment followed by clones of the source
 * mbuf segments. clones are segments that reference the source segments
 * without copying their data.
 */
struct mbuf *m_clone(struct mbuf *m)
{
	struct mbuf *clone; /* new mbuf being built */
	struct sbuf *s;     /* current source segment */
	struct sbuf *slast; /* last segment of the new mbuf */
	struct sbuf *sc;    /* current seg clone, not appended to new mbuf */

	m_check(m);

	/* Per-arch stuff to do before cloning a mbuf. At least useful
	 * for XLP to refill Network Accelerator's pool. */
	if (unlikely(__m_prepare_clone(m) < 0))
		return NULL;

	clone = m_alloc();
	if (unlikely(clone == NULL))
		return NULL;

	m_add_flags(m, M_F_SHARED);
	m_add_flags(clone, M_F_SHARED);

	s = m_first_seg(m);
	slast = m_first_seg(clone);

	do {
		/* skip empty segments */
		if (unlikely(s_len(s) == 0))
			continue;
		/* clone source segment */
		sc = __s_clone(s);
		if (sc == NULL) {
			m_freem(clone);
			return NULL;
		}
		__m_append_seg(clone, slast, sc);
		slast = sc;

	} while ((s = s_next(m, s)) != NULL);

	/* copy input port */
	m_set_input_port(clone, m_input_port(m));

	/* copy mbuf_priv */
	fpn_memcpy(mtopriv(clone, void *), mtopriv(m, void *),
	       FPN_MBUF_PRIV_COPY_SIZE);

	m_check(m);
	return clone;
}

/*
 * clone a part of an mbuf
 *
 * Create a clone of an mbuf, that references 'len' bytes of the original mbuf
 * starting at offset 'off'.
 *
 * The first 'writable' bytes (starting at offset 'off') are copied instead of
 * being references to the original segments.
 */
struct mbuf *m_clone_area(struct mbuf *m, uint32_t writable, uint32_t off,
			  uint32_t len)
{
	struct mbuf *clone; /* new mbuf being built */
	struct sbuf *s;     /* current source segment */
	struct sbuf *slast; /* last segment of the new mbuf */
	struct sbuf *sc;    /* current seg clone, not appended to new mbuf */
	uint32_t tocopy;

	if (unlikely(off > m_len(m) || off + len > m_len(m)))
		return NULL;

	if (writable > len)
		writable = len;

	/* Per-arch stuff to do before cloning a mbuf. At least useful
	 * for XLP to refill Network Accelerator's pool. */
	if (unlikely(__m_prepare_clone(m) < 0)) {
		m_freem(m);
		return NULL;
	}

	clone = m_alloc();
	if (unlikely(clone == NULL || len == 0))
		return clone;

	m_add_flags(m, M_F_SHARED);
	m_add_flags(clone, M_F_SHARED);

	/* first source segment */
	s = m_first_seg(m);
	/* first segment of the new mbuf (empty) */
	slast = m_first_seg(clone);

	/* skip source segments up to 'offset' */
	while (off >= s_len(s)) {
		off -= s_len(s);
		s = s_next(m, s);
	}

	/* still 'off' bytes to skip in current src segment */

	/* copy 'writable' bytes of data from source segment starting
	 * at offset 'off' */
	while (writable) {
		if (likely(writable <= s_tailroom(slast)
			&& writable <= s_len(s) - off)) {
			/*  straightforward case */
			__s_append(slast, writable);
			fpn_memcpy(s_data(slast, char *) + s_len(slast),
				s_data(s, char *) + off, writable);
			off += writable;
			len -= writable;
			//writable = 0;
			/* if src segment is fully consumed, find next
			 * non-empty segment */
			if (off == s_len(s)) {
				off = 0;
				do {
					s = s_next(m, s);
				} while (unlikely(s_len(s) == 0));
			}
			/* finished copying 'writable' bytes */
			break;
		} else {
			/* complex case: several dst segments must be looked up
			 * or extra dst segments must be allocated */
			if (s_tailroom(slast) == 0) {
				slast = __m_add_seg(m, slast);
				if (unlikely(slast == NULL)) {
					m_freem(clone);
					return NULL;
				}
			}
			tocopy = writable;
			if (tocopy > s_len(s) - off)
				tocopy = s_len(s) - off;
			if (tocopy > s_tailroom(slast))
				tocopy = s_tailroom(slast);
			if (tocopy) {
				__s_append(slast, tocopy);
				fpn_memcpy(s_data(slast, char *) + s_len(slast),
					s_data(s, char *) + off, tocopy);
				writable -= tocopy;
				len -= tocopy;
				off += tocopy;
			}
			/* if src segment is fully consumed, find next
			 * non-empty segment */
			if (off == s_len(s)) {
				off = 0;
				do {
					s = s_next(m, s);
				} while (unlikely(s_len(s) == 0));
			}
		}
	}

	/* we have copied 'writable' bytes. The next len bytes must be cloned,
	 * not copied.
	 * 'off' is the start offset in the current src segment */

	/* clone source segment */
	sc = __s_clone(s);
	if (unlikely(sc == NULL)) {
		m_freem(clone);
		return NULL;
	}
	/* skip first bytes of segment clone up to offset */
	if (off) {
		__s_adj(sc, off);
		//off = 0;
	}

	/* append full copies of source segments up to 'len' */
	while (len > s_len(sc)) {

		len -= s_len(sc);
		__m_append_seg(clone, slast, sc);
		slast = sc;

		/* find next non-empty source segment */
		do {
			s = s_next(m, s);
		} while (unlikely(s_len(s) == 0));

		/* clone source segment */
		sc = __s_clone(s);
		if (unlikely(sc == NULL)) {
			m_freem(clone);
			return NULL;
		}
	}

	/* only keep first len bytes of the segment */
	if (len < s_len(sc)) {
		__s_trim(sc, s_len(sc) - len);
	}
	//len = 0;

	/* append last segment to mbuf clone */
	__m_append_seg(clone, slast, sc);

	/* copy input port */
	m_set_input_port(clone, m_input_port(m));

	/* copy mbuf_priv */
	fpn_memcpy(mtopriv(clone, void *), mtopriv(m, void *),
	       FPN_MBUF_PRIV_COPY_SIZE);

	return clone;
}
#endif /* CONFIG_MCORE_FPN_MBUF_CLONE */

#define __m_check_printf(fmt, args...) \
	fpn_printf("%s:%d %s(): " fmt, file, line, func, ## args)

void __m_check(const struct mbuf *m,
	const char *file, int line, const char *func)
{
	const struct sbuf *s;
	const struct sbuf *last_seg = NULL;
	unsigned slen_sum = 0;
	int i = 0;

	if (m == NULL)
		return;

	M_FOREACH_SEGMENT(m, s) {
		slen_sum += s_len(s);
		last_seg = s;
		i++;
	}

	if (m_seg_count(m) == 0) {
		__m_check_printf("     NO SEG\n");
		fpn_abort();
	}

	if (m_seg_count(m) > 250) {
		__m_check_printf("     TOO MANY SEGS claimed=%u>250\n", (unsigned)m_seg_count(m));
		fpn_abort();
	}

#ifndef CONFIG_MCORE_ARCH_NPS
	/* these checks are meaningless when sbufs are not fully implemented */
	/* sanity checks */
	if (m_len(m) != slen_sum) {
		__m_check_printf("     BAD LEN claimed=%u/real=%u\n", (unsigned)m_len(m),
			slen_sum);
		fpn_abort();
	}
	if (m_last_seg(m) != last_seg) {
		__m_check_printf("     BAD LAST SEG (%p != %p)\n",
			   (void *)m_last_seg(m), (void *)last_seg);
		fpn_abort();
	}
	if (m_seg_count(m) != i) {
		__m_check_printf("     BAD SEG COUNT claimed=%u/real=%u\n",
			(unsigned)m_seg_count(m), (unsigned)i);
		fpn_abort();
	}
#endif
}

void m_dump(const struct mbuf *m, int dump_len)
{
	const struct sbuf *s, *last_seg = NULL;
	uint32_t slen_sum = 0;
	int i = 0;
	uint32_t len;

	if (m == NULL) {
		fpn_printf("==== mbuf is NULL\n");
		return;
	}

	fpn_printf("==== mbuf at [%p]: %d segment(s), len=%d\n",
		   m, m_seg_count(m), m_len(m));
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	fpn_printf("                   next=%p flags=0x%x\n",
		   m_nextpkt(m), (unsigned)m_get_flags(m));
#else
	fpn_printf("                   next=%p\n",
		   m_nextpkt(m));
#endif
	M_FOREACH_SEGMENT(m, s) {
		slen_sum += s_len(s);
		s_dump(s);
		if (dump_len > 0) {
			len = dump_len;
			if (len > s_len(s))
				len = s_len(s);
			fpn_hexdump("sbuf data", s_data(s, char *), len);
			dump_len -= len;
		}
		last_seg = s;
		i++;
	}

#ifndef CONFIG_MCORE_ARCH_NPS
	/* these checks are meaningless when sbufs are not fully implemented */
	/* sanity checks */
	if (m_len(m) != slen_sum)
		fpn_printf("     BAD LEN\n");
	if (m_last_seg(m) != last_seg)
		fpn_printf("     BAD LAST SEG (%p != %p)\n",
			   (void *)m_last_seg(m), (void *)last_seg);
	if (m_seg_count(m) != i)
		fpn_printf("     BAD SEG COUNT\n");
#endif
}

#ifdef CONFIG_MCORE_FPN_MBUF_TRACK

#include "shmem/fpn-shmem.h"

static FPN_DEFINE_SHARED(struct {
	struct m_track *area;
	size_t free;
	size_t count;
	fpn_spinlock_t lock;
}, m_track_data) = {
	.lock = FPN_SPINLOCK_UNLOCKED_INITIALIZER
};

void m_track_init(void)
{
	size_t size = CONFIG_MCORE_MBUF_TRACK_SIZE;
	void *ptr;

	fpn_shmem_add("mtrack-shared", size);
	ptr = fpn_shmem_mmap("mtrack-shared",
			     NULL,
			     size);
	if (ptr == NULL) {
		fpn_printf("mtrack-shared not available\n");
		return;
	}

	memset(ptr, 0, size);
	fpn_spinlock_lock(&m_track_data.lock);
	m_track_data.area = ptr;
	m_track_data.free = size;
	fpn_spinlock_unlock(&m_track_data.lock);
}

void m_track_untrack(struct mbuf *m)
{
	struct m_track **mbuf_track;

	FPN_ASSERT(m != NULL);
	FPN_ASSERT(m_track_data.area != NULL);
	/* ignore if mbuf cannot be tracked or isn't tracked */
	fpn_spinlock_lock(&m_track_data.lock);
	if (((mbuf_track = m_track_get(m)) == NULL) ||
	    (*mbuf_track == NULL)) {
		fpn_spinlock_unlock(&m_track_data.lock);
		return;
	}
	(*mbuf_track)->mbuf_tracked --;
	(*mbuf_track)->seg_tracked -= m_seg_count(m);
	fpn_spinlock_unlock(&m_track_data.lock);
	*mbuf_track = NULL;
}

void m_track(struct mbuf *m, const char *file, const char *func,
	     int32_t line, const char *group)
{
	struct m_track *track;
	struct m_track **mbuf_track;
	const char *c;
	size_t i;

	FPN_ASSERT(m != NULL);
	FPN_ASSERT(file != NULL);
	FPN_ASSERT(func != NULL);
	/* if the mbuf cannot be tracked, there's no need to go any further */
	fpn_spinlock_lock(&m_track_data.lock);
	if ((mbuf_track = m_track_get(m)) == NULL) {
		fpn_spinlock_unlock(&m_track_data.lock);
		return;
	}
	if (m_track_data.area == NULL)
		fpn_panic("%s:%u: %s: M_TRACK() called before"
			  " M_TRACK_INIT()\n",
			  file, line, func);
	/* strip leading directories */
	for (c = file; (*c != '\0'); ++c)
		if (*c == '/')
			file = (c + 1);
	for (i = 0; (i < m_track_data.count); ++i) {
		track = &m_track_data.area[i];
		FPN_ASSERT(track != NULL); /* logically impossible */
		if ((track->line == line) &&
		    (memcmp(track->file, file, strlen(track->file)) == 0) &&
		    (memcmp(track->func, func, strlen(track->func)) == 0) &&
		    (memcmp(track->group, group, strlen(track->group)) == 0)) {
			/* skip if mbuf is already tracked by the same entry */
			if (*mbuf_track == track)
				goto out;
			/* check if mbuf is already tracked to fix counters */
			if (*mbuf_track != NULL) {
				(*mbuf_track)->mbuf_tracked --;
				(*mbuf_track)->seg_tracked -= m_seg_count(m);
			}
			track->mbuf_tracked ++;
			track->mbuf_hits ++;
			track->seg_tracked += m_seg_count(m);
			track->seg_hits += m_seg_count(m);
			goto out;
		}
	}
	/* tracking element not found, add it to the array */
	if (m_track_data.free < sizeof(*track))
		fpn_panic("%s:%u: %s: M_TRACK(): not enough space to add"
			  " a new tracking element, you need to increase"
			  " CONFIG_MCORE_MBUF_TRACK_SIZE; currently"
			  " %zu\n",
			  file, line, func,
			  ((m_track_data.count * sizeof(*track)) +
			   m_track_data.free));
	m_track_data.free -= sizeof(*track);
	track = &m_track_data.area[m_track_data.count];
	++m_track_data.count;
	strncpy(track->file, file, sizeof(track->file));
	strncpy(track->func, func, sizeof(track->func));
	strncpy(track->group, group, sizeof(track->group));
	track->file[(sizeof(track->file) - 1)] = '\0';
	track->func[(sizeof(track->func) - 1)] = '\0';
	track->group[(sizeof(track->group) - 1)] = '\0';
	track->line = line;
	track->mbuf_tracked = 1;
	track->mbuf_hits = 1;
	track->seg_tracked = m_seg_count(m);
	track->seg_hits = m_seg_count(m);
	if (*mbuf_track != NULL) {
		(*mbuf_track)->mbuf_tracked --;
		(*mbuf_track)->seg_tracked -= m_seg_count(m);
	}
out:
	*mbuf_track = track;
	fpn_spinlock_unlock(&m_track_data.lock);
}

/*
 * increment the number of segments tracked for this mbuf.
 * must be called when the number fo segments of a mbuf is changed,
 * without modifying the mbuf tracking line.
 *
 * inc may be negative or positive
 */
void m_track_update_seg(struct mbuf *m, int32_t inc)
{
	struct m_track **mbuf_track;

	FPN_ASSERT(m != NULL);
	FPN_ASSERT(m_track_data.area != NULL);
	fpn_spinlock_lock(&m_track_data.lock);
	/* ignore if mbuf cannot be tracked or isn't tracked */
	if (((mbuf_track = m_track_get(m)) == NULL) ||
	    (*mbuf_track == NULL)) {
		fpn_spinlock_unlock(&m_track_data.lock);
		return;
	}
	(*mbuf_track)->seg_tracked += inc;
	if (inc > 0)
		(*mbuf_track)->seg_hits += inc;
	fpn_spinlock_unlock(&m_track_data.lock);
}

#endif /* CONFIG_MCORE_FPN_MBUF_TRACK */
