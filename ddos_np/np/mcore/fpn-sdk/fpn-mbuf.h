/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _FPN_MBUF_H_
#define	_FPN_MBUF_H_

/* To attach extra information to mbuf, application
 * defines FPN_MBUF_EXTRA_SIZE to inform board-specific
 * mbuf implementation to reserve room to hold extra information.
 * typedef { int field; ... } mbuf_extra_t
 */

/*
 * Allocate a new mbuf. Return NULL if allocation failed. This new
 * mbuf contains one segment, which length is 0. The pointer to data
 * is initialized in order to have some bytes of headroom in the
 * buffer.
 *
 * struct mbuf *m_alloc(void)


 *
 * Free an mbuf, and all its segments in case of chained buffers.
 *
 * void m_freem(struct mbuf *m)

 *
 * Free an mbuf without freeing the attached segments. On architectures
 * where (sbuf == mbuf), this function does nothing.
 *
 * void m_free_mhdr(struct mbuf *m)

 *
 * Return total length of data in the mbuf.
 *    m_len(m) = SUM (s_len(s1) + s_len(s2) + ... s_len(sn))
 *
 * uint32_t m_len(const struct mbuf *m)


 *
 * Prepend space of len bytes to mbuf data area. Return a pointer to
 * the new data start address. If there is not enough headroom in the
 * first segment, the function won't allocate a new segment and will
 * return NULL, without modifying the mbuf.
 *
 * char *m_prepend(struct mbuf *m, uint32_t len)


 *
 * Append contiguous space of size len to the last segment of the mbuf.
 * Return a pointer to the start address of the added data. On most
 * architectures, if there is not enough tailroom in the last segment,
 * the function won't allocate a new segment and will return NULL, without
   modifying the mbuf.
 * The architecture where the allocation of an extra segment can occur are
 * identified with the flag HAVE_MAPPEND_ALLOC_SUPPORT set.
 *
 * char *m_append(struct mbuf *m, uint32_t len)


 *
 * Remove len bytes of data at the beginning of the mbuf. If the len
 * is bigger than the len of the first segment, then the function will
 * fail and will return NULL, without modifying the mbuf.
 * WARNING, depending on architectures, m_adj() may modify the content
 * of "adjusted" data.
 *
 * char *m_adj(struct mbuf *m, uint32_t len)


 * Remove len bytes of data at the beginning of the mbuf. The m_adj2()
 * function is able to remove more data than the len of the first
 * segment. But, as is it not possible to remove the first segment on
 * some architectures, this function does not remove it even if it is
 * empty. In clearer terms, the mbuf, after a call to m_adj2(), can have
 * its first segment (and only its first segment) empty. The user should
 * call m_pullup() if he wants to fill the first segment. This function
 * returns the pointer to the head of data, or NULL on error.
 *
 * char *m_adj2(struct mbuf *m, uint32_t len)


 *
 * Remove len bytes of data at the end of the mbuf. If the len is
 * bigger than the len of the last segment, then the function will
 * remove and free the segments. If len >= m_len(m), the function will
 * fail and return 0.
 *
 * uint32_t m_trim(struct mbuf *m, uint32_t len)

 *
 * Returns the length of the first segment.
 *
 * uint32_t m_headlen(const struct mbuf *m)

 *
 * Returns the size of the tailroom in last segment.
 *
 * uint32_t *m_tailroom(const struct mbuf *m)
 *

 * Macro that points to the start of data in the mbuf. The returned
 * pointer is casted to type t. Before using this function, the user
 * must ensure that m_headlen(m) is large enough to read its data.
 *
 * mtod(const struct mbuf *m, type t) 

 *
 * Return a pointer just after the end of the data. The pointer can be
 * located in a different segment than the start of data.
 *
 * char *m_tail(const struct mbuf *m) 


 *
 * Returns a pointer (type t) to data at offset or NULL if
 * off>m_len(m)
 *
 * m_off(const struct mbuf *m, uint32_t off, type t)


 *
 * Network input port of the mbuf
 *
 * uint8_t m_input_port(const struct mbuf *m) 


 *
 * Set the network input port of the mbuf
 * 
 * void m_set_input_port(struct mbuf *m, uint8_t port) 


 *
 * Get and set color for egress
 * 
 * void m_set_egress_color(struct mbuf *, const uint8_t color) 
 * uint8_t m_get_egress_color(const struct mbuf *m) 


 *
 * Concatenate mbuf m2 to m1
 *     On success it returns 0 and frees m2  
 *     On error, it returns -1, m1 and m2 are not freed.
 *
 * int m_cat(struct mbuf *m1, struct mbuf *m2); 


 *
 * Return the length of continous data starting at off.
 *
 * uint32_t m_maypull(const struct mbuf *m, uint32_t off);


 *
 * Return 1 if all data are contiguous in mbuf, else 0
 *
 * int m_is_contiguous(const struct mbuf *m)
 

 *
 * struct sbuf *m_first_seg(const struct mbuf *m)
 *
 * Return the first segment of a mbuf.

 *
 * struct sbuf *m_last_seg(const struct mbuf *m)
 *
 * Return the last segment of a mbuf.

 *
 * s_data(const struct sbuf *s, type t)
 *
 * macro to point to the start of data in the segment s. Pointer is
 * casted to type t.


 *
 * struct sbuf *s_next(const struct mbuf *m, const struct sbuf *s)
 *
 * In packet m, return the next segment after s. If there's no next
 * segment, return NULL.


 *
 * struct sbuf *s_len(const struct sbuf *s)
 *
 * Return the length of the segment s, owned by mbuf m.

 *
 * Return the size of the tailroom in segment s.
 *
 * uint32_t s_tailroom(const struct sbuf *s)

 *
 * Return the size of the headroom in segment s.
 *
 * uint32_t s_headroom(const struct sbuf *s)

 *
 * uint32_t m_copytobuf(void *dest, const struct mbuf *m, uint32_t off, uint32_t len)
 *
 * Copy len bytes from source mbuf m, at offset off, to memory area
 * dest. The memory areas should not overlap.
 *   o If off > m_len(m), packet and destination buffer are not modified.
 *   o If len > (m_len(m)-off), only (m_len(m)-off) bytes are copied.
 * The function returns the number of copied bytes.


 *
 * uint32_t m_copyfrombuf(struct mbuf *m, uint32_t off, const void *src, uint32_t len)
 *
 * Copy len bytes from source buffer src, to mbuf m at offset off. The
 * memory areas should not overlap. If there is not enough room in
 * segments, the function automatically allocates segments to store
 * data. The m_copyfrombuf() function returns the number of copied
 * bytes. If the function fails (segment allocation), the return value
 * can be different of len.
 * If the off argument is m_len(m), then this function can be used to
 * append data in mbuf, allocating new segments if necessary.

 *
 * struct mbuf *m_copypack(const struct mbuf *m, uint32_t off, uint32_t len)
 *
 * Duplicate an area of a packet in a new mbuf, starting of offset off and
 * finishing after len bytes. The function returns the new mbuf on
 * success, or NULL on error.
 *

 * struct mbuf *m_split(struct mbuf *m, uint32_t off)
 *
 * Split a mbuf in 2 mbufs at offset off. Let's call m1 the original
 * mbuf and m2 the returned mbuf. The function allocates a new buffer m2
 * and copies the minimum of data at offset off of m1 in the first
 * segment of m2. The last segments of m1 are relinked to m2. In case of
 * error, the function returns NULL and m1 is left unmodified.


 * struct mbuf *m_dup(const struct mbuf *m);
 *
 * Duplicate the mbuf m. Also copy the input_port in the new
 * mbuf. Return NULL in case of error. 
 * Note: The private part of the mbuf is copied too.


 * struct mbuf *m_pullup(struct mbuf *m, uint32_t len);
 *
 * Check that the first "len" bytes of mbuf are contiguous. If not,
 * reorganize segments in mbuf to matches this condition. On error, it
 * returns NULL: in this case the mbuf and all its segments are
 * freed. On success, it returns the mbuf "m" that can be left
 * unmodified (if len bytes are already contiguous) or have some
 * intermediate segments deleted. Note: it is not possible to pullup
 * more than the maximum segment size which is architecture dependant
 * (around 2K usually).
 * If there is room, it will add up to m_max_protohdr extra bytes
 * to the contiguous region in an attempt to avoid being called next
 * time.


 * struct mbuf *m_shrink(struct mbuf *m);
 *
 * Reorganize segments in mbuf in order to have as much data as
 * possible in each segment. On error, it returns NULL: in this case
 * the mbuf and all its segments are freed. On success, return the mbuf
 * "m".

 * struct mbuf *m_clone(struct mbuf *m)
 *
 * Duplicate a mbuf without copying the carried data. The packet becomes
 * read-only. The user should call m_unclone() before modifying the packet.

 * struct mbuf *m_unclone(struct mbuf *m)
 *
 * If the mbuf is not a clone, do nothing. Else, duplicate the mbuf to have
 * a read/write copy of the packet.

 * void m_dump(const struct mbuf *m, int dump_len)
 *
 * Dump a mbuf structure on the console. If dump_len != 0, also dump
 * the "dump_len" first bytes of the packet.

 * struct mbuf *m_clone_area(struct mbuf *m, uint32_t writable, uint32_t off,
 *			  uint32_t len)
 *
 * Create a clone of an mbuf, that references 'len' bytes of the original mbuf
 * starting at offset 'off'.
 * The first 'writable' bytes (starting at offset 'off') are copied instead of
 * being references to the original segments.

 * int m_set_process_fct(struct mbuf *m, void *f, void *arg)
 *
 * Store a callback 'f' with a parameter 'arg' for future execution.

 * int m_call_process_fct(struct mbuf *m)
 *
 * Execute mbuf associated callback.

 * void m_freeback(struct mbuf *m)
 *
 * Release hardware resources associated to this mbuf if necessary.
 * On some platforms, a mbuf received on a physical port may still reference
 * resources that are also referenced by the hardware. By default, it assumes
 * that the resources are released because the packet is freed or forwarded
 * to another hardware interface. If the mbuf is kept by software (for instance
 * in a queue), this function has to be called.
 * This function does nothing on most platforms.

 */
#include "fpn-mbuf-track.h"

/* Egress color info */
#define FPN_QOS_COLOR_GREEN    0 /* default */
#define FPN_QOS_COLOR_YELLOW   1
#define FPN_QOS_COLOR_RED      2
#define FPN_QOS_COLOR_MAX      2

/* fpn mbuf flags.
 * Note: M_F_BCAST and M_F_MCAST are exclusive.
 */
#define M_F_SHARED_BIT     0
#define M_F_SHARED         (1 << M_F_SHARED_BIT) /* may have shared segments, don't use hw free */
#define M_F_BCAST_BIT      1 /* send/received as link-level broadcast */
#define M_F_BCAST          (1 << M_F_BCAST_BIT)
#define M_F_MCAST_BIT      2 /* send/received as link-level multicast */
#define M_F_MCAST          (1 << M_F_MCAST_BIT)
#define M_F_OTHERHOST_BIT  3 /* packet destined to other host */
#define M_F_OTHERHOST      (1 << M_F_OTHERHOST_BIT) /* XXX: not set by fpn-sdk */
#define M_F_MAX_BIT        3
#define M_F_MAX            (1 << M_F_MAX_BIT)

extern struct mbuf *m_dup(const struct mbuf *m);

extern void m_dump(const struct mbuf *m, int dump_data);

extern void __m_check(const struct mbuf *m,
		      const char *file, int line, const char *func);

#ifdef CONFIG_MCORE_FPN_MBUF_CHECK
#define m_check(m) __m_check(m, __FILE__, __LINE__, __func__)
#else
#define m_check(m) do { } while (0)
#endif

/* macro that loops for each segments owned in mbuf m. */
#define M_FOREACH_SEGMENT(m, s) \
	for (s=m_first_seg(m); s; s=s_next(m,s))

/* macro that returns the length of the first segment */
#define m_headlen(m) ((uint32_t)s_len(m_first_seg(m)))

/* macro that returns the size of tailroom in last segment */
#define m_tailroom(m) (s_tailroom(m_last_seg(m)))

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
#define m_is_shared(m) (m_get_flags(m) & M_F_SHARED)
#else
#define m_is_shared(m) 0
#endif

#if !defined(CONFIG_MCORE_FPE_VFP)
#define __m_set_data(m, d)       do { } while(0) /* no mbuf_data, do nothing */
#endif

extern uint32_t __m_copytobuf(void *dest, const struct mbuf *m, uint32_t off, uint32_t len);

extern uint32_t __m_copyfrombuf(struct mbuf *m, uint32_t off, const void *src, uint32_t len);

extern struct mbuf *m_copypack(const struct mbuf *m, uint32_t off, uint32_t len);

extern struct mbuf *m_split(struct mbuf *m, uint32_t off);
extern uint32_t __m_trim(struct mbuf *m, uint32_t len);
extern struct mbuf *__m_pullup(struct mbuf *m, uint32_t len);

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
extern struct mbuf *m_clone(struct mbuf *m);
extern struct mbuf *m_clone_area(struct mbuf *m, uint32_t writable, uint32_t off,
				 uint32_t len);
extern char *__m_adj2_clone(struct mbuf *m, uint32_t len);
#endif

#ifdef CONFIG_MCORE_ARCH_NPS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

extern char *__m_adj2(struct mbuf *m, uint32_t len);
static inline char *m_adj2(struct mbuf *m, uint32_t len)
{
	struct sbuf *s;
	char *d;

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	if (m_is_shared(m))
		return __m_adj2_clone(m, len);
#endif

	/* simple case: remove data at beginning of first sbuf */
	s = m_first_seg(m);
	if (likely(len < s_len(s))) {
		__m_set_len(m, m_len(m) - len);
		__s_adj(s, len);

		d = s_data(s, char *);
		__m_set_data(m, d);
		return d;
	}
	return __m_adj2(m, len);
}

static inline void m_freem(struct mbuf *m)
{
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	if (m_is_shared(m)) {
		__m_freem_clone(m);
		return;
	}
#endif

	/* the packet was never cloned, don't need to check ref
	 * counts */
	__m_freem(m);
}

static inline uint32_t m_copytobuf(void *dest, const struct mbuf *m, uint32_t off, uint32_t len)
{
	const struct sbuf *s = m_first_seg(m);

	if (likely(s_len(s) >= off + len)) {
		memcpy(dest, s_data(s, char *) + off, len);
		return len;
	} else {
		return __m_copytobuf(dest, m, off, len);
	}
}

static inline uint32_t m_copyfrombuf(struct mbuf *m, uint32_t off, const void *src, uint32_t len)
{
	struct sbuf *s = m_first_seg(m);

	if (likely(s_len(s) >= off + len)) {
		memcpy(s_data(s, char *) + off, src, len);
		return len;
	} else {
		return __m_copyfrombuf(m, off, src, len);
	}
}

#ifdef CONFIG_MCORE_ARCH_NPS
#pragma GCC diagnostic pop
#endif

static inline struct mbuf *m_pullup(struct mbuf *m, uint32_t len)
{
	if (likely(m_headlen(m) >= len))
		return m;
	else
		return __m_pullup(m, len);
}

struct mbuf *m_shrink(struct mbuf *m);

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
static inline struct mbuf *m_unclone(struct mbuf *m)
{
	struct mbuf *m2;

	if (!m_is_shared(m))
		return m;

	m2 = m_dup(m);
	m_freem(m);

	return m2; /* can be NULL if m_dup() failed */
}
#endif

/* m_trim() do support jumbo-frame */
#ifndef HAVE_ARCH_MTRIM
static inline uint32_t m_trim(struct mbuf *m, uint32_t len)
{
#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
	FPN_ASSERT(!m_is_shared(m));
	/* m_trim() is currently not supported on clones */
	if (m_is_shared(m))
		return 0;
#endif
	return __m_trim(m, len);
}
#endif

#endif /* _FPN_MBUF_H_ */
