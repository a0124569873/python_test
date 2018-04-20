/*
 * Copyright 2004-2013 6WIND S.A.
 */

#ifndef __VNBLINUX__
#define __VNBLINUX__

/*
 * When needed, VNB_DEBUG must be defined here, never in makefiles nor anywhere
 * else to make sure that all files use the same definition.
 */
#ifdef VNB_DEBUG
#error Only vnblinux.h is allowed to define VNB_DEBUG.
#else
#define VNB_DEBUG 0
#endif

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
#include <linux/export.h>
#endif
#include <asm/byteorder.h>
#include <net/sock.h>

#define SKB_RESERVED_HEADER_SIZE NET_SKB_PAD


/*
  NG_KASSERT(condition, (format string[, ...]))
  KASSERT(condition)

  The mess below takes care of the extra parenthesis around the format
  string and its arguments to feed it to WARN_ONCE() with some additional
  information. This is a remnant from the original KASSERT() prototype.
*/

#define __NG_KASSERT(f, c, r, s, ...)					\
	WARN_ONCE((r), "KASSERT: %s: `" c "': " s "%c", f, __VA_ARGS__)

#define ___NG_KASSERT(...) __NG_KASSERT(__VA_ARGS__)
#define ____NG_KASSERT(...) __VA_ARGS__

#define NG_KASSERT(cond, pstr)						\
	___NG_KASSERT(__func__, # cond, (!(cond)), ____NG_KASSERT pstr, '\n')
#define KASSERT(cond) NG_KASSERT(cond, ("assertion failed"))

/*
  VNB_TRAP([format string[, ...]])

  This macro depends on VNB_DEBUG == 1 to work. It's a generic replacement for
  the old TRAP_ERROR. Its only purpose is to log a message when VNB_DEBUG is
  enabled. Format string can be left empty.
*/

#if !defined(VNB_DEBUG) || VNB_DEBUG == 0
#define VNB_TRAP(...) (void)0
#elif defined(VNB_DEBUG) && VNB_DEBUG == 1
static inline const char *__vnb_trap_basename(const char *file)
{
	const char *i;

	for (i = file; (*i != '\0'); ++i)
		if (*i == '/')
			file = (i + 1);
	return file;
}
#define __VNB_TRAP(s, ...)				\
	(printk((const char *){ s "\n" },		\
		__vnb_trap_basename(__FILE__),		\
		__LINE__, __func__, __VA_ARGS__))
#define VNB_TRAP(...)							\
	(__VNB_TRAP(KERN_INFO "VNB_TRAP %s:%d: %s: " __VA_ARGS__, 0), (void)0)
#endif

/* enable asynchronous netdevice removal */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define ASYNCHRONOUS_NETDEV_REMOVAL
#endif

/* skb frag_list manipulation macros */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
  #ifdef RHEL_RELEASE_CODE
    #if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,5)
      #define skb_has_frag_list(...) skb_has_frags(__VA_ARGS__)
    #endif
  #else
    #define skb_has_frag_list(...) skb_has_frags(__VA_ARGS__)
  #endif
#endif

#define ___htonll(x) __cpu_to_be64(x)
#define ___ntohll(x) __be64_to_cpu(x)

#define htonll(x) ___htonll(x)
#define ntohll(x) ___ntohll(x)

#define VNB_BIG_ENDIAN     1
#define VNB_LITTLE_ENDIAN  2
#if defined(__BIG_ENDIAN)
#define VNB_BYTE_ORDER VNB_BIG_ENDIAN
#elif defined(__LITTLE_ENDIAN)
#define VNB_BYTE_ORDER VNB_LITTLE_ENDIAN
#else
#error "endianness not defined"
#endif

#define M_ALLOC_SIZE		2048
#define M_ALLOC_HEADROOM	128

#define strtoul simple_strtoul
/* XXX simple_strtoll symbol not found ? */
static __inline long long strtoq(const char *cp,char **endp,unsigned int base)
{
        if(*cp=='-')
                return -simple_strtoull(cp+1,endp,base);
        return simple_strtoull(cp,endp,base);
}
#define strtol simple_strtol
#define bcmp memcmp
#define ifnet net_device
#define mbuf sk_buff
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define m_iif(m) m->iif
#else
#define m_iif(m) m->skb_iif
#endif
#define mtod(m, c)	((c)(m->data))
#define m_freem(m)      kfree_skb(m)
#define m_dup(m, a)	skb_copy(m, GFP_ATOMIC)
#define m_copypacket(m, f)	skb_copy(m, GFP_ATOMIC)
#define m_copydata(m,o,l,c)     memcpy(c, m->data+o, l)
#define m_adj(m, l)		skb_pull(m, l)
#define M_ZERO 0x1
#define M_WAITOK 0x2
#define M_NOWAIT 0
#define M_DONTWAIT	0

/* Do *NOT* use MALLOC()/FREE() for data that may be freed outside of VNB. */
#if defined(VNB_DEBUG) && VNB_DEBUG == 1

/*
  The memory debugging functions below are much faster than Linux's kmemcheck
  which in addition to being slow also forces Linux to run on a single core,
  removing most race conditions in the process. You probably also want to
  enable CONFIG_STACKTRACE in the kernel.
*/

#ifdef CONFIG_STACKTRACE
#include <linux/stacktrace.h>
#endif /* CONFIG_STACKTRACE */

struct MALLOC_debug {
	size_t size;
	void *magic;
#ifdef CONFIG_STACKTRACE
	void *malloc_trace[8];
	void *free_trace[8];
	void *unref_trace[8];
#endif /* CONFIG_STACKTRACE */
	unsigned long data[];
};

/*
  Poison allocated memory with 0xfa, prepend allocated size and a magic,
  store allocation stack trace.
*/
static inline void *MALLOC_debug(size_t size, unsigned int flags)
{
#ifdef CONFIG_STACKTRACE
	struct stack_trace st;
#endif /* CONFIG_STACKTRACE */
	struct MALLOC_debug *m;

	m = kmalloc((sizeof(*m) + size),
		    ((flags & M_WAITOK) ? GFP_KERNEL : GFP_ATOMIC));
	if (m == NULL)
		return NULL;
	m->size = size;
	m->magic = (void *)0xafafafaf;
#ifdef CONFIG_STACKTRACE
	st.max_entries =
		(sizeof(m->malloc_trace) / sizeof(m->malloc_trace[0]));
	st.nr_entries = 0;
	st.entries = (unsigned long *)m->malloc_trace;
	st.skip = 1;
	memset(m->malloc_trace, 0x00, sizeof(m->malloc_trace));
	memset(m->unref_trace, 0x00, sizeof(m->unref_trace));
	save_stack_trace(&st);
	memset(m->free_trace, 0x00, sizeof(m->free_trace));
#endif /* CONFIG_STACKTRACE */
	if (flags & M_ZERO)
		memset(m->data, 0x00, size);
	else
		memset(m->data, 0xfa, size);
	return m->data;
}

/*
  Poison released memory with 0xfb or crash in case of an invalid free,
  store deallocation stack trace.
*/
static inline void FREE_debug(void *p)
{
#ifdef CONFIG_STACKTRACE
	struct stack_trace st;
#endif /* CONFIG_STACKTRACE */
	struct MALLOC_debug *m;
	size_t size;

	if (p == NULL)
		return;
	m = ((struct MALLOC_debug *)p - 1);
	BUG_ON(m->magic != (void *)0xafafafaf);
	m->magic = (void *)0xbfbfbfbf;
	size = m->size;
#ifdef CONFIG_STACKTRACE
	st.max_entries = (sizeof(m->free_trace) / sizeof(m->free_trace[0]));
	st.nr_entries = 0;
	st.entries = (unsigned long *)m->free_trace;
	st.skip = 1;
	save_stack_trace(&st);
#endif /* CONFIG_STACKTRACE */
	memset(m->data, 0xfb, size);
	kfree(m);
}

#define MALLOC(d, c, l, t, w) ((d = (c)MALLOC_debug((l), (w))))
#define FREE(d, t) (FREE_debug(d))

#else

#define MALLOC(d, c, l, t, w)				\
	((((d = (c)kmalloc((l),				\
			   (((w) & M_WAITOK) ?		\
			    GFP_KERNEL :		\
			    GFP_ATOMIC))) != NULL) &&	\
	  ((w) & M_ZERO)) ?				\
	 ((void)memset((d), 0x00, (l)), (c)(d)) :	\
	 (c)(d))
#define FREE(d, t) (kfree(d))

#endif

#define bzero(c,l)      memset(c, 0, l)
#define bcopy(s,d,l)    memcpy(d, s, l)

#define soisdisconnected(so) sock_orphan(so->sk)

#define M_PREPEND(skb, size, how) ((skb) = m_prepend((skb), (size)))

static inline struct sk_buff *m_prepend(struct sk_buff *m, unsigned int len)
{
	struct sk_buff *m_tmp = m;

	if (unlikely(skb_headroom(m) < len)) {
		m = skb_realloc_headroom(m_tmp, len);
		kfree_skb(m_tmp);
	} else if (unlikely(skb_cloned(m))) {
		m = pskb_copy(m_tmp, GFP_ATOMIC);
		kfree_skb(m_tmp);
	}
	if (likely(m))
		skb_push(m, len);
	return m;
}

static inline unsigned int m_trim(struct sk_buff *m, unsigned int len)
{
	if ((len >= m->len) ||
	    (pskb_trim(m, (m->len - len)) != 0))
		return 0;
	return len;
}

static inline struct sk_buff *m_last_seg(struct sk_buff *m)
{
	if (skb_shinfo(m)->frag_list != NULL) {
		m = skb_shinfo(m)->frag_list;
		while (m->next != NULL)
			m = m->next;
	}
	return m;
}

static inline struct sk_buff *m_alloc(void)
{
	struct sk_buff *ret = alloc_skb(M_ALLOC_SIZE, GFP_ATOMIC);

	if (ret != NULL)
		skb_reserve(ret, M_ALLOC_HEADROOM);
	return ret;
}

static inline char *m_append(struct sk_buff *m, unsigned int len)
{
	uint8_t *ret;
	int truesize;
	struct sk_buff *l = m_last_seg(m);

	truesize = l->truesize;
	if ((skb_linearize(l) != 0) ||
	    ((unsigned int)skb_tailroom(l) < len))
		return NULL;
	ret = skb_put(l, len);
	if (l != m) {
		/* manually increase sizes of the head skb */
		m->len += len;
		m->data_len += len;
		m->truesize -= truesize;
		m->truesize += l->truesize;
	}
	return (char *)ret;
}

/* same as m_append, except that it may expand m if necessary */
static inline char *m_append_expand(struct sk_buff *m, unsigned int len)
{
	uint8_t *ret;
	int truesize;
	struct sk_buff *l = m_last_seg(m);

	truesize = l->truesize;
	if ((skb_linearize(l) != 0) ||
	    (((unsigned int)skb_tailroom(l) < len) &&
	     (pskb_expand_head(l, 0, (len - skb_tailroom(l)), GFP_ATOMIC))))
		return NULL;
	ret = skb_put(l, len);
	if (l != m) {
		/* manually increase sizes of the head skb */
		m->len += len;
		m->data_len += len;
		m->truesize -= truesize;
		m->truesize += l->truesize;
	}
	return (char *)ret;
}

static inline int m_cat(struct sk_buff *m1, struct sk_buff *m2)
{
	NG_KASSERT(m1 != m2, ("m1 and m2 are the same"));
	NG_KASSERT(m2->next == NULL, ("m2 is a fragment"));
	/* add m2 total length to m1 */
	m1->len += m2->len;
	m1->data_len += m2->len;
	m1->truesize += m2->truesize;
	if (unlikely(skb_has_frag_list(m2))) {
		unsigned int sub = 0;
		unsigned int ts_sub = 0;
		struct sk_buff *cur;

		skb_walk_frags(m2, cur) {
			sub += cur->len;
			ts_sub += cur->truesize;
		}
		/* sanity check */
		BUG_ON(sub > m2->len);
		BUG_ON(ts_sub > m2->truesize);
		/* fix m2 lengths */
		m2->len -= sub;
		m2->data_len -= sub;
		m2->truesize -= ts_sub;
		/* m2 becomes a fragment */
		m2->next = skb_shinfo(m2)->frag_list;
		skb_shinfo(m2)->frag_list = NULL;
	}
	/* link them together */
	if (skb_has_frag_list(m1)) {
		m1 = m_last_seg(m1);
		m1->next = m2;
	}
	else
		skb_shinfo(m1)->frag_list = m2;
	return 0;
}

/* try to cram m1 and m2 together to free m2, return 0 on success */
static inline int m_cram(struct sk_buff *m1, struct sk_buff *m2)
{
	uint8_t *data;

	NG_KASSERT(m1 != m2, ("m1 and m2 are the same"));
	NG_KASSERT(m2->next == NULL, ("m2 is a fragment"));
	if ((data = m_append_expand(m1, m2->len)) == NULL)
		return -1;
	skb_copy_bits(m2, 0, data, m2->len);
	kfree_skb(m2);
	return 0;
}

/* Total length of mbuf */
#define MBUF_LENGTH(m) (m)->len

#define M_SPLIT(m, l, f) m_split((m), (l), (f))

/* split m into two buffers, return the tail */
static inline struct sk_buff *m_split(struct sk_buff *m1, int len, int flag)
{
	struct sk_buff *m2 = NULL;
	struct sk_buff *cur;
	unsigned int off;
	unsigned int ts;

	(void)flag;
	if ((len <= 0) || ((unsigned int)len >= m1->len))
		return NULL;
	if (likely(!skb_has_frag_list(m1))) {
		/* no frag_list, allocate m2 */
		cur = m1;
		if ((m2 = alloc_skb((m1->len - len), GFP_ATOMIC)) == NULL)
			return NULL;
		skb_split(m1, m2, len);
		return m2;
	}
	off = 0;
	skb_walk_frags(m1, cur) {
		unsigned int tmp = (off + cur->len);

		if (tmp == (unsigned int)len) {
			/* the next frag becomes m2 */
			m2 = cur->next;
			skb_shinfo(m2)->frag_list = m2->next;
			m2->next = NULL;
			cur->next = NULL;
			break;
		}
		else if (tmp > (unsigned int)len) {
			if (off == 0) {
				/* frag_list becomes m2 */
				m2 = cur;
				skb_shinfo(m2)->frag_list = m2->next;
				m2->next = NULL;
				BUG_ON(skb_shinfo(m1)->frag_list == NULL);
				skb_shinfo(m1)->frag_list = NULL;
				break;
			}
			/* m2 needs to be allocated */
			m2 = alloc_skb((m1->len - len), GFP_ATOMIC);
			if (m2 == NULL)
				return NULL;
			skb_split(cur, m2, (len - off));
			skb_shinfo(m2)->frag_list = cur->next;
			cur->next = NULL;
			break;
		}
		off = tmp;
	}
	BUG_ON(m2 == NULL);
	/* fix m2 sizes */
	off = 0;
	ts = 0;
	skb_walk_frags(m2, cur) {
		off += cur->len;
		ts += cur->truesize;
	}
	m2->len += off;
	m2->data_len += off;
	m2->truesize += ts;
	/* fix m1 sizes */
	m1->len -= m2->len;
	m1->data_len -= m2->len;
	m1->truesize -= m2->truesize;
	return m2;
}

static inline struct sk_buff *m_pullup(struct sk_buff *m, int len)
{
	if (!pskb_may_pull(m, len)) {
		kfree_skb(m);
		m = NULL;
	}
	return m;
}

static inline uint32_t m_copytobuf(void *dest, const struct sk_buff *m,
				   uint32_t off, uint32_t len)
{
	if (len > m->len)
		len = m->len;
	skb_copy_bits(m, off, dest, len);
	return len;
}

static inline uint32_t m_copyfrombuf(struct sk_buff *m, uint32_t off,
				     const void *src, uint32_t len)
{
	uint32_t req = (off + len);

	if ((m->len < req) &&
	    (m_append_expand(m, (req - m->len)) == NULL))
		return 0;
	skb_store_bits(m, off, src, len);
	return len;
}

#if defined(CONFIG_64BIT)
typedef int64_t         intptr_t;
#else
typedef int             intptr_t;
#endif
typedef int64_t         quad_t;


typedef atomic_t vnb_atomic_t;
#define VNB_ATOMIC_INIT(i)		ATOMIC_INIT(i)
#define vnb_atomic_read(v)		atomic_read(v)
#define vnb_atomic_set(v, i)		atomic_set(v, i)
#define vnb_atomic_add(i, v)		atomic_add(i, v)
#define vnb_atomic_sub(i, v)		atomic_sub(i, v)
#define vnb_atomic_inc(v)		atomic_inc(v)
#define vnb_atomic_dec(v)		atomic_dec(v)
#define vnb_atomic_dec_and_test(v)	atomic_dec_and_test(v)
#define vnb_atomic_inc_and_test(v)	atomic_inc_and_test(v)

#include <linux/spinlock.h>

typedef spinlock_t vnb_spinlock_t;
#define vnb_spinlock_init(x) spin_lock_init(x)
#define vnb_spinlock_lock(x) spin_lock_bh(x)
#define vnb_spinlock_trylock(x) spin_trylock_bh(x)
#define vnb_spinlock_unlock(x) spin_unlock_bh(x)

#define vnb_mutex_lock mutex_lock
#define vnb_mutex_unlock mutex_unlock

typedef rwlock_t vnb_rwlock_t;
#define vnb_rwlock_init rwlock_init
#define vnb_read_lock read_lock
#define vnb_read_unlock read_unlock
#define vnb_write_lock write_lock
#define vnb_write_unlock write_unlock

#define _KERNEL	1

#define LOG_EMERG KERN_EMERG /* system is unusable */
#define LOG_ALERT KERN_ALERT /* action must be taken immediately */
#define LOG_CRIT KERN_CRIT /* critical conditions */
#define LOG_ERR KERN_ERR /* error conditions */
#define LOG_WARNING KERN_WARNING /* warning conditions */
#define LOG_NOTICE KERN_NOTICE /* normal but significant condition */
#define LOG_INFO KERN_INFO /* informational */
#define LOG_DEBUG KERN_DEBUG /* debug-level messages */

#define log(level, ...) printk(level __VA_ARGS__)

#define NBBY    8               /* number of bits in a byte */

/* timers */

/* vnb code must use struct vnb_timeval and vnb_time_t */
#define vnb_time_t time_t
#define vnb_timeval timeval

#define microtime(x) do_gettimeofday(x)
#define timevalcmp(tvp, uvp, cmp)		\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?	\
	 ((tvp)->tv_usec cmp (uvp)->tv_usec) :	\
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

/*
 * Add and subtract routines for timevals.
 * N.B.: subtract routine doesn't deal with
 * results which are before the beginning,
 * it just gets very confused in this case.
 * Caveat emptor.
 */

static inline void timevalfix(struct vnb_timeval *t1)
{
	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
	if (t1->tv_usec >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

static inline void timevaladd(struct vnb_timeval *t1, struct vnb_timeval *t2)
{
	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}

static inline void timevalsub(struct vnb_timeval *t1, struct vnb_timeval *t2)
{
	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}

#include <netgraph_linux/callout.h>

#define hz	HZ

#ifndef MAX_SOCK_ADDR
#define MAX_SOCK_ADDR	128
#endif
#ifndef INET6
#define INET6 1
#endif
#ifndef INET
#define INET 1
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN    46
#endif

#define VNB_DEFINE_SHARED(type, name) __typeof__(type) name
#define VNB_DECLARE_SHARED(type, name) extern __typeof__(type) name

#define VNB_BUILD_BUG_ON(x) BUILD_BUG_ON(x)

#ifdef CONFIG_SMP
#define VNB_NR_CPUS CONFIG_NR_CPUS
#define VNB_CORE_ID() smp_processor_id()
#else
#define VNB_NR_CPUS 1
#define VNB_CORE_ID() 0
#endif

typedef struct vnb_core_state_s {
	int state;   /* flag: whether core is in critical section */
	int exitcnt; /* counter: nb of times core exited critical section */
} vnb_core_state_t;

VNB_DECLARE_SHARED(volatile vnb_core_state_t, vnb_core_state[VNB_NR_CPUS]);
VNB_DECLARE_SHARED(vnb_core_state_t, vnb_core_nb_instances[VNB_NR_CPUS]);

#define GC_DEBUG 0

/*
 * In order to protect shared data and per-core variables, VNB_ENTER()
 * and VNB_EXIT() must use preempt_disable()/preempt_enable() to prevent
 * rescheduling on a different core and invalidate per-core indices.
 */

#if GC_DEBUG
#define VNB_ENTER()	do {						\
		preempt_disable();					\
		vnb_core_nb_instances[VNB_CORE_ID()].state++;	\
		vnb_core_state[VNB_CORE_ID()].state = 1;		\
		log(LOG_ERR, "Enter VNB in %s: %d: state: %d, instances: %d\n",	\
		    __FUNCTION__, __LINE__,				\
		    vnb_core_state[VNB_CORE_ID()].state,		\
		    vnb_core_nb_instances[VNB_CORE_ID()].state);	\
	} while (0)

#define VNB_EXIT()	do {						\
		log(LOG_ERR, "Exit VNB in %s: %d: state: %d\n",		\
		    __FUNCTION__, __LINE__,				\
		    vnb_core_state[VNB_CORE_ID()].state);		\
		if ((--vnb_core_nb_instances[VNB_CORE_ID()].state) == 0) {	\
			vnb_core_state[VNB_CORE_ID()].state = 0;	\
			vnb_core_state[VNB_CORE_ID()].exitcnt++;		\
			log(LOG_ERR, "Reset core state %s: %d: state: %d, instances: %d\n", \
			    __FUNCTION__, __LINE__,			\
			    vnb_core_state[VNB_CORE_ID()].state,	\
			    vnb_core_nb_instances[VNB_CORE_ID()].state); \
		}							\
		preempt_enable();					\
	} while (0)
#else
#define VNB_ENTER()	do {						\
		preempt_disable();					\
		vnb_core_nb_instances[VNB_CORE_ID()].state++;	\
		vnb_core_state[VNB_CORE_ID()].state = 1;		\
	} while (0)

#define VNB_EXIT()	do {						\
		if ((--vnb_core_nb_instances[VNB_CORE_ID()].state) == 0) {	\
			vnb_core_state[VNB_CORE_ID()].state = 0;	\
			vnb_core_state[VNB_CORE_ID()].exitcnt++;	 	\
		}							\
		preempt_enable();					\
	} while (0)
#endif

#define VNB_DUP_NG_MESG(new, old) ({						\
		int __error = 0;						\
		MALLOC((new), struct ng_mesg *,					\
		       sizeof(struct ng_mesg) + (old)->header.arglen,		\
			      M_NETGRAPH, M_NOWAIT);				\
		if ((new) == NULL)						\
			__error = ENOMEM;					\
		else								\
			memcpy((new), (old),					\
			       sizeof(struct ng_mesg) + (old)->header.arglen);	\
		__error;							\
	})

struct vnb_skb_parms {
	u64	vnb_magic;
#define VNB_MAGIC_SKIP	0x2010102212072012ULL
};
#define VNB_CB(skb)         (*(struct vnb_skb_parms*)&((skb)->cb))

/*  Return a netns of a packet */
static inline struct net * packet_net(struct mbuf *m)
{
	struct net *net = NULL;
	if (m->dev)
		net = dev_net(m->dev);
	else if (m->sk)
		net = sock_net(m->sk);

	return net;
}

#endif
