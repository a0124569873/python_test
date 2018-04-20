#ifndef _FP_NETGRAPH_H_
#define _FP_NETGRAPH_H_

/*
 * When needed, VNB_DEBUG must be defined here, never in makefiles nor anywhere
 * else to make sure that all files use the same definition.
 */
#ifdef VNB_DEBUG
#error Only fp-netgraph.h is allowed to define VNB_DEBUG.
#else
#define VNB_DEBUG 0
#endif

#include "fpn.h"
#include "fp-includes.h"
#include "fp-bsd-compat.h"
#include "fp-log.h"

#ifdef CONFIG_MCORE_VNB_MAX_NS
#define VNB_MAX_NS CONFIG_MCORE_VNB_MAX_NS
#endif

#ifndef LOG_EMERG
#define LOG_EMERG   FP_LOG_EMERG
#endif
#ifndef LOG_ALERT
#define LOG_ALERT   FP_LOG_ALERT
#endif
#ifndef LOG_CRIT
#define LOG_CRIT    FP_LOG_CRIT
#endif
#ifndef LOG_ERR
#define LOG_ERR     FP_LOG_ERR
#endif
#ifndef LOG_WARNING
#define LOG_WARNING FP_LOG_WARNING
#endif
#ifndef LOG_NOTICE
#define LOG_NOTICE  FP_LOG_NOTICE
#endif
#ifndef LOG_INFO
#define LOG_INFO    FP_LOG_INFO
#endif
#ifndef LOG_DEBUG
#define LOG_DEBUG   FP_LOG_DEBUG
#endif

/* XXX */
#define splhigh(x) 0
#define splnet(x) 0
#define splx(x)

typedef fpn_spinlock_t vnb_spinlock_t;
#define vnb_spinlock_init(x) fpn_spinlock_init(x)
#define vnb_spinlock_lock(x) fpn_spinlock_lock(x)
#define vnb_spinlock_trylock(x) fpn_spinlock_trylock(x)
#define vnb_spinlock_unlock(x) fpn_spinlock_unlock(x)

typedef fpn_rwlock_t vnb_rwlock_t;
#define vnb_rwlock_init fpn_rwlock_init
#define vnb_read_lock fpn_rwlock_read_lock
#define vnb_read_unlock fpn_rwlock_read_unlock
#define vnb_write_lock fpn_rwlock_write_lock
#define vnb_write_unlock fpn_rwlock_write_unlock

typedef fpn_atomic_t vnb_atomic_t;
#define VNB_ATOMIC_INIT(i)              FPN_ATOMIC_INIT(i)
#define vnb_atomic_read(v)              fpn_atomic_read(v)
#define vnb_atomic_set(v, i)            fpn_atomic_set(v, i)
#define vnb_atomic_add(v, i)            fpn_atomic_add(v, i)
#define vnb_atomic_sub(v, i)            fpn_atomic_sub(v, i)
#define vnb_atomic_inc(v)               fpn_atomic_inc(v)
#define vnb_atomic_dec(v)               fpn_atomic_dec(v)
#define vnb_atomic_dec_and_test(v)      fpn_atomic_dec_and_test(v)
#define vnb_atomic_inc_and_test(v)      fpn_atomic_inc_and_test(v)

#define M_NETGRAPH 0
#define M_NOWAIT 0
#define M_WAITOK 1
#define M_ZERO 2

#define MALLOC(d, c, l, t, w)   \
	d = (c)fpn_malloc(l, 0);				\
	if (d && ((w) & M_ZERO) == M_ZERO) bzero((d), (l))

#define FREE(d, t) fpn_free(d)


#define log(x, fmt, args...) FP_LOG(x, VNB, fmt, ## args)

#define TRACE_VNB(level, fmt, args...) do { \
   FP_LOG(level, VNB, fmt "\n", ## args);   \
} while(0)


#define VNB_ENTER() do {} while (0)
#define VNB_EXIT() do {} while (0)

#define intptr_t fpn_uintptr_t

#ifndef ULONG_MAX
#define ULONG_MAX FPN_ULONG_MAX
#endif

#define VNB_DECLARE_SHARED(type, var) FPN_DECLARE_SHARED(type, var)
#define VNB_DEFINE_SHARED(type, var)  FPN_DEFINE_SHARED(type, var)

#define VNB_BUILD_BUG_ON(x) BUILD_BUG_ON(x)

/*
  NG_KASSERT(condition, (format string[, ...]))
  KASSERT(condition)

  Disabled when CONFIG_MCORE_FPN_ASSERT_ENABLE isn't defined.
*/

#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE
#define __NG_KASSERT(cond, str, ...)					\
	(!(cond) ?							\
	 (fpn_printf("KASSERT: `" # cond "': " str "%c", __VA_ARGS__),	\
	  fpn_assert_fail(__FILE__, __LINE__, __func__, # cond)) :	\
	 (void)0)
#else /* CONFIG_MCORE_FPN_ASSERT_ENABLE */
#define __NG_KASSERT(cond, str, ...) ((void)0)
#endif /* CONFIG_MCORE_FPN_ASSERT_ENABLE */

/* the only purpose of these macros is to remove the extra parenthesis */
#define ___NG_KASSERT(...) __NG_KASSERT(__VA_ARGS__)
#define ____NG_KASSERT(...) __VA_ARGS__

#define NG_KASSERT(cond, pstr) ___NG_KASSERT((cond), ____NG_KASSERT pstr, '\n')

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
	(FP_LOG(FP_LOG_ERR, VNB, s "%c",		\
		__vnb_trap_basename(__FILE__),		\
		__LINE__, __func__, __VA_ARGS__))
#define VNB_TRAP(...)							\
	(__VNB_TRAP("VNB_TRAP %s:%d: %s: " __VA_ARGS__, '\n'), (void)0)
#endif

#define M_PREPEND(a,b,c) \
	do {					\
		if (m_prepend(a,b) == NULL) {	\
			m_freem(a);		\
			a = NULL;		\
		}				\
	} while (0)

#define MBUF_LENGTH(m) m_len(m)
#define M_SPLIT(m, l, f) m_split((m), (l))

#define VNB_CORE_ID() fpn_get_core_num()
#define VNB_NR_CPUS FPN_MAX_CORES

/* for struct fp_in_addr ( e.g. ng_parse.c) */
#define in_addr fp_in_addr
#define iphdr fp_ip
#define saddr ip_src.s_addr
#define daddr ip_dst.s_addr
#define in6_addr fp_in6_addr
#ifndef IPVERSION
#define IPVERSION FP_IPVERSION
#endif
#ifndef IPDEFTTL
#define IPDEFTTL FP_IPDEFTTL
#endif
#ifndef NIPQUAD
#define NIPQUAD FP_NIPQUAD
#endif

#define NG_NODE_CACHE   1

#define NG_BRIDGE_TIMER 1
#define NG_BRIDGE_FLOOD 1
//#define NG_BRIDGE_SNOOP 1

#define VNB_BYTE_ORDER    FPN_BYTE_ORDER
#define VNB_LITTLE_ENDIAN FPN_LITTLE_ENDIAN
#define VNB_BIG_ENDIAN    FPN_BIG_ENDIAN

#ifndef ECANCELED
#define ECANCELED            (__ELASTERROR + 2210)
#endif
#ifdef CONFIG_MCORE_KTABLES
#define HAVE_KTABLES
#endif

#ifndef HZ
#define HZ 1
#endif

#define vnb_core_state_t fpn_core_state_t
#define vnb_core_state fpn_core_state

typedef long vnb_time_t;

struct vnb_timeval {
	vnb_time_t tv_sec;
	long tv_usec;
};

static inline void microtime(struct vnb_timeval *tv)
{
	uint64_t freq = fpn_get_clock_hz();
	uint64_t cy = fpn_get_clock_cycles();

	tv->tv_sec = cy / freq;
	cy -= tv->tv_sec * freq;
	tv->tv_usec = cy * 1000000 / freq;
}

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

#define m_copypacket(m, f) m_dup(m)

#endif
