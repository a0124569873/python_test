/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FPN_H__
#define __FPN_H__

/* uint64_t definition */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#include <stdint.h>
#endif

#include "fpn-assert.h"
#include "fpn-queue.h"

/*
 * macro to define a shared variable <var> of type <type>,
 * don't use keyword like 'extern' or 'static' in type, just 
 * prefix the whole macro.
 * FPN_DEFINE_SHARED(type, var)
 * macro to declare an extern shared variable <var> of type <type>
 * FPN_DECLARE_SHARED(type, var)
 */

/*
 * macro to define a per core variable <var> of type <type>
 * FPN_DEFINE_PER_CORE(type, var)
 * macro to declare an extern per core variable <var> of type <type>
 * FPN_DECLARE_PER_CORE(type, var)
 * read the per-core variable value:
 * FPN_PER_CORE_VAR(var)
 */

/*
 * prefetch macro 
 * FPN_PREFETCH(addr)
 */

/* Get core number 
 * static inline int fpn_get_core_num() 
 */

/* Online cores: cores that run the fast path
 *
 * example, if cores 0, 2, 3 and 7 run the fast path:
 * fpn_get_online_core_count() = 4
 * fp_get_running_core_num(0) = 0
 * fp_get_running_core_num(1) = 2
 * fp_get_running_core_num(2) = 3
 * fp_get_running_core_num(4) = 7
 */

/* Get total count of cores running the fast path
 * unsigned fpn_get_online_core_count()
 */

/* Get core number of the n-th online core
 * rank should range from 0 to fp_get_online_core()
 * -1 is returned otherwise.
 * int fp_get_running_core_num(unsigned rank)
 */

/* Copy full ethernet header (14 bytes)
 * __attribute__((nonnull (1, 2))) static inline void fpn_ethcpy(void *eth, const void *eh)
 */

/*
 * printf function
 * fpn_printf(fmt, args...)
 */

/* __fpn_cache_aligned is used to align a structure on a cache line.
 * It must be set to __attribute__ ((aligned(n)))
 * where n is the size of a cache line.
 */
#define __fpn_cache_aligned __attribute__((aligned(FPN_CACHELINE_SIZE)))
#define FPN_CACHELINE_MASK (FPN_CACHELINE_SIZE-1)

/* __fpn_maybe_unused informs the compiler that this variable is maybe
 * unused and that a warning should not be displayed.
 */
#define __fpn_maybe_unused __attribute__((unused))

#define FPN_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define fpn_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define fpn_containerof(PTR, TYPE, MEMBER) \
	((TYPE *)((uint8_t *)(PTR) - fpn_offsetof(TYPE, MEMBER)))

#define fpn_roundup(x, y) (__builtin_constant_p (y) && fpn_ispowerof2 (y)      \
                           ? (((x) + (y) - 1) & ~((y) - 1))                  \
                           : ((((x) + ((y) - 1)) / (y)) * (y)))
#define fpn_ispowerof2(x) ((((x) - 1) & (x)) == 0)

#define FPN_MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      _a < _b ? _a : _b; })

#define FPN_MAX(a,b) \
   ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      _a > _b ? _a : _b; })

/* (a) must be a power of two */
#define FPN_ALIGN(x,a) ({ typeof(a) __a = (a); (((x)+ __a - 1) & ~(__a - 1)); })
#define FPN_ALIGN4(x) FPN_ALIGN(x,4)
#define FPN_ALIGN8(x) FPN_ALIGN(x,8)

/* Force a compilation error if condition is true */
#define FPN_BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#define FPN_LITTLE_ENDIAN 1234
#define FPN_BIG_ENDIAN 4321

/*
 * FPN_STATS_INC(addr) increment by one a 64-bit statistic
 * FPN_STATS_INC32(addr) increment by one a 32-bit statistic
 * FPN_STATS_ADD(addr, val) increment by val a 64-bit statistic
 * FPN_STATS_ADD32(addr, val) increment by val a 32-bit statistic
 */

/* up to 256 ports can be defined with 8 bits */
#if defined(CONFIG_MCORE_L2_INFRA)
#define FPN_ALL_PORTS 256
#endif
/* reserved portid values */
#define FPN_RESERVED_PORTID_FPN0 (255)  /* for CONTROL_PORTID */
#define FPN_RESERVED_PORTID_VIRT (254)  /* for FP_IFNET_VIRTUAL_PORT */

#ifdef CONFIG_MCORE_FPE_VFP

/* fpn-emulator on x86:
 * Maximum number of cores is actually the number of possible pthreads for
 * which there is no fixed limit, so we used an arbitrary high number instead.
 */
#define FPN_MAX_CORES 128

/*
 * Maximum number of ports managed by the fpn-sdk
 */
#define FPN_MAX_PORTS 64

/* assume 32 bytes, but it is often 64 on recent x86 */
#define FPN_CACHELINE_SIZE 32

#if defined(CONFIG_MCORE_ARCH_X86)
typedef uint32_t fpn_uintptr_t;
#define FPN_ULONG_MAX    4294967295UL
#define FPN_BYTE_ORDER FPN_LITTLE_ENDIAN
#elif defined (CONFIG_MCORE_ARCH_X86_64)
typedef uint64_t fpn_uintptr_t;
#define FPN_ULONG_MAX    18446744073709551615UL
#define FPN_BYTE_ORDER FPN_LITTLE_ENDIAN
#endif

typedef uint64_t fpn_core_set_t;
#define FPN_CORE_SET_DISP  PRIx64
#define FPN_CORE_SET_FILL  "016"

#ifdef __FastPath__
#include "emulator/fpn-emulator.h"
#endif

#endif /* CONFIG_MCORE_FPE_VFP */

#ifdef CONFIG_MCORE_ARCH_OCTEON

#define FPN_MAX_CORES 32
/* 64 ports are supported by the architecture (6-bit field
 * for w_port(work)). the last portid is reserved for fpn0
 */
#define FPN_MAX_PORTS 63
#define FPN_CACHELINE_SIZE 128
#define FPN_BYTE_ORDER FPN_BIG_ENDIAN
#define FPN_ULONG_MAX 18446744073709551615UL
typedef uint64_t fpn_uintptr_t;

typedef uint64_t fpn_core_set_t;
#define FPN_CORE_SET_DISP  PRIx64
#define FPN_CORE_SET_FILL  "016"

#ifdef __FastPath__
#include "octeon/fpn-octeon.h"
#endif

#endif /* CONFIG_MCORE_ARCH_OCTEON */

#ifdef CONFIG_MCORE_ARCH_XLP

typedef uint64_t fpn_core_set_t;
#define FPN_CORE_SET_DISP  PRIx64
#define FPN_CORE_SET_FILL  "016"

#include "xlp/fpn-xlp.h"
#endif

#ifdef CONFIG_MCORE_ARCH_DPDK

/* maximum number of lcores */
#define FPN_MAX_CORES 128
#define FPN_MAX_PORTS 64
#define FPN_CACHELINE_SIZE 64

typedef uint64_t fpn_core_set_t;
#define FPN_CORE_SET_DISP  PRIx64
#define FPN_CORE_SET_FILL  "016"

#if defined(CONFIG_MCORE_ARCH_X86)
typedef uint32_t fpn_uintptr_t;
#define FPN_ULONG_MAX    4294967295UL
#define FPN_BYTE_ORDER FPN_LITTLE_ENDIAN
#elif defined(CONFIG_MCORE_ARCH_X86_64)
typedef uint64_t fpn_uintptr_t;
#define FPN_ULONG_MAX    18446744073709551615UL
#define FPN_BYTE_ORDER FPN_LITTLE_ENDIAN
#elif defined(CONFIG_MCORE_ARCH_XLP_DPDK)
typedef uint64_t fpn_uintptr_t;
#define FPN_ULONG_MAX    18446744073709551615UL
#define FPN_BYTE_ORDER FPN_BIG_ENDIAN
#endif

#ifdef __FastPath__
#include "dpdk/fpn-dpdk.h"
#endif

#endif /* CONFIG_MCORE_ARCH_DPDK */

#ifdef CONFIG_MCORE_ARCH_TILEGX

#define FPN_MAX_CORES 72
#define FPN_MAX_PORTS 32
#define FPN_MAX_MPIPE_INSTANCE 2

#define FPN_MAX_BURST 32

#define L1I_CACHE_LINE_SIZE	64
#define L1D_CACHE_LINE_SIZE	64
#define L2_CACHE_LINE_SIZE	64
#define FPN_CACHELINE_SIZE	L2_CACHE_LINE_SIZE
#define FPN_BYTE_ORDER		FPN_LITTLE_ENDIAN
#define FPN_ULONG_MAX		18446744073709551615UL
typedef uint64_t fpn_uintptr_t;

typedef uint64_t fpn_core_set_t;
#define FPN_CORE_SET_DISP  PRIx64
#define FPN_CORE_SET_FILL  "016"

#ifdef __FastPath__
#include "tilegx/fpn-tilegx.h"
#endif

#endif /* CONFIG_MCORE_ARCH_TILEGX */

#ifdef CONFIG_MCORE_ARCH_NPS

/* fpn-sdk on EZchip NPS:
 * The maximum number of cores is actually 4k.
 */
#define FPN_MAX_CORES 256

/*
 * Maximum number of ports managed by the fpn-sdk
 */
#define FPN_MAX_PORTS 128

/* on NPS: 32 bytes in L1 cache, 128 bytes in L2 cache */
#define FPN_CACHELINE_SIZE 32

typedef uint32_t fpn_uintptr_t;
#define FPN_ULONG_MAX    4294967295UL
#define FPN_BYTE_ORDER FPN_BIG_ENDIAN

typedef uint64_t fpn_core_set_t;
#define FPN_CORE_SET_DISP  PRIx64
#define FPN_CORE_SET_FILL  "016"

#ifdef __FastPath__
#include "nps/fpn-nps.h"
#endif

#endif /* CONFIG_MCORE_ARCH_NPS */

#ifdef __FastPath__
#include "fpn-core.h"
#include "fpn-track.h"
#include "fpn-ftrace.h"
#include "fpn-lock.h"
#include "fpn-mbuf.h"
#include "fpn-div64.h"
#include "fpn-string.h"
#include "fpn-malloc.h"
#include "fpn-timer.h"
#include "fpn-job.h"
#include "fpn-cpu-usage.h"
#include "fpn-test-cycles.h"
#include "fpn-hook.h"

#ifndef FPN_HAVE_ETHCOPY
#include "fpn-eth.h"
#define fpn_ethcpy(x, y) memcpy(x, y, FPN_ETHER_HDR_LEN)
#endif

#ifndef FPN_HAVE_IPV4HDR_COPY
#define fpn_ipv4hdr_copy(dst, src, len) memcpy(dst, src, len);
#endif

#ifndef FPN_HAVE_CRYPTO_AUTH_COPY
#define fpn_crypto_auth_copy(dst, src, len) memcpy(dst, src, len);
#endif

#ifndef FPN_HAVE_CRYPTO_AUTH_CLEAR
#define fpn_crypto_auth_clear(dst, len) memset(dst, 0, len);
#endif

/*
 * SDK specific initialization.
 * Returns < 0 if error happens.
 * Else returns the number of parsed arguments.
 */
int fpn_sdk_init(int argc, char **argv);

/*
 * Called for each incoming packet from an ethernet port
 */
extern void fpn_process_input(struct mbuf *m);

/*
 * Called for each incoming packet from software
 */
extern void fpn_process_soft_input(struct mbuf *m);

/*
 * Called to start processing packets
 * Arg is not used.
 */
extern int fpn_main_loop(void *);

/*
 * To send a packet out given port.
 *
 *    extern int __fpn_send_packet(struct mbuf *m, uint8_t port);
 *
 *
 * To send a packet exception (to the core running linux)
 *
 *    extern void __fpn_send_exception(struct mbuf *m, uint8_t port);
 *
 *
 * To configure input packet engine with how many cache lines 
 * to write into L2 cache:
 * When num_cache_lines is set to -1, all the data are copied
 * into L2 cache.
 *
 *    extern void fpn_configure_l2_prefetch(int num_cache_lines);
 */

#ifndef CONFIG_MCORE_NET_EMUL
#define fpn_send_packet __fpn_send_packet

#define fpn_send_exception __fpn_send_exception
#else
/* Network I/O emulation interface exported to fast path */
extern int  fpn_send_packet(struct mbuf *m, uint8_t port);
extern void fpn_send_exception(struct mbuf *m, uint8_t port);
#endif

/* associated to FPN_DRIVER_SET_MTU_FPN capability */
extern int32_t fpn_set_mtu(const uint16_t portid, const uint16_t mtu);
/* associated to FPN_DRIVER_SET_MAC_FPN capability */
extern int32_t fpn_set_mac(const uint16_t portid, const uint8_t *mac);
/* associated to FPN_DRIVER_SET_FLAGS_FPN capability */
extern int32_t fpn_set_flags(const uint16_t portid, const uint32_t flags);
#define FPN_FLAGS_PROMISC (1UL << 0)
#define FPN_FLAGS_LINK_UP (1UL << 1)

#endif

#ifndef htonll
#ifdef __KERNEL__
#include <asm/byteorder.h>
#define htonll(x)  __cpu_to_be64 (x)
#define ntohll(x)  __be64_to_cpu (x)
#else
#if FPN_BYTE_ORDER == FPN_LITTLE_ENDIAN
#include <byteswap.h>
#define htonll(x)  (uint64_t)__bswap_64 (x)
#define ntohll(x)  (uint64_t)__bswap_64 (x)
#else
#define htonll(x)  (x)
#define ntohll(x)  (x)
#endif
#endif
#endif

/* Help to share code between userspace and fastpath */
#ifndef __FastPath__
#define FPN_RECORD_TRACK() do { } while (0)
#endif

#endif /* __FPN_H__ */
