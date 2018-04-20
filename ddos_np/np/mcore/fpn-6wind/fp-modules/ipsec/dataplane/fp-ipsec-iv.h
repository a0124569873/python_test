/*
 * Copyright(c) 2008 6WIND
 */

#ifndef __FPN_IPSEC_IV_H__
#define __FPN_IPSEC_IV_H__

#if defined (CONFIG_MCORE_ARCH_OCTEON) && defined (CONFIG_MCORE_FPE_MCEE)
#include "fp-octeon-ipsec-iv.h"
#endif

#if defined (CONFIG_MCORE_ARCH_XLP) && defined (CONFIG_MCORE_FPE_MCEE)
#include "fp-xlp-ipsec-iv.h"
#define HAVE_SPECIFIC_GEN_IV
#endif

#ifndef HAVE_SPECIFIC_GEN_IV

struct __iv_state {
        uint64_t t0;
        uint64_t t1;
} __fpn_cache_aligned;

FPN_DECLARE_SHARED(struct __iv_state[FPN_MAX_CORES], iv_state);

/*
 * Copy a constant value in 'iv' pointer.
 * All values in iv_state are random-once-for-all values, which are
 * generated at the boot time (refer to fp_ipsec_output_init()).
 */
#define FILL_PACKET_IV(iv, ivlen)                                  \
do {                                                               \
	uint64_t *t = (uint64_t *)iv;                              \
	if (ivlen == 16) {                                         \
		int cpu = fpn_get_core_num();                      \
		t[0] = iv_state[cpu].t0;                           \
		t[1] = iv_state[cpu].t1;                           \
	}                                                          \
	else if (ivlen == 8) {                                     \
		int cpu = fpn_get_core_num();                      \
		t[0] = iv_state[cpu].t0;                           \
	}                                                          \
} while (0)

/*
 * Copy IV from state to packet buffer.
 */
#define COPY_PACKET_IV(iv, src, ivlen)                             \
do {                                                               \
	if (ivlen == 16) {                                         \
		uint64_t *s = (uint64_t *)src;                     \
		uint64_t *t = (uint64_t *)iv;                      \
		t[0] = s[0];                                       \
		t[1] = s[1];                                       \
	}                                                          \
	else if (ivlen == 8) {                                     \
		uint64_t *s = (uint64_t *)src;                     \
		uint64_t *t = (uint64_t *)iv;                      \
		t[0] = s[0];                                       \
	}                                                          \
	else if (ivlen == 4) {                                     \
		uint32_t *s = (uint32_t *)src;                     \
		uint32_t *t = (uint32_t *)iv;                      \
		t[0] = s[0];                                       \
	}                                                          \
} while (0)

#endif /* HAVE_SPECIFIC_GEN_IV */

#endif /* __FPN_IPSEC_IV_H__ */
