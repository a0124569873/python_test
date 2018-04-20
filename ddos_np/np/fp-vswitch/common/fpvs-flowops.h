/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef _FPVS_FLOW_OPS_H
#define _FPVS_FLOW_OPS_H

#include <stdint.h>
#include <string.h>

#include "fpvs-hash.h"

struct fp_flow_tnl {
	uint64_t id;
	uint32_t src;
	uint32_t dst;
	uint16_t flags;
	uint8_t tos;
	uint8_t ttl;
};

struct fp_flow_key {
	struct fp_flow_tnl tunnel;
	uint32_t recirc_id;
	struct {
		uint32_t ovsport;
	} l1;
	struct {
		uint8_t src[6];
		uint8_t dst[6];
		uint16_t ether_type;
		uint16_t vlan_tci;
	} l2;
	struct {
		uint32_t mpls_lse;
	} l2_5;
	struct {
		uint8_t proto;
		uint8_t tos;
		uint8_t ttl;
		uint8_t frag;
		union {
			struct {
				uint32_t src;
				uint32_t dst;
				struct {
					uint8_t sha[6];
					uint8_t tha[6];
				} arp;
			} ip;
			struct {
				uint32_t src[4];
				uint32_t dst[4];
				uint32_t label;
				struct {
					uint32_t target[4];
					uint8_t sll[6];
					uint8_t tll[6];
				} ndp;
			} ip6;
		};
	} l3;
	struct {
		uint16_t sport;
		uint16_t dport;
		uint16_t flags;
	} l4;
};

/* Assert that there are FLOW_SIG_SIZE bytes of significant data in "struct
 * flow", followed by FLOW_PAD_SIZE bytes of padding. */
#define FLOW_SIG_SIZE sizeof(struct fp_flow_key)

/*
 * Use the largest possible alignment requirement, currently due to
 * Intel's AVX which requires 32 bytes alignment.
 * __BIGGEST_ALIGNMENT__ cannot be used directly because it depends on
 * compiler flags that aren't necessarily enabled for all tools that use
 * shared memory (for instance, we don't enable AVX explicitly in fp-cli).
 */
#define FPVS_FLOW_ALIGNMENT 32

#ifdef __BIGGEST_ALIGNMENT__
#if FPVS_FLOW_ALIGNMENT < __BIGGEST_ALIGNMENT__
#error FPVS_FLOW_ALIGNMENT must be at least equal to __BIGGEST_ALIGNMENT__.
#endif /* FPVS_FLOW_ALIGNMENT < __BIGGEST_ALIGNMENT__ */
#endif /* __BIGGEST_ALIGNMENT__ */

/* compare 'key1' and 'key2' masked with 'mask' */
static inline int
fpvs_flow_equal_masked(struct fp_flow_key *key1, const struct fp_flow_key *key2,
		       const struct fp_flow_key *mask,
		       unsigned int start, unsigned int end)
{
	const uint64_t *k1 = (uint64_t *)((char*)key1 + start);
	const uint64_t *k2 = (uint64_t *)((char*)key2 + start);
	const uint64_t *m = (uint64_t *)((char*)mask + start);
	unsigned int i;

	for (i = start; i < end; i += sizeof(uint64_t))
		if (*k1++ != (*k2++ & *m++))
			return 0;

	return 1;
}

/* not used in datapath code, compare two flows */
static inline int
fpvs_flow_equal(struct fp_flow_key *key1, const struct fp_flow_key *key2,
		unsigned int start, unsigned int end)
{
	return !memcmp((char *)key1 + start, (char *)key2 + start, end - start);
}

/*
 * AVX and SSE intrinsics are required in the following code. These intrinsics
 * are only available when adequate -m options are specified.
 * Note that since this code mixes SSE and AVX instructions (never used at the
 * same time for performance reasons), -mno-sse2avx is mandatory.
 * Without -mno-vzeroupper, GCC 4.6+ automatically sprinkles the generated ASM
 * with "vzeroupper" after encountering AVX instructions. This crashes the
 * program on machines that don't support AVX.
 */
#if defined(__SSE4_1__) && defined(__SSE4_2__) && defined(__AVX__)

#include <immintrin.h>
#include <cpuid.h>

static volatile struct flow_cpu_features {
	unsigned int avx:1;
	unsigned int sse4_1:1;
	unsigned int sse4_2:1;
} flow_cpu_features;

/*
 * Because global variable flow_cpu_features is defined in this header,
 * flow_cpu_features_set() must be called once *in each file* that calls
 * flow_hash(), flow_equal() or flow_zero(), otherwise they will never use
 * optimized code.
 *
 * This is implicitly done by making this function a constructor.
 */
static inline void
flow_cpu_features_set(void) __attribute__((constructor));

static inline void
flow_cpu_features_set(void)
{
	unsigned int eax, ebx, ecx, edx;
	struct flow_cpu_features fcf;

	if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
		fcf.avx = 0;
		fcf.sse4_1 = 0;
		fcf.sse4_2 = 0;
	}
	else {
		fcf.avx = !!(ecx & bit_AVX);
		fcf.sse4_1 = !!(ecx & bit_SSE4_1);
		fcf.sse4_2 = !!(ecx & bit_SSE4_2);
	}
	flow_cpu_features = fcf;
}

static inline uint32_t
fpvs_hash_crc_4byte(uint32_t data, uint32_t init_val)
{
	return _mm_crc32_u32(data, init_val);
}

static inline uint32_t
fpvs_hash_crc_masked(const void *data, const void *mask,
		     uint32_t data_len, uint32_t init_val)
{
	unsigned i;
	uint32_t temp = 0;
	const uint32_t *p32 = (const uint32_t *)data;
	const uint32_t *m32 = (const uint32_t *)mask;

	for (i = 0; i < data_len / 4; i++) {
		init_val = fpvs_hash_crc_4byte((*p32++) & (*m32++), init_val);
	}

	switch (3 - (data_len & 0x03)) {
		case 0:
			temp |= *((const uint8_t *)p32 + 2) << 16;
			temp &= *((const uint8_t *)m32 + 2) << 16;
			/* Fallthrough */
		case 1:
			temp |= *((const uint8_t *)p32 + 1) << 8;
			temp &= *((const uint8_t *)m32 + 1) << 8;
			/* Fallthrough */
		case 2:
			temp |= *((const uint8_t *)p32);
			temp &= *((const uint8_t *)m32);
			init_val = fpvs_hash_crc_4byte(temp, init_val);
		default:
			break;
	}

	return init_val;
}

static inline size_t
fpvs_flow_hash_masked(const struct fp_flow_key *flow, const struct fp_flow_key *mask,
		      uint32_t basis, uint32_t start, uint32_t end)
{
	if (flow_cpu_features.sse4_2)
		return fpvs_hash_crc_masked((char*)flow + start, (char*)mask + start,
					    end - start, basis);
	return hash_bytes_masked((char*)flow + start, (char*)mask + start,
				 end - start, basis);
}

static inline void
fpvs_flow_zero(struct fp_flow_key *key)
{
	unsigned int i = 0;

	if (flow_cpu_features.avx) {
		/*
		 * The two variables below are necessary because VPXOR can
		 * only operate on 128-bit registers (xmm*) when using AVX 1.
		 * AVX 2 support is required for 256-bit operation on ymm*
		 * registers.
		 * According to Intel's spec, AVX 1 VPXOR also clears the upper
		 * 128 bits of the destination register, so the end result is
		 * the same to us, i.e. %ymm2 is zeroed as intended.
		 */
		register __m128i m128 __asm__ ("xmm2");
		register __m256i m256 __asm__ ("xmm2");

		__asm__ ("vpxor %[tmp], %[tmp], %[tmp]\n\t" :
			 [tmp] "=x" (m128));
		for (i /= sizeof(__m256i);
		     (i != (FLOW_SIG_SIZE / sizeof(__m256i))); ++i) {
			__asm__ ("vmovdqa %[tmp], %[k]\n\t" :
				 [k] "=m" (((__m256i *)key)[i]) :
				 [tmp] "x" (m256));
		}
		i *= sizeof(__m256i);
	}
	else if (flow_cpu_features.sse4_1) {
		register __m128i m128;

		__asm__ ("pxor %[tmp], %[tmp]\n\t" :
			 [tmp] "=x" (m128));
		for (i /= sizeof(__m128i);
		     (i != (FLOW_SIG_SIZE / sizeof(__m128i))); ++i) {
			__asm__ ("movdqa %[tmp], %[k]\n\t" :
				 [k] "=m" (((__m128i *)key)[i]) :
				 [tmp] "x" (m128));
		}
		i *= sizeof(__m128i);
	}
	/* 8 bytes per iteration */
	for (i /= sizeof(uint64_t);
	     (i != (FLOW_SIG_SIZE / sizeof(uint64_t))); ++i) {
		((uint64_t *)key)[i] = 0;
	}
	i *= sizeof(uint64_t);
	/* 4 bytes per iteration */
	for (i /= sizeof(uint32_t);
	     (i != (FLOW_SIG_SIZE / sizeof(uint32_t))); ++i) {
		((uint32_t *)key)[i] = 0;
	}
	i *= sizeof(uint32_t);
	/* 2 bytes per iteration */
	for (i /= sizeof(uint16_t);
	     (i != (FLOW_SIG_SIZE / sizeof(uint16_t))); ++i) {
		((uint16_t *)key)[i] = 0;
	}
	i *= sizeof(uint16_t);
	/* 1 byte per iteration */
	for (i /= sizeof(uint8_t);
	     (i != (FLOW_SIG_SIZE / sizeof(uint8_t))); ++i) {
		((uint8_t *)key)[i] = 0;
	}
}

#else /* __SSE4_1__ && __SSE4_2__ && __AVX__ */

static inline size_t
fpvs_flow_hash_masked(const struct fp_flow_key *flow, const struct fp_flow_key *mask,
		      uint32_t basis, unsigned int start, unsigned int end)
{
	return hash_bytes_masked((char*)flow + start, (char*)mask + start,
				 end - start, basis);
}

static inline void
fpvs_flow_zero(struct fp_flow_key *key)
{
	memset(key, 0, sizeof(*key));
}

#endif /* __SSE4_1__ && __SSE4_2__ && __AVX__ */

#endif /* _FPVS_FLOW_OPS_H */
