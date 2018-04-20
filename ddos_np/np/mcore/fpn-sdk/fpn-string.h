/*
 * Copyright(c) 2009 6WIND, All rights reserved.
 */
#ifndef __FPN_STRING_H__
#define __FPN_STRING_H__

/*
 * Fast memcmp().
 *
 * Note that it can be used to compare string, if we respect some
 * constraints: if we know that there is no '\0' in the first (n-1)
 * characters of s1 or s2.
 * For instance, this is the case when we compare the hookname in
 * netgraph with a fixed string (in this case we know the length and
 * we can use sizeof).
 *
 * Returns 0 if memory zones are equal, else != 0. This function is
 * only useful for data (len <= 16). Note that is n is a constant, the
 * compiler will be able to optimize the if(), resulting in a faster
 * code.
 */
static inline uint64_t fpn_fast_memcmp(const void *s1, const void *s2, size_t n)
{
#if __GNUC__ == 4 && __GNUC_MINOR__ == 4
	/* On gcc-4.4, we sometimes run into aliasing problems with this
	 * function. Let's see what will be the behavior with gcc-4.5 before
	 * trying to fix it. */
	return memcmp(s1, s2, n);
#else
	uint64_t mask;
	register uint64_t s1_u64, s2_u64;

	s1_u64 = *(uint64_t *)s1;
	s2_u64 = *(uint64_t *)s2;

	if (likely(n <= 8)) {

		/* behaviour of a shift greater than
		 * sizeof(uint64_t)*8 is undefined. For instance, on
		 * mips, we have: (1ULL << 64) gives 1 instead of
		 * 0. So we need a special case we n==8. */
		if (unlikely(n == 8)) {
			mask = ~0ULL;
		}
		else {
			mask = (1ULL << (n << 3ULL));
			mask -= 1;
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
			mask <<= ((8-n) << 3);
#endif
		}
		return ((s1_u64 ^ s2_u64) & mask);
	}

	if (likely(n <= 16)) {
		uint64_t ret;

		n -= 8;
		ret = s1_u64 ^ s2_u64;
		s1_u64 = *(uint64_t *)(s1+8);
		s2_u64 = *(uint64_t *)(s2+8);

		if (unlikely(n == 8)) {
			mask = ~0ULL;
		}
		else {
			mask = (1ULL << (n << 3ULL));
			mask -= 1;
#if FPN_BYTE_ORDER == FPN_BIG_ENDIAN
			mask <<= ((8-n) << 3);
#endif
		}
		return ret | ((s1_u64 ^ s2_u64) & mask);
	}

	return memcmp(s1, s2, n);
#endif
}

#ifndef FPN_HAVE_ARCH_MEMCPY
#define fpn_memcpy memcpy
#endif

#endif
