/*
 * Copyright 2008 6WIND, All rights reserved.
 */

#ifndef __FP_JHASH_H__
#define __FP_JHASH_H__

/* whole hash is 20 cycles on octeon */
#define fp_jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

#define FP_JHASH_GOLDEN_RATIO      0x9e3779b9

static inline uint32_t fp_jhash_1word(uint32_t a)
{
	uint32_t b = FP_JHASH_GOLDEN_RATIO;
	uint32_t c = FP_JHASH_GOLDEN_RATIO;

	fp_jhash_mix(a, b, c);
	return c;
}
#endif /* __FP_JHASH_H__ */
