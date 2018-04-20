/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FPN_DIV64_H__
#define __FPN_DIV64_H__

/* define FPN_NO_DIV64 in fpn-${arch}.h if the architecture does not
 * support 64 bits integer division. This is not needed on 64 bits
 * archs. */
#ifdef FPN_NO_DIV64
static inline uint64_t fpn_div64_32(uint64_t n, uint32_t base)
{
	uint64_t b = base;
	uint64_t res, d = 1;
	uint32_t high = n >> 32;

	/* Reduce the thing a bit first */
	res = 0;
	if (high >= base) {
		high /= base;
		res = (uint64_t) high << 32;
		n -= (uint64_t) (high*base) << 32;
	}

	while ((int64_t)b > 0 && b < n) {
		b = b+b;
		d = d+d;
	}

	do {
		if (n >= b) {
			n -= b;
			res += d;
		}
		b >>= 1;
		d >>= 1;
	} while (d);

	return res;
}

/* Use scaling to do a full 64 bit division  */
static inline uint64_t fpn_div64_64(uint64_t dividend, uint64_t divisor)
{
	uint32_t d = divisor;

	if (divisor > 0xffffffffULL) {
		unsigned int shift = fls(divisor >> 32);

		d = divisor >> shift;
		dividend >>= shift;
	}

	/* avoid 64 bit division if possible */
	if (dividend >> 32)
		fpn_div64_32(dividend, d);
	else
		dividend = (uint32_t) dividend / d;

	return dividend;
}

#else
#define fpn_div64_32(n, base) ((n)/(base))
#define fpn_div64_64(n, base) ((n)/(base))
#endif /* FPN_NO_DIV64 */


#endif /* __FPN_DIV64_H__ */
