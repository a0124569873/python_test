/*
 * Copyright(c) 2011  6WIND
 */

/*	$OpenBSD: md5.h,v 1.1.2.1 2004/06/05 23:12:36 niklas Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#ifndef __FPN_MD5_H__
#define __FPN_MD5_H__

#define	MD5_BLOCK_LENGTH		64
#define	MD5_DIGEST_LENGTH		16


typedef struct MD5Context {
	uint32_t state[4];			/* state */
	uint64_t count;			/* number of bits, mod 2^64 */
	uint8_t buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} MD5_CTX;

#include <sys/cdefs.h>

__BEGIN_DECLS
void	 MD5Init(MD5_CTX *);
void	 MD5Update(MD5_CTX *, const uint8_t *, size_t);
void	 MD5Final(uint8_t [MD5_DIGEST_LENGTH], MD5_CTX *);
void	 MD5Transform(uint32_t [4], const u_int8_t [MD5_BLOCK_LENGTH]);
__END_DECLS

#define HMAC_MD5_KEY_LENGTH 16 /* bytes */
static inline void fpn_hmac_md5(char *md5, const char *key,
				const struct mbuf *m, uint32_t off,
				uint32_t buffer_len,
				char *ipad __attribute((unused)),
				char *opad __attribute((unused)))
{
	const unsigned char *buffer = m_off(m, off, const unsigned char *);
	MD5_CTX ctx_i, ctx_o;

	HMAC_Init((uint8_t *)&ctx_i,(uint8_t *)&ctx_o,(const uint8_t *)key,
		  HMAC_MD5_KEY_LENGTH, MD5_BLOCK_LENGTH, MD5_DIGEST_LENGTH,
		  md5_init, md5_update, md5_final);
	if (m_is_contiguous(m)) {
		HMAC_Update((uint8_t *)&ctx_i, buffer, buffer_len, md5_update);
		HMAC_Final((uint8_t *)md5,(uint8_t *)&ctx_i, (uint8_t *)&ctx_o,
			   MD5_DIGEST_LENGTH, md5_update, md5_final);
	} else {
		char *authbuf = (char *)fpn_malloc(buffer_len, 64);
		if (authbuf == NULL)
			return;

		__m_copytobuf(authbuf, m, off, buffer_len);

		HMAC_Update((uint8_t *)&ctx_i, (const unsigned char *)authbuf,
			    buffer_len, md5_update);
		HMAC_Final((unsigned char*)md5, (uint8_t *)&ctx_i,
			   (uint8_t *)&ctx_o, MD5_DIGEST_LENGTH, md5_update,
			   md5_final);
		fpn_free(authbuf);
	}
}


#endif /* __FPN_MD5_H__ */
