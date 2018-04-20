/*
 * Copyright(c) 2011  6WIND
 */

/*	$OpenBSD: sha1.h,v 1.5 2007/09/10 22:19:42 henric Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef __FPN_SHA1_H__
#define __FPN_SHA1_H__

#define	SHA1_BLOCK_LENGTH		64
#define	SHA1_DIGEST_LENGTH		20

typedef struct {
	u_int32_t	state[5];
	u_int64_t	count;
	unsigned char	buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

void SHA1Init(SHA1_CTX * context);
void SHA1Transform(u_int32_t state[5],
		   const unsigned char buffer[SHA1_BLOCK_LENGTH]);
void SHA1Update(SHA1_CTX *context, const unsigned char *data, unsigned int len);
void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context);

/* #include <crypto/fpn-md5.h> */
/* #include <crypto/fpn-sha1.h> */
/* #include <crypto/fpn-sha2.h> */
#include <crypto/fpn-hmac.h>
#define HMAC_SHA1_KEY_LENGTH 20 /* bytes */
#define HMAC_SHA256_KEY_LENGTH 32 /* bytes */
#define HMAC_SHA384_KEY_LENGTH 48 /* bytes */
#define HMAC_SHA512_KEY_LENGTH 64 /* bytes */

static inline void fpn_hmac_sha1(char *sha1, const char *key,
				 const struct mbuf *m, uint32_t off,
				 uint32_t buffer_len,
				 char *ipad __attribute((unused)),
				 char *opad __attribute((unused)))
{
	const unsigned char *buffer = m_off(m, off, const unsigned char *);
	SHA1_CTX ctx_i, ctx_o;
	HMAC_Init((uint8_t *)&ctx_i, (uint8_t *)&ctx_o, (const uint8_t *)key,
		  HMAC_SHA1_KEY_LENGTH, SHA1_BLOCK_LENGTH, SHA1_DIGEST_LENGTH,
		  sha1_init, sha1_update, sha1_final);

	if (m_is_contiguous(m)) {
		HMAC_Update((uint8_t *)&ctx_i, buffer, buffer_len, sha1_update);
		HMAC_Final((unsigned char*)sha1, (uint8_t *)&ctx_i,
			   (uint8_t *)&ctx_o, SHA1_DIGEST_LENGTH,
			   sha1_update, sha1_final);
	} else {
		char *authbuf = (char *)fpn_malloc(buffer_len, 64);
		if (authbuf == NULL)
			return;

		__m_copytobuf(authbuf, m, off, buffer_len);
		HMAC_Update((uint8_t *)&ctx_i, (const unsigned char *)authbuf,
			    buffer_len, sha1_update);
		HMAC_Final((unsigned char*)sha1, (uint8_t *)&ctx_i,
			   (uint8_t *)&ctx_o, SHA1_DIGEST_LENGTH,
			   sha1_update, sha1_final);
		fpn_free(authbuf);
	}
}

#endif /* _SHA1_H_ */
