/*
 * Copyright(c) 2011 6WIND
 */

#include "fpn.h"

#include <crypto/fpn-hmac.h>
#include <crypto/fpn-md5.h>
#include <crypto/fpn-sha1.h>
#include <crypto/fpn-sha2.h>

void md5_init(uint8_t *ctx)
{
	MD5Init((MD5_CTX *)ctx);
}

void md5_update(uint8_t *ctx, const uint8_t *input, int len)
{
	MD5Update((MD5_CTX *)ctx, input, len);
}

void md5_final(uint8_t *digest, uint8_t *ctx)
{
	MD5Final(digest, (MD5_CTX *)ctx);
}

void sha1_init(uint8_t *ctx)
{
	SHA1Init((SHA1_CTX *)ctx);
}

void sha1_update(uint8_t *ctx, const uint8_t *input, int len)
{
	SHA1Update((SHA1_CTX *)ctx, input, len);
}

void sha1_final(uint8_t *digest, uint8_t *ctx)
{
	SHA1Final(digest, (SHA1_CTX *)ctx);
}

void sha256_init(uint8_t *ctx)
{
	SHA256Init((SHA2_CTX *)ctx);
}

void sha256_update(uint8_t *ctx, const uint8_t *input, int len)
{
	SHA256Update((SHA2_CTX *)ctx, input, len);
}

void sha256_final(uint8_t *digest, uint8_t *ctx)
{
	SHA256Final(digest, (SHA2_CTX *)ctx);
}

void sha384_init(uint8_t *ctx)
{
	SHA384Init((SHA2_CTX *)ctx);
}

void sha384_update(uint8_t *ctx, const uint8_t *input, int len)
{
	SHA384Update((SHA2_CTX *)ctx, input, len);
}

void sha384_final(uint8_t *digest, uint8_t *ctx)
{
	SHA384Final(digest, (SHA2_CTX *)ctx);
}

void sha512_init(uint8_t *ctx)
{
	SHA512Init((SHA2_CTX *)ctx);
}

void sha512_update(uint8_t *ctx, const uint8_t *input, int len)
{
	SHA512Update((SHA2_CTX *)ctx, input, len);
}

void sha512_final(uint8_t *digest, uint8_t *ctx)
{
	SHA512Final(digest, (SHA2_CTX *)ctx);
}

void HMAC_Init(uint8_t *ctx_i, uint8_t *ctx_o, const uint8_t *key, int key_len,
	       int bsize, int digest_size, Init init, Update update,
	       Final final)
{
	uint8_t k_ipad[bsize];
	uint8_t k_opad[bsize];
	uint8_t new_key[bsize];
	int new_key_len;
	int i;

	if (key_len > bsize) { /*for ipsec, key size is fixed, not larger than block size.*/
		init(ctx_i);
		update(ctx_i, key, key_len);
		final(new_key, ctx_i);
		new_key_len = digest_size;
	} else {
		bcopy(key, new_key, key_len);
		new_key_len = key_len;
	}

	bzero(k_ipad, bsize);
	bcopy(new_key, k_ipad, new_key_len);
	for (i = 0; i < bsize; i++)
		k_ipad[i] ^= 0x36;

	init(ctx_i);
	update(ctx_i, k_ipad, bsize);

	bzero(k_opad, bsize);
	bcopy(new_key, k_opad, new_key_len);
	for (i = 0; i < bsize; i++)
		k_opad[i] ^= 0x5c;

	init(ctx_o);
	update(ctx_o, k_opad, bsize);

	bzero(k_ipad, sizeof(k_ipad));
	bzero(k_opad, sizeof(k_opad));
}

void HMAC_Update(uint8_t *ctx_i, const uint8_t *input,
		 size_t len, Update update)
{
	update(ctx_i, input, len);
}

void HMAC_Final(uint8_t *digest, uint8_t *ctx_i, uint8_t *ctx_o,
		int digest_size, Update update, Final final)
{

	final(digest, ctx_i);
	update(ctx_o, digest, digest_size);
	final(digest, ctx_o);
}
