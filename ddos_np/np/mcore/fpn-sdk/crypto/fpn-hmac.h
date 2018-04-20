/*
 * Copyright(c) 2011 6WIND
 */

#ifndef _FPN_HMAC_H_
#define _FPN_HMAC_H_

void md5_init(uint8_t *ctx);
void md5_update(uint8_t *ctx, const uint8_t *input, int len);
void md5_final(uint8_t *digest, uint8_t *ctx);
void sha1_init(uint8_t *ctx);
void sha1_update(uint8_t *ctx, const uint8_t *input, int len);
void sha1_final(uint8_t *digest, uint8_t *ctx);
void sha256_init(uint8_t *ctx);
void sha256_update(uint8_t *ctx, const uint8_t *input, int len);
void sha256_final(uint8_t *digest, uint8_t *ctx);
void sha384_init(uint8_t *ctx);
void sha384_update(uint8_t *ctx, const uint8_t *input, int len);
void sha384_final(uint8_t *digest, uint8_t *ctx);
void sha512_init(uint8_t *ctx);
void sha512_update(uint8_t *ctx, const uint8_t *input, int len);
void sha512_final(uint8_t *digest, uint8_t *ctx);

typedef void (*Init) (uint8_t *) ;
typedef void (*Update) (uint8_t *, const uint8_t *, int) ;
typedef void (*Final) (uint8_t *,uint8_t *) ;

void HMAC_Init(uint8_t *ctx_i, uint8_t *ctx_o, const uint8_t *key, int key_len,
	       int bsize, int digest_size, Init init, Update update,
	       Final final);
void HMAC_Update(uint8_t *ctx_i, const uint8_t *input, size_t len,
		 Update update);
void HMAC_Final(uint8_t *digest, uint8_t *ctx_i, uint8_t *ctx_o,
		int digest_size, Update update, Final final);

#endif	/* _FPN_HMAC_H_ */
