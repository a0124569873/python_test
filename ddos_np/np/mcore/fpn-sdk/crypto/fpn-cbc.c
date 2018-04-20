/*
 * Copyright 2013 6WIND S.A.
 */

#include "fpn.h"
#include "fpn-cbc.h"

/**
 * CBC context initialization
 */
void fpn_cbc_init(CBC_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size)
{
	/* Store crypto function and context */
	ctx->encrypt    = encrypt;
	ctx->enc_ctxt   = enc_ctxt;
	ctx->block_size = block_size;
}

/**
 * CBC per buffer initialization
 */
void fpn_cbc_start(CBC_CTX * ctx, const uint8_t * iv)
{
	/* Store IV in context */
	ctx->curr_iv = 0;
	fpn_memcpy(ctx->iv[0], iv, ctx->block_size);
}

/**
 * CBC encryption
 */
void fpn_cbc_encrypt(CBC_CTX * ctx, uint8_t *src, uint8_t *dst, int len)
{
	int i, done = 0, bsize = ctx->block_size;
	const uint8_t * iv = ctx->iv[ctx->curr_iv & 1];

	/* Apply block encryption operation to all blocks */
	/* Buffer size must be a multiple of block size */
	while (done < len) {
		for (i = 0; i < bsize; i++)
			dst[i] = src[i] ^ iv[i];
		ctx->encrypt(dst, dst, ctx->enc_ctxt);
		iv    = dst;
		src  += bsize;
		dst  += bsize;
		done += bsize;
	}

	/* Store last block as future IV */
	fpn_memcpy(ctx->iv[ctx->curr_iv & 1], iv, ctx->block_size);
}

/**
 * CBC decryption
 */
void fpn_cbc_decrypt(CBC_CTX * ctx, uint8_t *src, uint8_t *dst, int len)
{
	int i, left = len;
	int bsize = ctx->block_size;
	uint8_t * curr_iv;

	if (len > 0) {
		/* Get current and next iv */
		curr_iv = ctx->iv[ctx->curr_iv & 1];

		/* Change current IV */
		ctx->curr_iv++;

		/* Store last block as future IV */
		fpn_memcpy(ctx->iv[ctx->curr_iv & 1], &dst[len - bsize], ctx->block_size);
	}

	/* To avoid a useless copy, start to decrypt from the end of the */
	/* buffer */
	src += len;
	dst += len;

	/* Apply block encryption operation to all blocks */
	/* Buffer size must be a multiple of block size */
	while (left > bsize) {
		src -= bsize;
		dst -= bsize;
		ctx->encrypt(src, dst, ctx->enc_ctxt);
		for (i = 0; i < bsize; i++)
			dst[i] ^= dst[i - bsize];
		left -= bsize;
	}

	/* Use IV instead of buffer for last decryption operation */
	if (left > 0) {
		src -= bsize;
		dst -= bsize;
		ctx->encrypt(src, dst, ctx->enc_ctxt);
		for (i = 0; i < bsize; i++)
			dst[i] ^= curr_iv[i];
	}
}

/**
 * CBC encryption - old API
 */
void cbc_encrypt(uint8_t *src, uint8_t *dst, int nbytes, uint8_t *key,
                 uint8_t *iv, int bsize, fpn_crypt algfn)
{
	int i, done = 0;

	/* Apply block encryption operation to all blocks */
	/* Buffer size must be a multiple of block size */
	while (done < nbytes) {
		for (i = 0; i < bsize; i++)
			dst[i] = src[i] ^ iv[i];
		algfn(dst, dst, key);
		iv    = dst;
		src  += bsize;
		dst  += bsize;
		done += bsize;
	}
}

/**
 * CBC decryption - old API
 */
void cbc_decrypt(uint8_t *src, uint8_t *dst, int nbytes, uint8_t *key,
                 uint8_t *iv, int bsize, fpn_crypt algfn)
{
	int i, left = nbytes;

	/* To avoid a useless copy, start to decrypt from the end of the */
	/* buffer */
	src += nbytes;
	dst += nbytes;

	/* Apply block encryption operation to all blocks */
	/* Buffer size must be a multiple of block size */
	while (left > bsize) {
		src -= bsize;
		dst -= bsize;
		algfn(src, dst, key);
		for (i = 0; i < bsize; i++)
			dst[i] ^= dst[i - bsize];
		left -= bsize;
	}

	/* Use IV instead of buffer for last decryption operation */
	if (left > 0) {
		src -= bsize;
		dst -= bsize;
		algfn(src, dst, key);
		for (i = 0; i < bsize; i++)
			dst[i] ^= iv[i];
	}
}
