/*
 * Copyright 2013 6WIND S.A.
 */

#include "fpn.h"
#include "fpn-ctr.h"

/**
 * CTR context initialization
 */
void fpn_ctr_init(CTR_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size)
{
	/* Store crypto function and context */
	ctx->encrypt    = encrypt;
	ctx->enc_ctxt   = enc_ctxt;
	ctx->block_size = block_size;
}

/**
 * CTR per buffer initialization
 */
void fpn_ctr_start(CTR_CTX * ctx, const uint8_t * iv)
{
	/* Save nonce in auth context */
	fpn_memcpy(ctx->iv, iv, ctx->block_size);
}

/**
 * CTR encryption
 */
void fpn_ctr_encrypt(CTR_CTX * ctx, const uint8_t * src, uint8_t * dst, uint32_t len)
{
	uint8_t block[FPN_MAX_BLOCK_SIZE];
	uint32_t i, blen;

	while (len > 0) {
		/* compute len that may not be a block size multiple */
		blen = len < ctx->block_size ? len : ctx->block_size;

		/* Encrypt the IV */
		ctx->encrypt(ctx->iv, block, ctx->enc_ctxt);
		for (i = 0; i < blen; i++)
			dst[i] = block[i] ^ src[i];

		/* Increase counter */
		for(i = ctx->block_size; i > ctx->block_size-sizeof(uint32_t); i--)
			if (++ctx->iv[i - 1] != 0) break;

		/* Go to next block */
		src += blen;
		dst += blen;
		len -= blen;
	}
}

/**
 * CTR decryption
 */
void fpn_ctr_decrypt(CTR_CTX * ctx, const uint8_t * src, uint8_t * dst, uint32_t len)
{
	uint8_t block[FPN_MAX_BLOCK_SIZE];
	uint32_t i, blen;

	while (len > 0) {
		/* compute len that may not be a block size multiple */
		blen = len < ctx->block_size ? len : ctx->block_size;

		/* Encrypt the IV */
		ctx->encrypt(ctx->iv, block, ctx->enc_ctxt);
		for (i = 0; i < blen; i++)
			dst[i] = block[i] ^ src[i];

		/* Increase counter */
		for(i = ctx->block_size; i > ctx->block_size-sizeof(uint32_t); i--)
			if (++ctx->iv[i - 1] != 0) break;

		/* Go to next block */
		src += blen;
		dst += blen;
		len -= blen;
	}
}
