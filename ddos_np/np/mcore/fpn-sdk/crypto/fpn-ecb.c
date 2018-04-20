/*
 * Copyright 2013 6WIND S.A.
 */

#include "fpn.h"
#include "fpn-ecb.h"

/**
 * ECB context initialization
 */
void fpn_ecb_init(ECB_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size)
{
	/* Store crypto function and context */
	ctx->encrypt    = encrypt;
	ctx->enc_ctxt   = enc_ctxt;
	ctx->block_size = block_size;
}

/**
 * ECB per buffer initialization
 */
void fpn_ecb_start(__fpn_maybe_unused ECB_CTX * ctx,
                   __fpn_maybe_unused const uint8_t * iv)
{
}

/**
 * ECB encryption
 */
void fpn_ecb_encrypt(ECB_CTX * ctx, uint8_t *src, uint8_t *dst, int len)
{
	int done = 0;
	int bsize = ctx->block_size;

	/* Apply block encryption operation to all blocks */
	/* Buffer size must be a multiple of block size */
	while (done < len) {
		ctx->encrypt(src, dst, ctx->enc_ctxt);
		src  += bsize;
		dst  += bsize;
		done += bsize;
	}
}

/**
 * ECB decryption
 */
void fpn_ecb_decrypt(ECB_CTX * ctx, uint8_t *src, uint8_t *dst, int len)
{
	int done = 0;
	int bsize = ctx->block_size;

	/* Apply block encryption operation to all blocks */
	/* Buffer size must be a multiple of block size */
	while (done < len) {
		ctx->encrypt(src, dst, ctx->enc_ctxt);
		src  += bsize;
		dst  += bsize;
		done += bsize;
	}
}
