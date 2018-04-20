/*
 * Copyright 2013 6WIND S.A.
 */

#include "fpn.h"
#include "fpn-xcbc.h"

/*
 * AES-XCBC-MAC-96 (RFC3566)
 */
static uint8_t xcbc_k1[FPN_MAX_BLOCK_SIZE] = {
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
static uint8_t xcbc_k2[FPN_MAX_BLOCK_SIZE] = {
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02};
static uint8_t xcbc_k3[FPN_MAX_BLOCK_SIZE] = {
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03};

/**
 * XCBC context initialization
 */
void fpn_xcbc_init(XCBC_CTX *ctx_i, XCBC_CTX *ctx_o, uint8_t *key, int key_len,
                   int block_size, fpn_setkey setkey, fpn_crypt encrypt)
{
	/* Store crypto function and block size */
	ctx_i->encrypt    = encrypt;
	ctx_i->block_size = block_size;

	/* Set outer context */
	setkey((uint8_t *)&ctx_o->enc_ctxt, key, key_len);
	encrypt(xcbc_k1, ctx_o->block1, (uint8_t *)&ctx_o->enc_ctxt);
	encrypt(xcbc_k2, ctx_o->block2, (uint8_t *)&ctx_o->enc_ctxt);
	encrypt(xcbc_k3, ctx_o->block3, (uint8_t *)&ctx_o->enc_ctxt);

	/* Set inner context */
	setkey((uint8_t *)&ctx_i->enc_ctxt, ctx_o->block1, block_size);
	memset(ctx_i->block1, 0, block_size);
	ctx_i->size = 0;
}

/**
 * XCBC block authentication
 */
void fpn_xcbc_update(XCBC_CTX *ctx_i, const uint8_t *input, int len)
{
	int n, bsize = ctx_i->block_size;

	len   += ctx_i->size;
	input -= ctx_i->size;
	while (len > bsize) {
		for (n = 0; n < bsize; n++) {
			if (ctx_i->size > 0) {
				ctx_i->block2[n] = ctx_i->block3[n];
				ctx_i->size--;
			} else {
				ctx_i->block2[n] = input[n];
			}
			ctx_i->block2[n] ^= ctx_i->block1[n];
		}
		ctx_i->encrypt(ctx_i->block2, ctx_i->block1, (uint8_t *)&ctx_i->enc_ctxt);

		len   -= bsize;
		input += bsize;
	}

	/* Store last block that will be used to finalize auth */
	fpn_memcpy(&ctx_i->block3[ctx_i->size], &input[ctx_i->size], len - ctx_i->size);
	ctx_i->size = len;
}

/**
 * XCBC finalization
 */
void fpn_xcbc_final(XCBC_CTX *ctx_i, XCBC_CTX *ctx_o, uint8_t *digest)
{
	unsigned int n;

	/* There is always something in last buffer */
	if (ctx_i->size == ctx_i->block_size) {
		for (n = 0; n < ctx_i->block_size; n++)
			ctx_i->block2[n] = ctx_i->block1[n] ^ ctx_i->block3[n] ^
			                   ctx_o->block2[n];
	} else {
		for (n = 0; n < ctx_i->block_size; n++) {
			if (n < ctx_i->size) {
				ctx_i->block2[n] = ctx_i->block3[n];
			} else if (n == ctx_i->size) {
				ctx_i->block2[n] = 0x80;
			} else {
				ctx_i->block2[n] = 0x00;
			}
			ctx_i->block2[n] ^= ctx_i->block1[n] ^ ctx_o->block3[n];
		}
	}
	ctx_i->encrypt(ctx_i->block2, ctx_i->block1, (uint8_t *)&ctx_i->enc_ctxt);

	/* Copy final ICV */
	fpn_memcpy(digest, ctx_i->block1, ctx_i->block_size);
}
