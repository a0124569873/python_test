/*
 * Copyright 2013 6WIND S.A.
 */

#include "fpn.h"
#include "fpn-gcm.h"

static const uint64_t last[16] =
{
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/**
 * GCM MultH function
 */
static void fpn_gcm_mult(GCM_CTX *ctx, const uint8_t * op, const uint8_t len)
{
	uint64_t * ptag = (uint64_t *) ctx->tag;
	uint64_t zh, zl;
	uint8_t lo, hi, rem;
	int i;

	/* First XOR current tag with block passed as parameter */
	for (i = 0; i < len; i++)
		ctx->tag[i] ^= op[i];

	/* Then do mult with current tag */
	lo = ctx->tag[15] & 0xf;
	hi = ctx->tag[15] >> 4;

	zh = ctx->M0H[lo];
	zl = ctx->M0L[lo];

	for (i = 15; i >= 0; i--) {
		lo = ctx->tag[i] & 0xf;
		hi = ctx->tag[i] >> 4;

		if (i != 15) {
			rem = (uint8_t) zl & 0xf;
			zl  = (zh << 60) | (zl >> 4);
			zh  = (zh >> 4);
			zh ^= (uint64_t) last[rem] << 48;
			zh ^= ctx->M0H[lo];
			zl ^= ctx->M0L[lo];
		}

		rem = (uint8_t) zl & 0xf;
		zl  = (zh << 60) | (zl >> 4);
		zh  = (zh >> 4);
		zh ^= (uint64_t) last[rem] << 48;
		zh ^= ctx->M0H[hi];
		zl ^= ctx->M0L[hi];
	}

	/* Store new tag */
	ptag[0] = htonll(zh);
	ptag[1] = htonll(zl);
}

/**
 * Per session GCM context initialization
 */
void fpn_gcm_init(GCM_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size)
{
	uint64_t vl, vh, table[2];
	int i, j;

	/* Store crypto function and context */
	ctx->encrypt    = encrypt;
	ctx->enc_ctxt   = enc_ctxt;
	ctx->block_size = block_size;

	/* Initialize memory */
	table[0] = 0;
	table[1] = 0;
	memset(ctx->tag, 0, 16 );
	encrypt((uint8_t *) table, (uint8_t *) table, enc_ctxt);

	vh = ntohll(table[0]);
	vl = ntohll(table[1]);

	/* Precompute M0 table */
	ctx->M0L[8] = vl;
	ctx->M0H[8] = vh;

	for(i=4 ; i>0 ; i/=2) {
		uint64_t rbit = ((vl & 1) * 0xe1000000U << 32);
		vl = (vh << 63) | (vl >> 1);
		vh = (vh >> 1) ^ rbit;

		ctx->M0L[i] = vl;
		ctx->M0H[i] = vh;
	}

	for (i=2 ; i<16 ; i*=2) {
		for(j = 1; j < i; j++) {
			ctx->M0H[i + j] = ctx->M0H[i] ^ ctx->M0H[j];
			ctx->M0L[i + j] = ctx->M0L[i] ^ ctx->M0L[j];
		}
	}

	ctx->M0H[0] = 0;
	ctx->M0L[0] = 0;
}

/**
 * Per buffer GCM context initialization
 */
void fpn_gcm_start(GCM_CTX * ctx, const uint8_t * iv, const uint16_t iv_len)
{
	/* If ivlen is 12, J0 is IV || 00000001 */
	if (iv_len == 12) {
		uint8_t ctr = ctx->block_size - sizeof(uint32_t);

		/* Set IV in auth context */
		fpn_memcpy(ctx->iv, iv, ctr);
		ctx->iv[ctr+0] = 0;
		ctx->iv[ctr+1] = 0;
		ctx->iv[ctr+2] = 0;
		ctx->iv[ctr+3] = 1;
	} else {
		/* Else apply MultH to given IV to generate the real IV */
		uint64_t block[FPN_MAX_BLOCK_SIZE / sizeof(uint64_t)];
		uint16_t blen, len = iv_len;

		/* Setup last block content */
		block[0] = 0;
		block[1] = htonll(len * 8);

		/* Generate IV */
		while (len > 0) {
			blen = (len < ctx->block_size) ? len : ctx->block_size;
			fpn_gcm_mult(ctx, &iv[iv_len - len], blen);
			len -= blen;
		}
		fpn_gcm_mult(ctx, (uint8_t *)block, ctx->block_size);

		/* Save IV in auth context */
		fpn_memcpy(ctx->iv, ctx->tag, ctx->block_size);
		memset(ctx->tag, 0, ctx->block_size);
	}

	/* Encrypt Y0 for last authentication step */
	ctx->encrypt(ctx->iv, ctx->EKY0, ctx->enc_ctxt);

	/* Initialize context */
	ctx->alen = 0;
	ctx->clen = 0;
}

/**
 * AAD authentication
 */
void fpn_gcm_auth(GCM_CTX * ctx, const uint8_t * src, uint32_t len)
{
	uint32_t blen;

	/* Apply MultH to all AAD blocks */
	ctx->alen += len;
	while (len > 0) {
		blen = len < ctx->block_size ? len : ctx->block_size;
		fpn_gcm_mult(ctx, src, blen);
		src += blen;
		len -= blen;
	}
}

/**
 * GCM encryption
 */
void fpn_gcm_encrypt(GCM_CTX * ctx, const uint8_t * src, uint8_t * dst, uint32_t len)
{
	uint8_t block[FPN_MAX_BLOCK_SIZE];
	uint32_t i, blen;

	ctx->clen += len;
	while (len > 0) {
		/* compute len that may not be a block size multiple */
		blen = len < ctx->block_size ? len : ctx->block_size;

		/* Increase counter */
		for(i = ctx->block_size; i > ctx->block_size-sizeof(uint32_t); i--)
			if (++ctx->iv[i - 1] != 0) break;

		/* Encrypt the IV */
		ctx->encrypt(ctx->iv, block, ctx->enc_ctxt);
		for (i = 0; i < blen; i++)
			dst[i] = block[i] ^ src[i];

		/* Apply MultH function */
		fpn_gcm_mult(ctx, dst, blen);

		/* Go to next block */
		src += blen;
		dst += blen;
		len -= blen;
	}
}

/**
 * GCM decryption
 */
void fpn_gcm_decrypt(GCM_CTX * ctx, const uint8_t * src, uint8_t * dst, uint32_t len)
{
	uint8_t block[FPN_MAX_BLOCK_SIZE];
	uint32_t i, blen;

	ctx->clen += len;
	while (len > 0) {
		/* compute len that may not be a block size multiple */
		blen = len < ctx->block_size ? len : ctx->block_size;

		/* Apply MultH function */
		fpn_gcm_mult(ctx, src, blen);

		/* Increase counter */
		for(i = ctx->block_size; i > ctx->block_size-sizeof(uint32_t); i--)
			if (++ctx->iv[i - 1] != 0) break;

		/* Encrypt the IV */
		ctx->encrypt(ctx->iv, block, ctx->enc_ctxt);
		for (i = 0; i < blen; i++)
			dst[i] = block[i] ^ src[i];

		/* Go to next block */
		src += blen;
		dst += blen;
		len -= blen;
	}
}

/**
 * GCM authentication finalization
 */
void fpn_gcm_final(GCM_CTX * ctx, uint8_t * digest)
{
	uint64_t lengthes[FPN_MAX_BLOCK_SIZE / sizeof(uint64_t)];
	uint32_t i;

	/* Apply MultH function to A || C */
	lengthes[0] = htonll(ctx->alen * 8);
	lengthes[1] = htonll(ctx->clen * 8);
	fpn_gcm_mult(ctx, (uint8_t *) lengthes, ctx->block_size);

	/* Do last authentication operation with stored Ek(Y0) */
	for(i = 0; i < ctx->block_size; i++)
		ctx->tag[i] ^= ctx->EKY0[i];

	/* Copy final ICV */
	fpn_memcpy(digest, ctx->tag, ctx->block_size);
}
