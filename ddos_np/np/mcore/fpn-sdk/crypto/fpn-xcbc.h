/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_XCBC_H__
#define __FPN_XCBC_H__

#include "fpn-rijndael.h"

/**
 * This structure is only used to reserve space
 * for all supported crypto keys contexts
 */
typedef union {
	rijndael_ctx aes;
} enc_ctxt_t;

/**
 * XCBC crypto context
 */
typedef struct {
	uint8_t     block1[FPN_MAX_BLOCK_SIZE];/**< Temporary block1             */
	uint8_t     block2[FPN_MAX_BLOCK_SIZE];/**< Temporary block2             */
	uint8_t     block3[FPN_MAX_BLOCK_SIZE];/**< Temporary block3             */
	uint8_t     size;                  /**< Temporary block1                 */

	uint8_t     block_size;            /**< Underlying crypto block size     */
	enc_ctxt_t  enc_ctxt;              /**< Underlying crypto keyx context   */
	fpn_crypt   encrypt;               /**< Underlying crypto block function */
} XCBC_CTX;

/**
 * XCBC context initialization
 *
 * This function is used to initialize XCBC authentication
 *
 * @param[in] ctx_i
 *   XCBC inner context to populate
 * @param[in] ctx_o
 *   XCBC outer context to populate
 * @param[in] key
 *   Underlying block encryption key
 * @param[in] key_len
 *   Underlying block encryption key length
 * @param[in] block_size
 *   Underlying block encryption block size
 * @param[in] setkey
 *   Underlying block encryption keys context initialization function
 * @param[in] encrypt
 *   Underlying block encryption function
 */
void fpn_xcbc_init(XCBC_CTX *ctx_i, XCBC_CTX *ctx_o, uint8_t *key, int key_len,
                   int block_size, fpn_setkey setkey, fpn_crypt encrypt);

/**
 * XCBC update
 *
 * This function is used to hash buffer content in XCBC context
 *
 * @param[in] ctx_i
 *   XCBC inner context
 * @param[in] input
 *   Buffer containing contiguous data to authenticate
 * @param[in] len
 *   Size of data to authenticate in bytes.
 */
void fpn_xcbc_update(XCBC_CTX *ctx_i, const uint8_t *input, int len);

/**
 * XCBC authentication finalization
 *
 * This function is used to finalize XCBC authentication and return ICV
 *
 * @param[in] ctx_i
 *   XCBC inner context
 * @param[in] ctx_o
 *   XCBC outer context
 * @param[out] digest
 *   computed digest
 */
void fpn_xcbc_final(XCBC_CTX *ctx_i, XCBC_CTX *ctx_o, uint8_t *digest);

#endif /* __FPN_XCBC_H__ */
