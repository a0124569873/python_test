/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_CTR_H__
#define __FPN_CTR_H__

#include "fpn-fcrypt.h"

/**
 * CTR crypto context
 */
typedef struct {
	uint8_t     iv[FPN_MAX_BLOCK_SIZE];/**< IV for the operation             */

	uint8_t     block_size;            /**< Underlying crypto block size     */
	uint8_t   * enc_ctxt;              /**< Underlying crypto keys context   */
	fpn_crypt   encrypt;               /**< Underlying crypto block function */
} CTR_CTX;

/**
 * CTR context initialization
 *
 * This function is used to initialize per session CTR crypto context part
 *
 * @param[in] ctx
 *   CTR context to populate
 * @param[in] encrypt
 *   Underlying block encryption function
 * @param[in] enc_ctxt
 *   Underlying block crypto keys context
 * @param[in] block_size
 *   Block size of underlying crypto
 */
void fpn_ctr_init(CTR_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size);

/**
 * Per buffer CTR context initialization
 *
 * This function is used to initialize per buffer CTR crypto context part
 *
 * @param[in] ctx
 *   CTR context
 * @param[in] iv
 *   Initial IV to use. Must have the size of underlying crypto block size
 */
void fpn_ctr_start(CTR_CTX * ctx, const uint8_t * iv);

/**
 * CTR encryption
 *
 * This function can be used to encrypt a contiguous buffer in CTR mode
 *
 * @param[in] ctx
 *   CTR context
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] len
 *   Size of data to encrypt in bytes.
 */
void fpn_ctr_encrypt(CTR_CTX * ctx, const uint8_t * src, uint8_t * dst, uint32_t len);

/**
 * CTR decryption
 *
 * This function can be used to decrypt a contiguous buffer in CTR mode
 *
 * @param[in] ctx
 *   CTR context
 * @param[in] src
 *   Buffer containing contiguous data to decrypt
 * @param[out] dst
 *   Destination buffer that will contain decrypted data
 * @param[in] len
 *   Size of data to decrypt in bytes.
 */
void fpn_ctr_decrypt(CTR_CTX * ctx, const uint8_t * src, uint8_t * dst, uint32_t len);

#endif /* __FPN_CTR_H__ */
