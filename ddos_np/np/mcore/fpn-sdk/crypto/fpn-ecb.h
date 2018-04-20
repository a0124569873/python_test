/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_ECB_H__
#define __FPN_ECB_H__

#include "fpn-fcrypt.h"

/**
 * ECB crypto context
 */
typedef struct {
	fpn_crypt   encrypt;               /**< Underlying crypto block function */
	uint8_t   * enc_ctxt;              /**< Underlying crypto keys context   */
	uint8_t     block_size;            /**< Underlying crypto block size     */
} ECB_CTX;

/**
 * ECB context initialization
 *
 * This function is used to initialize per session ECB crypto context part
 *
 * @param[in] ctx
 *   ECB context to populate
 * @param[in] encrypt
 *   Underlying block encryption function
 * @param[in] enc_ctxt
 *   Underlying block crypto keys context
 * @param[in] block_size
 *   Block size of underlying crypto
 */
void fpn_ecb_init(ECB_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size);

/**
 * Per buffer ECB context initialization
 *
 * This function is used to initialize per buffer ECB crypto context part
 *
 * @param[in] ctx
 *   ECB context
 * @param[in] iv
 *   Initial IV to use. Must have the size of underlying crypto block size
 */
void fpn_ecb_start(ECB_CTX * ctx, const uint8_t * iv);

/**
 * ECB encryption
 *
 * This function can be used to encrypt a contiguous buffer in ECB mode
 *
 * @param[in] ctx
 *   ECB context
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] len
 *   Size of data to encrypt in bytes.
 */
void fpn_ecb_encrypt(ECB_CTX * ctx, uint8_t *src, uint8_t *dst, int len);

/**
 * ECB decryption
 *
 * This function can be used to decrypt a contiguous buffer in ECB mode
 *
 * @param[in] ctx
 *   ECB context
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] len
 *   Size of data to encrypt in bytes.
 */
void fpn_ecb_decrypt(ECB_CTX * ctx, uint8_t *src, uint8_t *dst, int len);

#endif /* __FPN_ECB_H__ */
