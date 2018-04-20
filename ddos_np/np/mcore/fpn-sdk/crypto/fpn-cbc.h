/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_CBC_H__
#define __FPN_CBC_H__

#include "fpn-fcrypt.h"

/**
 * CBC crypto context
 */
typedef struct {
	uint8_t     iv[2][FPN_MAX_BLOCK_SIZE];/**< IV for the operation          */
	fpn_crypt   encrypt;               /**< Underlying crypto block function */
	uint8_t   * enc_ctxt;              /**< Underlying crypto keys context   */
	uint8_t     block_size;            /**< Underlying crypto block size     */
	uint8_t     curr_iv;               /**< Current IV                       */
} CBC_CTX;

/**
 * CBC context initialization
 *
 * This function is used to initialize per session CBC crypto context part
 *
 * @param[in] ctx
 *   CBC context to populate
 * @param[in] encrypt
 *   Underlying block encryption function
 * @param[in] enc_ctxt
 *   Underlying block crypto keys context
 * @param[in] block_size
 *   Block size of underlying crypto
 */
void fpn_cbc_init(CBC_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt, uint8_t block_size);

/**
 * Per buffer CBC context initialization
 *
 * This function is used to initialize per buffer CBC crypto context part
 *
 * @param[in] ctx
 *   CBC context
 * @param[in] iv
 *   Initial IV to use. Must have the size of underlying crypto block size
 */
void fpn_cbc_start(CBC_CTX * ctx, const uint8_t * iv);

/**
 * CBC encryption
 *
 * This function can be used to encrypt a contiguous buffer in CBC mode
 *
 * @param[in] ctx
 *   CBC context
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] len
 *   Size of data to encrypt in bytes.
 */
void fpn_cbc_encrypt(CBC_CTX * ctx, uint8_t *src, uint8_t *dst, int len);

/**
 * CBC decryption
 *
 * This function can be used to decrypt a contiguous buffer in CBC mode
 *
 * @param[in] ctx
 *   CBC context
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] len
 *   Size of data to encrypt in bytes.
 */
void fpn_cbc_decrypt(CBC_CTX * ctx, uint8_t *src, uint8_t *dst, int len);

/* Old API compatibility */
void cbc_encrypt(uint8_t *src, uint8_t *dst, int nbytes, uint8_t *key,
		 uint8_t *iv, int bsize, fpn_crypt algfn);
void cbc_decrypt(uint8_t *src, uint8_t *dst, int nbytes, uint8_t *key,
		 uint8_t *iv, int bsize, fpn_crypt algfn);

#endif /* __FPN_CBC_H__ */
