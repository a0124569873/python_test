/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_GCM_H__
#define __FPN_GCM_H__

#include "fpn-fcrypt.h"

/**
 * GCM crypto context
 */
typedef struct {
    uint64_t    M0L[16];               /**< Precomputed M0 values            */
    uint64_t    M0H[16];               /**< Precomputed M0 values            */
	uint8_t     tag[FPN_MAX_BLOCK_SIZE];/**< Tag                             */
	uint8_t     iv[FPN_MAX_BLOCK_SIZE]; /**< IV                              */
	uint8_t     EKY0[FPN_MAX_BLOCK_SIZE];/**< Ek(Y0)                         */
	uint32_t    alen;                  /**< AAD length in bytes              */
	uint32_t    clen;                  /**< Ciphered text length in bytes    */

	uint8_t     block_size;            /**< Underlying crypto block size     */
	uint8_t   * enc_ctxt;              /**< Underlying crypto keys context   */
	fpn_crypt   encrypt;               /**< Underlying crypto block function */
} GCM_CTX;

/**
 * Per session GCM context initialization
 *
 * This function is used to initialize per session GCM crypto context part
 *
 * @param[in] ctx
 *   GCM context to populate
 * @param[in] encrypt
 *   Underlying block encryption function
 * @param[in] enc_ctxt
 *   Underlying block crypto keys context
 * @param[in] block_size
 *   Block size of underlying crypto
 */
void fpn_gcm_init(GCM_CTX * ctx, fpn_crypt encrypt, uint8_t * enc_ctxt,
                  uint8_t block_size);

/**
 * Per buffer GCM context initialization
 *
 * This function is used to initialize per buffer GCM crypto context part
 *
 * @param[in] ctx
 *   CTR context
 * @param[in] iv
 *   Initial IV to use.
 * @param[in] iv_len
 *   IV length.
 */
void fpn_gcm_start(GCM_CTX * ctx, const uint8_t * iv, const uint16_t iv_len);

/**
 * AAD authentication
 *
 * This function is used to process authentication of AAD part of the buffer
 *
 * @param[in] ctx
 *   CTR context
 * @param[in] src
 *   Buffer containing contiguous data to authenticate
 * @param[in] len
 *   Size of data to authenticate in bytes.
 */
void fpn_gcm_auth(GCM_CTX * ctx, const uint8_t * src, const uint32_t len);

/**
 * GCM encryption
 *
 * This function can be used to encrypt a contiguous buffer in GCM mode
 *
 * @param[in] ctx
 *   GCM context
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] len
 *   Size of data to encrypt in bytes.
 */
void fpn_gcm_encrypt(GCM_CTX * ctx, const uint8_t * src,
                     uint8_t * dst, uint32_t len);

/**
 * GCM decryption
 *
 * This function can be used to decrypt a contiguous buffer in GCM mode
 *
 * @param[in] ctx
 *   GCM context
 * @param[in] src
 *   Buffer containing contiguous data to decrypt
 * @param[out] dst
 *   Destination buffer that will contain decrypted data
 * @param[in] len
 *   Size of data to decrypt in bytes.
 */
void fpn_gcm_decrypt(GCM_CTX * ctx, const uint8_t * src,
                     uint8_t * dst, uint32_t len);

/**
 * GCM authentication finalization
 *
 * This function is used to finalize GCM authentication and return ICV
 *
 * @param[in] ctx
 *   GCM context
 * @param[out] digest
 *   computed digest
 */
void fpn_gcm_final(GCM_CTX * ctx, uint8_t * digest);

#endif /* __FPN_GCM_H__ */
