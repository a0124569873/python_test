/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_FCRYPT_H__
#define __FPN_FCRYPT_H__

#define FPN_MAX_BLOCK_SIZE      16

/**
 * Crypto block function
 *
 * @param[in] src
 *   Buffer containing contiguous data to encrypt
 * @param[out] dst
 *   Destination buffer that will contain encrypted data
 * @param[in] key
 *   Encryption context keys
 */
typedef void (*fpn_crypt)(uint8_t *src, uint8_t *dst, uint8_t *key);

/**
 * Context keys setup function
 *
 * @param[out] ctxt
 *   Encryption context keys
 * @param[in] key
 *   Key
 * @param[in] len
 *   Key length
 */
typedef int (*fpn_setkey)(uint8_t *ctxt, uint8_t *key, int len);

#endif /* __FPN_FCRYPT_H__ */
