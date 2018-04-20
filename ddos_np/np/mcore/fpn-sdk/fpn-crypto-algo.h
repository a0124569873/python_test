/*
 * Copyright(c) 2012 6WIND
 */
#ifndef _FPN_CRYPTO_ALGO_H_
#define _FPN_CRYPTO_ALGO_H_

#define FP_AALGO_NULL         0
#define FP_AALGO_HMACMD5      1
#define FP_AALGO_HMACSHA1     2
#define FP_AALGO_AESXCBC      3
#define FP_AALGO_HMACSHA256   4
#define FP_AALGO_HMACSHA384   5
#define FP_AALGO_HMACSHA512   6
#define FP_MAX_AALGOS         7

#define FP_EALGO_NULL         0
#define FP_EALGO_DESCBC       1
#define FP_EALGO_3DESCBC      2
#define FP_EALGO_AESCBC       3
#define FP_EALGO_AESGCM       4
#define FP_EALGO_NULL_AESGMAC 5
#define FP_MAX_EALGOS         6

/* Some common crypto definitions */
#define FP_MAX_KEY_ENC_LENGTH	40	/* 256 bits for AES + 32 bits GCM salt + 32 bits round up */
#define FP_MAX_KEY_AUTH_LENGTH	64	/* 512 bits for HMAC-SHA512 */
#define	FP_MAX_IVLEN            16	/* over all algo */
#define FP_MAX_HASH_BLOCK_SIZE  128

#endif /* _FPN_CRYPTO_ALGO_H_ */
