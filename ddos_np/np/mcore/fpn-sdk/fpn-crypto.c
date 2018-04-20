/*
 * Copyright(c) 2012 6WIND
 */

/* Only implemented on DPDK and TileGx architectures for now */
#if defined(CONFIG_MCORE_FPN_CRYPTO) && \
    (defined(CONFIG_MCORE_ARCH_DPDK) || \
     defined(CONFIG_MCORE_ARCH_TILEGX))

#include "fpn-crypto.h"

static int const cipher_desc[] = {
    [FP_EALGO_NULL]     = FPN_CRYPTO(ALGO_NULL),
    [FP_EALGO_DESCBC]   = FPN_CRYPTO(ALGO_DES_CBC),
    [FP_EALGO_3DESCBC]  = FPN_CRYPTO(ALGO_3DES_CBC),
    [FP_EALGO_AESCBC]   = FPN_CRYPTO(ALGO_AES_CBC),
    [FP_EALGO_AESGCM]   = FPN_CRYPTO(ALGO_AES_GCM),
    [FP_EALGO_NULL_AESGMAC] = FPN_CRYPTO(ALGO_NULL),
};

static struct {
    int   algo;
    u_int key_len;
    int   digest_len;
} const auth_desc[] = {
    [FP_AALGO_NULL]         = {
        .algo       = FPN_CRYPTO(AUTH_NULL),
        .key_len    = 0,
        .digest_len = 0,
    },
    [FP_AALGO_HMACMD5]      = {
        .algo       = FPN_CRYPTO(AUTH_HMACMD5),
        .key_len    = 128,
        .digest_len = 96,
    },
    [FP_AALGO_HMACSHA1]     = {
        .algo       = FPN_CRYPTO(AUTH_HMACSHA1),
        .key_len    = 160,
        .digest_len = 96,
    },
    [FP_AALGO_AESXCBC]      = {
        .algo       = FPN_CRYPTO(AUTH_AES_XCBC),
        .key_len    = 128,
        .digest_len = 96,
    },
    [FP_AALGO_HMACSHA256]   = {
        .algo       = FPN_CRYPTO(AUTH_HMACSHA256),
        .key_len    = 256,
        .digest_len = 128,
    },
    [FP_AALGO_HMACSHA384]   = {
        .algo       = FPN_CRYPTO(AUTH_HMACSHA384),
        .key_len    = 384,
        .digest_len = 192,
    },
    [FP_AALGO_HMACSHA512]   = {
        .algo       = FPN_CRYPTO(AUTH_HMACSHA512),
        .key_len    = 512,
        .digest_len = 256,
    },
};

/**
 * FPN crypto API
 */

/* Initialise per session structures */
int fpn_crypto_priv_alloc(void **sa_priv, uint8_t direction, const uint64_t *key_enc,
                          u_int key_len, const char *key_auth, int enc_algo,
                          int auth_algo, int esn)
{
    fpn_crypto_init_t init;
    void * session;

    /* Initialize a crypto session */
    init.enc_alg   = cipher_desc[enc_algo];
    init.enc_klen  = key_len * 8;
    init.enc_key   = (const char *) key_enc;
    init.flags     = (direction == FPN_ENCRYPT ? FPN_CRYPTO(F_ENCRYPT)
                                               : FPN_CRYPTO(F_AUTH_CHECK));

    switch (enc_algo) {
        case FP_EALGO_AESGCM:
            init.auth_alg  = FPN_CRYPTO(AUTH_AES_GCM);
            init.auth_klen = 8; /* IPsec AAD length */
            if (esn)
                init.auth_klen += 4;
            init.auth_dlen = 128;
            init.auth_key  = NULL;
            break;

        case FP_EALGO_NULL_AESGMAC:
            init.auth_alg  = FPN_CRYPTO(AUTH_AES_GMAC);
            init.auth_klen = key_len * 8;
            init.auth_dlen = 128;
            init.auth_key  = (const char *) key_enc;
            break;

        default:
            init.auth_alg  = auth_desc[auth_algo].algo;
            init.auth_klen = auth_desc[auth_algo].key_len;
            init.auth_dlen = auth_desc[auth_algo].digest_len;
            init.auth_key  = key_auth;
            break;
    }

    session = fpn_crypto_session_new(&init);

    if (session == NULL) {
        return -1;
    }

    *sa_priv = session;
    return 0;
}

/* Free per session structures */
int fpn_crypto_priv_free(void *sa_priv)
{
	/* Free session */
	return fpn_crypto_session_free(sa_priv);
}

/**
 * This function is used to send a buffer to be encrypted/decrypted to
 *   crypto library
 */
int fpn_crypto_async_cipher_auth(__fpn_maybe_unused int enc_algo,
                                 __fpn_maybe_unused const uint64_t *key_enc,
                                 __fpn_maybe_unused u_int key_len, 
                                 int cipher_src_off,
                                 unsigned int datalen, int iv_off,
                                 __fpn_maybe_unused int iv_len,
                                 __fpn_maybe_unused int auth_algo,
                                 __fpn_maybe_unused const char *key_auth,
                                 __fpn_maybe_unused int auth_key_len,
                                 int auth_src_off, char *auth,
                                 unsigned int auth_len,
                                 __fpn_maybe_unused int cipher_direction,
                                 struct mbuf *m,
                                 void *callback, void *priv)
{
	fpn_crypto_op_t operation;
	int status;

	/* Do the send to library */
	operation.session       = priv;
	operation.src           = m;
	operation.enc_dst       = m;
	operation.enc_len       = datalen;
	operation.enc_iv        = mtod(m, char *) + iv_off;
	operation.enc_skip      = cipher_src_off;
	operation.enc_inject    = 0;
	operation.auth_dst      = auth;
	operation.auth_len      = auth_len;
	operation.auth_skip     = auth_src_off;
	operation.opaque        = NULL;
	operation.cb            = callback;
	operation.flags         = FPN_CRYPTO(F_MBUF);

	/* Send packet to hardware and loop until it is done */
	while ((status = fpn_crypto_invoke(&operation)) == FPN_CRYPTO(BUSY));

	/* Return send status */
	return status;
}

#else

/* Initialise per session structures */
int fpn_crypto_priv_alloc(void **sa_priv,
                          __fpn_maybe_unused uint8_t direction, 
                          __fpn_maybe_unused const uint64_t *key_enc,
                          __fpn_maybe_unused u_int key_len,
                          __fpn_maybe_unused const char *key_auth,
                          __fpn_maybe_unused int enc_algo,
                          __fpn_maybe_unused int auth_algo,
			  __fpn_maybe_unused int esn)
{
    *sa_priv = 0;
	return -1;
}

/* Free per session structures */
int fpn_crypto_priv_free(__fpn_maybe_unused void *sa_priv)
{
	return 0;
}

/**
 * This function is used to send a buffer to be encrypted/decrypted to
 *   crypto library
 */
int fpn_crypto_async_cipher_auth(__fpn_maybe_unused int enc_algo,
                                 __fpn_maybe_unused const uint64_t *key_enc,
                                 __fpn_maybe_unused u_int key_len,
                                 __fpn_maybe_unused int cipher_src_off,
                                 __fpn_maybe_unused unsigned int datalen,
                                 __fpn_maybe_unused int iv_off,
                                 __fpn_maybe_unused int iv_len,
                                 __fpn_maybe_unused int auth_algo,
                                 __fpn_maybe_unused const char *key_auth,
                                 __fpn_maybe_unused int auth_key_len,
                                 __fpn_maybe_unused int auth_src_off,
                                 __fpn_maybe_unused char *auth,
                                 __fpn_maybe_unused unsigned int auth_len,
                                 __fpn_maybe_unused int cipher_direction,
                                 __fpn_maybe_unused struct mbuf *m,
                                 __fpn_maybe_unused void *callback,
                                 __fpn_maybe_unused void *priv)
{
	return -1;
}

#endif
