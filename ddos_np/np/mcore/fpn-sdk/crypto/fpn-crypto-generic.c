/*
 * Copyright(c) 2013 6WIND
 */

#include "fpn.h"
#include "fpn-mempool.h"
#include "fpn-ring.h"

/* Generic implementation */
#include "crypto/fpn-crypto-generic.h"
#include "crypto/fpn-rijndael.h"
#include "crypto/fpn-cbc.h"
#include "crypto/fpn-des.h"
#include "crypto/fpn-hmac.h"
#include "crypto/fpn-md5.h"
#include "crypto/fpn-sha1.h"
#include "crypto/fpn-sha2.h"
#include "crypto/fpn-aes.h"
#include "crypto/fpn-ecb.h"
#include "crypto/fpn-ctr.h"
#include "crypto/fpn-gcm.h"
#include "crypto/fpn-xcbc.h"

/*
 * container_of - cast a member of a structure out to the containing structure
 */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define FPN_CRYPTO_MAX_KEY_CRYPTO_SIZE  32 /**< 256 bits for AES             */
#define FPN_CRYPTO_MAX_KEY_AUTH_SIZE    64 /**< 512 bits for HMAC-SHA512     */
#define FPN_CRYPTO_MAX_HASH_DIGEST_LEN  64 /**< 512 bits for HMAC-SHA512     */
#define FPN_CRYPTO_MAX_BUFFERS          16 /**< Max buffers in vectors       */
#define FPN_CRYPTO_MAX_RING            256 /**< Max buffers in ring          */

#define FPN_CRYPTO_F_CLOSE              0x8000

/**
 * Generic crypto implementation
 */

/* This structure contains the per core configuration */
typedef struct fpn_crypto_generic_core_conf_s {
	/* Statistics */
	fpn_crypto_statistics_t     statistics;

	/* Ring of buffers processed */
	struct fpn_ring             ring;
	void                      * ring_table[FPN_CRYPTO_MAX_RING];

	/* Number of pending operations */
	uint32_t                    pending;

	/* Bulk size */
	uint16_t                    rx_bulk;
} __fpn_cache_aligned fpn_crypto_generic_core_conf_t;

/* Encryption context */
typedef union fpn_crypto_enc_ctxt_u {
	ECB_CTX                     ecb;
	CBC_CTX                     cbc;
	CTR_CTX                     ctr;
} fpn_crypto_enc_ctxt_t;

/* Authentication context */
typedef union fpn_crypto_auth_ctxt_u {
	MD5_CTX                     md5;
	SHA1_CTX                    sha1;
	SHA2_CTX                    sha2;
	XCBC_CTX                    xcbc;
	GCM_CTX                     gcm;
} __fpn_cache_aligned fpn_crypto_auth_ctxt_t;

/* This structure describes a ciphering session */
typedef struct fpn_crypto_generic_session_s {
	fpn_crypto_session_t        fpn_session;

	/* Precalc encryption contexts */
	union {
		des_key_schedule        des[3];
		rijndael_ctx            aes;
	}                           enc_precalc;

	/* Precalc auth contexts */
	fpn_crypto_enc_ctxt_t       ctx_e;
	fpn_crypto_auth_ctxt_t      ctx_i;
	fpn_crypto_auth_ctxt_t      ctx_o;

	/* Partial contexts */
	fpn_crypto_enc_ctxt_t       enc_partial;
	fpn_crypto_auth_ctxt_t      auth_partial;

	/* Number of pending operations */
	fpn_atomic_t                pending;

	/* Session flags */
	uint16_t                    flags;

	/* Crypto/hash algos */
	uint8_t                     enc_alg;
	uint8_t                     auth_alg;

	/* Various lengths */
	uint8_t                     crypto_key_len;
	uint8_t                     auth_key_len;
	uint8_t                     digest_len;
	uint8_t                     block_len;
	uint8_t                     iv_len;
} __fpn_cache_aligned fpn_crypto_generic_session_t;

/* Shared with userland driver client */
typedef struct crypto_buffer_s {
	/* Source and dest buffers for this operation */
	void                      * src;
	void                      * dst;

	/* user callback and private param used in callback call */
	fpn_crypto_callback_t       callback;
	void                      * param;

	/* Job result */
	int                         status;

	/* Operation flags */
	uint16_t                    flags;

	union {
		struct sym_s {
			/* Session used */
			fpn_crypto_generic_session_t * session;

			/* Destination vec copy */
			fpn_vec_t           dst_vec[FPN_CRYPTO_MAX_BUFFERS];
			fpn_buf_t           dst_buf;
		}                       sym;
	} __fpn_cache_aligned priv;
} __fpn_cache_aligned fpn_crypto_generic_buffer_t;

static struct {
    uint8_t block_len;
    uint8_t iv_len;
} generic_cipher_desc [] = {
	[FPN_CRYPTO(ALGO_NULL)]          = {
		.iv_len         = 0,
		.block_len      = 1,
	},
	[FPN_CRYPTO(ALGO_DES_CBC)]       = {
		.iv_len         = 8,
		.block_len      = 8,
	},
	[FPN_CRYPTO(ALGO_3DES_CBC)]      = {
		.iv_len         = 8,
		.block_len      = 8,
	},
	[FPN_CRYPTO(ALGO_AES_CBC)]       = {
		.iv_len         = 16,
		.block_len      = 16,
	},
	[FPN_CRYPTO(ALGO_AES_CTR)]       = {
		.iv_len         = 16,
		.block_len      = 1,
	},
	[FPN_CRYPTO(ALGO_AES_GCM)]       = {
		.iv_len         = 12,
		.block_len      = 1,
	},
	[FPN_CRYPTO(ALGO_DES_ECB)]       = {
		.iv_len         = 0,
		.block_len      = 8,
	},
	[FPN_CRYPTO(ALGO_3DES_ECB)]      = {
		.iv_len         = 0,
		.block_len      = 8,
	},
	[FPN_CRYPTO(ALGO_AES_ECB)]       = {
		.iv_len         = 0,
		.block_len      = 16,
	},
	[FPN_CRYPTO(ALGO_RC4)]       = {
		.iv_len         = 0,
		.block_len      = 1,
	},
};

static fpn_atomic_t generic_out_of_session;
static fpn_atomic_t generic_nb_session;
static struct fpn_mempool * generic_session_pool;
static struct fpn_mempool * generic_buffer_pool;
static FPN_DEFINE_PER_CORE(fpn_crypto_generic_core_conf_t *, core_conf);
static fpn_crypto_statistics_t *generic_statistic[FPN_MAX_CORES];


/**
 * Create a session.
 */
fpn_crypto_session_t * fpn_crypto_generic_session_new(fpn_crypto_init_t * init)
{
	fpn_crypto_generic_session_t * session;
	uint32_t encrypt;

	/* Filter unsupported algorithms */
	if (unlikely((init->enc_alg == FPN_CRYPTO(ALGO_RC4)) ||
	             (init->auth_alg == FPN_CRYPTO(AUTH_SHA224)) ||
	             (init->auth_alg == FPN_CRYPTO(AUTH_HMACSHA224)))) {
		fpn_printf("%s: Unsupported algorithms %d/%d\n",
		        __func__, init->enc_alg, init->auth_alg);
		return NULL;
	}

	if (unlikely(((init->enc_klen / 8) > FPN_CRYPTO_MAX_KEY_CRYPTO_SIZE) ||
	             ((init->auth_klen / 8) > FPN_CRYPTO_MAX_KEY_AUTH_SIZE))) {
		fpn_printf("%s: Unsupported key length %d/%d\n",
		        __func__, init->enc_klen, init->auth_klen);
		return NULL;
	}

	/* Get a session from pool */
	fpn_mempool_get(generic_session_pool, (void **) &session);
	if (unlikely(session == NULL)) {
		fpn_printf("%s: No memory available\n", __func__);
		fpn_atomic_inc(&generic_out_of_session);
		return NULL;
	}

	/* Clear session */
	memset(session, 0, sizeof(fpn_crypto_generic_session_t));

	/* Initialize session */
	session->flags          = init->flags;
	session->enc_alg        = init->enc_alg;
	session->auth_alg       = init->auth_alg;
	session->crypto_key_len = init->enc_klen / 8;
	session->auth_key_len   = init->auth_klen / 8;
	session->digest_len     = init->auth_dlen / 8;
	session->iv_len         = generic_cipher_desc[init->enc_alg].iv_len;
	session->block_len      = generic_cipher_desc[init->enc_alg].block_len;
	fpn_atomic_set(&session->pending, 0);

	/* One more session allocated */
	fpn_atomic_inc(&generic_nb_session);

	/* Compute per session stuf */
	encrypt = session->flags & FPN_CRYPTO(F_ENCRYPT);
	switch (session->enc_alg) {
		case FPN_CRYPTO(ALGO_NULL):
			break;

		case FPN_CRYPTO(ALGO_DES_ECB):
			des_set_key((des_cblock *) init->enc_key,
			            &session->enc_precalc.des[0]);
			fpn_ecb_init(&session->ctx_e.ecb,
			             encrypt ? fpn_des_blk_encrypt : fpn_des_blk_decrypt,
			             (uint8_t *)&session->enc_precalc.des, DES_BLK_SZ);
			break;

		case FPN_CRYPTO(ALGO_DES_CBC):
			des_set_key((des_cblock *) init->enc_key,
			            &session->enc_precalc.des[0]);
			fpn_cbc_init(&session->ctx_e.cbc,
			             encrypt ? fpn_des_blk_encrypt : fpn_des_blk_decrypt,
			             (uint8_t *)&session->enc_precalc.des, DES_BLK_SZ);
			break;

		case FPN_CRYPTO(ALGO_3DES_ECB):
			des_set_key((des_cblock *) &init->enc_key[0],
			            &session->enc_precalc.des[0]);
			des_set_key((des_cblock *) &init->enc_key[8],
			            &session->enc_precalc.des[1]);
			des_set_key((des_cblock *) &init->enc_key[16],
			            &session->enc_precalc.des[2]);
			fpn_ecb_init(&session->ctx_e.ecb,
			             encrypt ? fpn_3des_blk_encrypt : fpn_3des_blk_decrypt,
			             (uint8_t *)&session->enc_precalc.des, DES_BLK_SZ);
			break;

		case FPN_CRYPTO(ALGO_3DES_CBC):
			des_set_key((des_cblock *) &init->enc_key[0],
			            &session->enc_precalc.des[0]);
			des_set_key((des_cblock *) &init->enc_key[8],
			            &session->enc_precalc.des[1]);
			des_set_key((des_cblock *) &init->enc_key[16],
			            &session->enc_precalc.des[2]);
			fpn_cbc_init(&session->ctx_e.cbc,
			             encrypt ? fpn_3des_blk_encrypt : fpn_3des_blk_decrypt,
			             (uint8_t *)&session->enc_precalc.des, DES_BLK_SZ);
			break;

		case FPN_CRYPTO(ALGO_AES_ECB):
			aes_setkey((uint8_t *)&session->enc_precalc.aes,
			           (uint8_t *)init->enc_key, session->crypto_key_len);
			fpn_ecb_init(&session->ctx_e.ecb,
			             encrypt ? aes_encrypt : aes_decrypt,
			             (uint8_t *)&session->enc_precalc.aes, AES_BLOCK_SIZE);
			break;

		case FPN_CRYPTO(ALGO_AES_CBC):
			aes_setkey((uint8_t *)&session->enc_precalc.aes,
			           (uint8_t *)init->enc_key, session->crypto_key_len);
			fpn_cbc_init(&session->ctx_e.cbc,
			             encrypt ? aes_encrypt : aes_decrypt,
			             (uint8_t *)&session->enc_precalc.aes, AES_BLOCK_SIZE);
			break;

		case FPN_CRYPTO(ALGO_AES_GCM):
			aes_setkey((uint8_t *)&session->enc_precalc.aes,
			           (uint8_t *)init->enc_key, session->crypto_key_len);
			break;

		case FPN_CRYPTO(ALGO_AES_CTR):
			aes_setkey((uint8_t *)&session->enc_precalc.aes,
			           (uint8_t *)init->enc_key, session->crypto_key_len);
			fpn_ctr_init(&session->ctx_e.ctr, aes_encrypt,
			             (uint8_t *)&session->enc_precalc.aes, AES_BLOCK_SIZE);
			break;
	}

	switch (session->auth_alg) {
		case FPN_CRYPTO(AUTH_NULL):
			break;

		case FPN_CRYPTO(AUTH_MD5):
			md5_init((uint8_t *)&session->ctx_i.md5);
			break;

		case FPN_CRYPTO(AUTH_SHA1):
			sha1_init((uint8_t *)&session->ctx_i.sha1);
			break;

		case FPN_CRYPTO(AUTH_SHA256):
			sha256_init((uint8_t *)&session->ctx_i.sha2);
			break;

		case FPN_CRYPTO(AUTH_SHA384):
			sha384_init((uint8_t *)&session->ctx_i.sha2);
			break;

		case FPN_CRYPTO(AUTH_SHA512):
			sha512_init((uint8_t *)&session->ctx_i.sha2);
			break;

		case FPN_CRYPTO(AUTH_HMACMD5):
			HMAC_Init((uint8_t *)&session->ctx_i.md5,
			          (uint8_t *)&session->ctx_o.md5,
			          (uint8_t *)init->auth_key, session->auth_key_len,
			          MD5_BLOCK_LENGTH, MD5_DIGEST_LENGTH,
					  md5_init, md5_update, md5_final);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA1):
			HMAC_Init((uint8_t *)&session->ctx_i.sha1,
			          (uint8_t *)&session->ctx_o.sha1,
			          (uint8_t *)init->auth_key, session->auth_key_len,
			          SHA1_BLOCK_LENGTH, SHA1_DIGEST_LENGTH,
			          sha1_init, sha1_update, sha1_final);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA256):
			HMAC_Init((uint8_t *)&session->ctx_i.sha2,
			          (uint8_t *)&session->ctx_o.sha2,
			          (uint8_t *)init->auth_key, session->auth_key_len,
			          SHA256_BLOCK_LENGTH, SHA256_DIGEST_LENGTH,
			          sha256_init, sha256_update, sha256_final);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA384):
			HMAC_Init((uint8_t *)&session->ctx_i.sha2,
			          (uint8_t *)&session->ctx_o.sha2,
			          (uint8_t *)init->auth_key, session->auth_key_len,
			          SHA384_BLOCK_LENGTH, SHA384_DIGEST_LENGTH,
			          sha384_init, sha384_update, sha384_final);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA512):
			HMAC_Init((uint8_t *)&session->ctx_i.sha2,
			          (uint8_t *)&session->ctx_o.sha2,
			          (uint8_t *)init->auth_key, session->auth_key_len,
			          SHA512_BLOCK_LENGTH, SHA512_DIGEST_LENGTH,
			          sha512_init, sha512_update, sha512_final);
			break;

		case FPN_CRYPTO(AUTH_AES_XCBC):
			fpn_xcbc_init(&session->ctx_i.xcbc, &session->ctx_o.xcbc,
 			              (uint8_t *)init->auth_key, session->auth_key_len,
			              AES_BLOCK_SIZE, aes_setkey_enc, aes_encrypt);
			break;

		case FPN_CRYPTO(AUTH_AES_GCM):
			fpn_gcm_init(&session->ctx_i.gcm, aes_encrypt,
			             (uint8_t *)&session->enc_precalc.aes, AES_BLOCK_SIZE);
			break;

		case FPN_CRYPTO(AUTH_AES_GMAC):
			session->iv_len    = generic_cipher_desc[FPN_CRYPTO(ALGO_AES_GCM)].iv_len;
			session->block_len = generic_cipher_desc[FPN_CRYPTO(ALGO_AES_GCM)].block_len;
			aes_setkey((uint8_t *)&session->enc_precalc.aes,
			           (uint8_t *)init->auth_key, session->auth_key_len);
			fpn_gcm_init(&session->ctx_i.gcm, aes_encrypt,
			             (uint8_t *)&session->enc_precalc.aes, AES_BLOCK_SIZE);
			break;
	}

	/* All is done */
	return &session->fpn_session;
}

/**
 * Get some session parameters
 */
int fpn_crypto_generic_session_params(fpn_crypto_session_t * fpn_session, uint16_t * block_len, uint16_t * digest_len)
{
	fpn_crypto_generic_session_t * session = container_of(fpn_session, fpn_crypto_generic_session_t, fpn_session);

	/* Return expected values */
	*block_len  = session->block_len;
	*digest_len = session->digest_len;

	return FPN_CRYPTO(SUCCESS);
}

/**
 * Duplicate a session.
 */
fpn_crypto_session_t * fpn_crypto_generic_session_dup(fpn_crypto_session_t * orig)
{
	fpn_crypto_generic_session_t * initial = container_of(orig, fpn_crypto_generic_session_t, fpn_session);
	fpn_crypto_generic_session_t * session;

	/* Allocate a session */
	fpn_mempool_get(generic_session_pool, (void **) &session);
	if (unlikely(session == NULL)) {
		fpn_printf("%s: No memory available\n", __func__);
		fpn_atomic_inc(&generic_out_of_session);
		return NULL;
	}

	/* Copy session */
	fpn_memcpy(session, initial, sizeof(fpn_crypto_generic_session_t));

	/* Initialize session */
	session->flags &= ~FPN_CRYPTO_F_CLOSE;
	fpn_atomic_set(&session->pending, 0);

	/* One more session allocated */
	fpn_atomic_inc(&generic_nb_session);

	/* All is done */
	return &session->fpn_session;
}

/**
 * Free a session
 */
static inline int fpn_crypto_generic_session_exit(
    fpn_crypto_generic_session_t * session   /* Session context                    */
)
{
	/* Free session */
	fpn_mempool_put(generic_session_pool, session);

	/* One more session freed */
	fpn_atomic_dec(&generic_nb_session);

	/* All is done */
	return FPN_CRYPTO(SUCCESS);
}

/**
 * Free a session. Wait until all pending calls are done
 */
int fpn_crypto_generic_session_free(fpn_crypto_session_t * arg)
{
	fpn_crypto_generic_session_t * session;

	/* Get session */
	session = container_of(arg, fpn_crypto_generic_session_t, fpn_session);

	/* Return if invalid pointer */
	if (arg == NULL) return FPN_CRYPTO(SUCCESS);

	/* Mark session as closing */
	/* No wmb needed, atomic instruction below ensure sync */
	session->flags |= FPN_CRYPTO_F_CLOSE;

	/* test-and-set to ensure that 'pending' will not be seen null at
	 * the same time on the core that polled the last crypto processed
	 * packet, causing a dual free of the session.
	 * If it is null, setting it atomically to any non null value will
	 * guarantee that it will never be null again, since no more packets
	 * are expected to come back from crypto
	 */
	if (!fpn_atomic_test_and_set(&session->pending)) {
		/* Do the release when all buffers are received */
		return FPN_CRYPTO(SUCCESS);
	} else {
		/* There is nothing pending on this session, free it directly */
		return fpn_crypto_generic_session_exit(session);
	}
}

/**
 * Do crypto operation
 */
static void fpn_crypto_generic_process(fpn_crypto_generic_session_t * session,
                                       fpn_crypto_enc_ctxt_t * enc_ctxt,
                                       fpn_crypto_auth_ctxt_t * auth_ctxt,
                                       uint8_t * enc_src, uint8_t * enc_dst,
                                       uint32_t enc_len, 
                                       uint8_t * auth_src, uint32_t auth_len)
{
	/* In GCM, first process AAD data */
	if ((session->auth_alg == FPN_CRYPTO(AUTH_AES_GCM)) &&
	    (auth_len > enc_len)) {
	     fpn_gcm_auth(&auth_ctxt->gcm, auth_src, auth_len - enc_len);
	}

	/* Do encryption part */
	if (session->flags & FPN_CRYPTO(F_ENCRYPT)) {
		switch (session->enc_alg) {
			case FPN_CRYPTO(ALGO_NULL):
				break;

			case FPN_CRYPTO(ALGO_DES_CBC):
			case FPN_CRYPTO(ALGO_3DES_CBC):
			case FPN_CRYPTO(ALGO_AES_CBC):
				fpn_cbc_encrypt(&enc_ctxt->cbc, enc_src, enc_dst, enc_len);
				break;

			case FPN_CRYPTO(ALGO_AES_CTR):
				fpn_ctr_encrypt(&enc_ctxt->ctr, enc_src, enc_dst, enc_len);
				break;

			case FPN_CRYPTO(ALGO_AES_GCM):
				fpn_gcm_encrypt(&auth_ctxt->gcm, enc_src, enc_dst, enc_len);
				break;

			case FPN_CRYPTO(ALGO_DES_ECB):
			case FPN_CRYPTO(ALGO_3DES_ECB):
			case FPN_CRYPTO(ALGO_AES_ECB):
				fpn_ecb_encrypt(&enc_ctxt->ecb, enc_src, enc_dst, enc_len);
				break;
		}
	}

	/* Do authentication */
	switch (session->auth_alg) {
		case FPN_CRYPTO(AUTH_NULL):
			break;

		case FPN_CRYPTO(AUTH_MD5):
			md5_update((uint8_t *)&auth_ctxt->md5, auth_src, auth_len);
			break;

		case FPN_CRYPTO(AUTH_SHA1):
			sha1_update((uint8_t *)&auth_ctxt->sha1, auth_src, auth_len);
			break;

		case FPN_CRYPTO(AUTH_SHA256):
			sha256_update((uint8_t *)&auth_ctxt->sha2, auth_src, auth_len);
			break;

		case FPN_CRYPTO(AUTH_SHA384):
			sha384_update((uint8_t *)&auth_ctxt->sha2, auth_src, auth_len);
			break;

		case FPN_CRYPTO(AUTH_SHA512):
			sha512_update((uint8_t *)&auth_ctxt->sha2, auth_src, auth_len);
			break;

		case FPN_CRYPTO(AUTH_HMACMD5):
			HMAC_Update((uint8_t *)&auth_ctxt->md5, auth_src,
			            auth_len, md5_update);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA1):
			HMAC_Update((uint8_t *)&auth_ctxt->sha1, auth_src,
			            auth_len, sha1_update);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA256):
			HMAC_Update((uint8_t *)&auth_ctxt->sha2, auth_src,
			            auth_len, sha256_update);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA384):
			HMAC_Update((uint8_t *)&auth_ctxt->sha2, auth_src,
			            auth_len, sha384_update);
			break;

		case FPN_CRYPTO(AUTH_HMACSHA512):
			HMAC_Update((uint8_t *)&auth_ctxt->sha2, auth_src,
			            auth_len, sha512_update);
			break;

		case FPN_CRYPTO(AUTH_AES_XCBC):
			fpn_xcbc_update(&auth_ctxt->xcbc, auth_src, auth_len);
			break;

		case FPN_CRYPTO(AUTH_AES_GMAC):
			fpn_gcm_auth(&auth_ctxt->gcm, auth_src, auth_len);
			break;
	}

	/* Do decryption part */
	if (!(session->flags & FPN_CRYPTO(F_ENCRYPT))) {
		switch (session->enc_alg) {
			case FPN_CRYPTO(ALGO_NULL):
				break;

			case FPN_CRYPTO(ALGO_DES_CBC):
			case FPN_CRYPTO(ALGO_3DES_CBC):
			case FPN_CRYPTO(ALGO_AES_CBC):
				fpn_cbc_decrypt(&enc_ctxt->cbc, enc_src, enc_dst, enc_len);
				break;

			case FPN_CRYPTO(ALGO_AES_CTR):
				fpn_ctr_decrypt(&enc_ctxt->ctr, enc_src, enc_dst, enc_len);
				break;

			case FPN_CRYPTO(ALGO_AES_GCM):
				fpn_gcm_decrypt(&auth_ctxt->gcm, enc_src, enc_dst, enc_len);
				break;

			case FPN_CRYPTO(ALGO_DES_ECB):
			case FPN_CRYPTO(ALGO_3DES_ECB):
			case FPN_CRYPTO(ALGO_AES_ECB):
				fpn_ecb_decrypt(&enc_ctxt->ecb, enc_src, enc_dst, enc_len);
				break;
		}
	}
}


/**
 * Do crypto operation
 */
int fpn_crypto_generic_invoke(fpn_crypto_op_t * operation)
{
	fpn_crypto_generic_core_conf_t * core_conf;
	fpn_crypto_generic_session_t   * session;
	fpn_crypto_generic_buffer_t    * buffer;
	fpn_crypto_enc_ctxt_t            enc_ctxt, * enc_base;
	fpn_crypto_auth_ctxt_t           auth_ctxt, * auth_base;
	struct sym_s                   * sym;
	void                           * dst;
	uint32_t                         enc_skip, enc_inject;
	uint8_t                          auth_digest[FPN_CRYPTO_MAX_HASH_DIGEST_LEN];
	int                              ret, continued = 0;

	/* Get core conf */
	core_conf = FPN_PER_CORE_VAR(core_conf);

	/* Get session */
	session = container_of(operation->session, fpn_crypto_generic_session_t, fpn_session);

	/* If no session or no buffer provided, this is an error */
	if (unlikely((session == NULL) ||
	             ((operation->enc_len != 0) &&
	              (operation->enc_dst == NULL)))) {
		return FPN_CRYPTO(FAILURE);
	}

	/* Do NULL encryption immediately */
	if (unlikely((session->enc_alg  == FPN_CRYPTO(ALGO_NULL)) &&
	             (session->auth_alg == FPN_CRYPTO(AUTH_NULL)))) {
		if (operation->cb != NULL) {
			operation->cb(operation->opaque, operation->enc_dst, FPN_CRYPTO(SUCCESS));
		}
		return FPN_CRYPTO(SUCCESS);
	}

	/* Get buffer from pool */
	if ((generic_buffer_pool == NULL) ||
	    (fpn_mempool_get(generic_buffer_pool, (void **) &buffer) < 0)) {
		fpn_printf("%s: Can not allocate buffer\n",
		        __func__);
		core_conf->statistics.out_of_buffer++;
		return FPN_CRYPTO(FAILURE);
	}

	/* Setup buffer */
	buffer->src     = operation->src;
	buffer->dst     = operation->enc_dst;
	buffer->flags   = operation->flags;
	buffer->callback= operation->cb;
	buffer->param   = operation->opaque;
	buffer->status  = FPN_CRYPTO(SUCCESS);

	/* Initialize symmetric fields */
	sym = &buffer->priv.sym;
	sym->session    = session;

	/* If partial hash in progress, get hash context from session */
	/* else get precalc contexts */
	if (session->flags & FPN_CRYPTO(F_PARTIAL)) {
		enc_base  = &session->enc_partial;
		auth_base = &session->auth_partial;
		continued = 1;
	} else {
		enc_base  = &session->ctx_e;
		auth_base = &session->ctx_i;
	}

	/* Setup authentication context */
	switch (session->auth_alg) {
		case FPN_CRYPTO(AUTH_NULL):
			break;

		case FPN_CRYPTO(AUTH_MD5):
		case FPN_CRYPTO(AUTH_HMACMD5):
			auth_ctxt.md5 = auth_base->md5;
			break;

		case FPN_CRYPTO(AUTH_HMACSHA1):
		case FPN_CRYPTO(AUTH_SHA1):
			auth_ctxt.sha1 = auth_base->sha1;
			break;

		case FPN_CRYPTO(AUTH_SHA256):
		case FPN_CRYPTO(AUTH_SHA384):
		case FPN_CRYPTO(AUTH_SHA512):
		case FPN_CRYPTO(AUTH_HMACSHA256):
		case FPN_CRYPTO(AUTH_HMACSHA384):
		case FPN_CRYPTO(AUTH_HMACSHA512):
			auth_ctxt.sha2 = auth_base->sha2;
			break;

		case FPN_CRYPTO(AUTH_AES_XCBC):
			auth_ctxt.xcbc = auth_base->xcbc;
			break;

		case FPN_CRYPTO(AUTH_AES_GCM):
		case FPN_CRYPTO(AUTH_AES_GMAC):
			auth_ctxt.gcm = auth_base->gcm;
			/* Setup IV */
			if (!continued) {
				fpn_gcm_start(&auth_ctxt.gcm, 
				              (uint8_t *)operation->enc_iv,
				              session->iv_len);
			}
			break;
	}

	/* Setup encryption context */
	switch (session->enc_alg) {
		case FPN_CRYPTO(ALGO_DES_ECB):
		case FPN_CRYPTO(ALGO_3DES_ECB):
		case FPN_CRYPTO(ALGO_AES_ECB):
			enc_ctxt.ecb = enc_base->ecb;
			if (!continued) {
				fpn_ecb_start(&enc_ctxt.ecb,
				              (uint8_t *)operation->enc_iv);
			}
			break;

		case FPN_CRYPTO(ALGO_DES_CBC):
		case FPN_CRYPTO(ALGO_3DES_CBC):
		case FPN_CRYPTO(ALGO_AES_CBC):
			enc_ctxt.cbc = enc_base->cbc;
			if (!continued) {
				fpn_cbc_start(&enc_ctxt.cbc, 
				              (uint8_t *)operation->enc_iv);
			}
			break;

		case FPN_CRYPTO(ALGO_AES_CTR):
			enc_ctxt.ctr = enc_base->ctr;
			if (!continued) {
				fpn_ctr_start(&enc_ctxt.ctr, 
				              (uint8_t *)operation->enc_iv);
			}
			break;
	}

	/* Skip enc skipped data */
	enc_skip   = operation->enc_skip;
	enc_inject = enc_skip;

	/* Set up destination buffer chain */
	dst = operation->src;
	if (unlikely((operation->enc_dst != operation->src) && 
	             (operation->enc_dst != NULL))) {
		if (buffer->flags & FPN_CRYPTO(F_MBUF)) {
			/* Copy injected data */
			if (operation->enc_inject > 0) {
				fpn_memcpy(mtod((struct mbuf *) operation->enc_dst, char *),
						   mtod((struct mbuf *) operation->src, char *),
						   operation->enc_inject);
			}
		} else {
			fpn_buf_t * vbuf = operation->enc_dst;

			/* Store destination vec, will be used on return */
			if (unlikely(vbuf->veccnt > FPN_CRYPTO_MAX_BUFFERS)) {
				fpn_printf("%s: buffer chain too long\n", __func__);

				fpn_mempool_put(generic_buffer_pool, buffer);
				core_conf->statistics.out_of_buffer++;
				return FPN_CRYPTO(FAILURE);
			}
			fpn_memcpy(sym->dst_vec, vbuf->vec,
					   sizeof(fpn_vec_t) * vbuf->veccnt);

			/* Use copied desc since operation structure may be obsolete on callback call */
			sym->dst_buf.vec    = sym->dst_vec;
			sym->dst_buf.veccnt = vbuf->veccnt;
			buffer->dst = &sym->dst_buf;

			/* Copy injected data */
			if (operation->enc_inject > 0) {
				fpn_memcpy(sym->dst_vec[0].base,
						   ((fpn_buf_t *) operation->src)->vec[0].base,
						   operation->enc_inject);
			}
		}

		/* Skip injected data */
		enc_inject = operation->enc_inject;

		/* Set up destination buffer */
		dst = operation->enc_dst;
	}

	/* Process buffer chain */
	if (likely(operation->src != NULL)) {
		uint8_t * dest = NULL;
		uint8_t   block[FPN_MAX_BLOCK_SIZE];
		uint32_t  auth_skip;
		uint32_t  enc_left, auth_left;
		uint8_t   stored = 0;

		/* Set base offsets */
		auth_skip   = operation->auth_skip;
		enc_left    = operation->enc_len;
		auth_left   = operation->auth_len;

		/* Process according to buffer type */
		if (likely(buffer->flags & FPN_CRYPTO(F_MBUF))) {
			struct mbuf * mbuf = operation->src;
			struct mbuf * dbuf = dst;
			struct sbuf * sseg, * dseg;

			sseg = m_first_seg(mbuf);
			dseg = m_first_seg(dbuf);
			while (sseg != NULL) {
				uint32_t enc_len, auth_len;

				/* Check destination segment */
				if (dseg == NULL) {
					fpn_printf("%s: Invalid destination buffer\n", __func__);
					fpn_mempool_put(generic_buffer_pool, buffer);
					return FPN_CRYPTO(FAILURE);
				}

				/* If some data were remaining from previous buffer */
				if (unlikely(stored != 0)) {
					uint8_t blen = session->block_len, dlen = blen - stored;

					/* Fill block */
					fpn_memcpy(&block[stored], s_data(sseg, uint8_t *), dlen);

					/* Call generic crypto operation */
					fpn_crypto_generic_process(session, &enc_ctxt,
					                           &auth_ctxt, block, block,
					                           blen, block, blen);

					/* Copy back cipher text in correct location */
					fpn_memcpy(dest, block, stored);
					fpn_memcpy(s_data(dseg, uint8_t *), &block[stored], dlen);

					/* Skip copied data and update offsets */
					enc_skip    += dlen;
					auth_skip   += dlen;
					enc_inject  += dlen;
					enc_left    -= blen;
					auth_left   -= blen;
					stored       = 0;
				}

				/* Buffer chain crypto need special block size checks */
				if (likely(enc_left <= (s_len(sseg) - enc_skip))) {
					enc_len  = enc_left;
					auth_len = auth_left > s_len(sseg) - auth_skip ?
							   s_len(sseg) - auth_skip : auth_left;
				} else {
					enc_len = s_len(sseg) - enc_skip;

					/* If encrypt size is not a multiple of block length */
					stored = enc_len & (session->block_len - 1);
					if (stored != 0) {
						/* Reduce to a block length */
						enc_len &= ~(session->block_len - 1);

						/* Copy remaining data in a temporary block */
						fpn_memcpy(block, s_data(sseg, uint8_t *) + 
						                  enc_skip + enc_len, stored);
						dest = s_data(dseg, uint8_t *) + enc_inject + enc_len;
					}

					/* Restrict authentication size to encrypted data */
					auth_len = enc_skip + enc_len - auth_skip;
				}

				/* Call generic crypto operation */
				fpn_crypto_generic_process(session, &enc_ctxt, &auth_ctxt,
				                           s_data(sseg, uint8_t *) + enc_skip,
				                           s_data(dseg, uint8_t *) + enc_inject, enc_len,
				                           s_data(dseg, uint8_t *) + auth_skip, auth_len);

				/* Update offsets */
				enc_skip     = 0;
				auth_skip    = 0;
				enc_inject   = 0;
				enc_left    -= enc_len;
				auth_left   -= auth_len;

				/* Next segment */
				sseg = s_next(mbuf, sseg);
				dseg = s_next(dbuf, dseg);
			}
		} else {
			fpn_buf_t * vsrc = operation->src;
			fpn_buf_t * vdst = dst;
			fpn_vec_t * svec, * dvec;
			int seg;

			for (seg=0 ; seg < vsrc->veccnt ; seg++) {
				uint32_t enc_len, auth_len;

				/* Get next segment */
				svec = &vsrc->vec[seg];
				dvec = &vdst->vec[seg];

				/* Check destination segment */
				if (dvec->base == NULL) {
					fpn_printf("%s: Invalid destination buffer\n", __func__);
					fpn_mempool_put(generic_buffer_pool, buffer);
					return FPN_CRYPTO(FAILURE);
				}

				/* If some data were remaining from previous buffer */
				if (unlikely(stored != 0)) {
					uint8_t blen = session->block_len, dlen = blen - stored;

					/* Fill block */
					fpn_memcpy(&block[stored], svec->base, dlen);

					/* Call generic crypto operation */
					fpn_crypto_generic_process(session, &enc_ctxt,
					                           &auth_ctxt, block, block,
					                           blen, block, blen);

					/* Copy back cipher text in correct location */
					fpn_memcpy(dest, block, stored);
					fpn_memcpy(dvec->base, &block[stored], dlen);

					/* Skip copied data and update offsets */
					enc_skip    += dlen;
					auth_skip   += dlen;
					enc_inject  += dlen;
					enc_left    -= blen;
					auth_left   -= blen;
					stored       = 0;
				}

				/* Buffer chain crypto need special block size checks */
				if (likely(enc_left <= (svec->len - enc_skip))) {
					enc_len  = enc_left;
					auth_len = auth_left > svec->len - auth_skip ?
							   svec->len - auth_skip : auth_left;
				} else {
					enc_len = svec->len - enc_skip;

					/* If encrypt size is not a multiple of block length */
					stored = enc_len & (session->block_len - 1);
					if (stored != 0) {
						/* Reduce to a block length */
						enc_len &= ~(session->block_len - 1);

						/* Copy remaining data in a temporary block */
						fpn_memcpy(block, svec->base + enc_skip + enc_len, stored);
						dest = dvec->base + enc_inject + enc_len;
					}

					/* Restrict authentication size to encrypted data */
					auth_len = enc_skip + enc_len - auth_skip;
				}

				/* Call generic crypto operation */
				fpn_crypto_generic_process(session, &enc_ctxt, &auth_ctxt,
				                           svec->base + enc_skip,
				                           dvec->base + enc_inject, enc_len,
				                           dvec->base + auth_skip, auth_len);

				/* Update offsets */
				enc_skip     = 0;
				auth_skip    = 0;
				enc_inject   = 0;
				enc_left    -= enc_len;
				auth_left   -= auth_len;
			}
		}
	}

	/* In partial mode, save context in session else finalize hash */
	if (buffer->flags & FPN_CRYPTO(F_PARTIAL)) {
		/* Store partial flag in session */
		session->flags |= FPN_CRYPTO(F_PARTIAL);

		/* Store context in session */
		session->enc_partial  = enc_ctxt;
		session->auth_partial = auth_ctxt;
	} else {
		fpn_crypto_auth_ctxt_t ctx_o;

		/* Reset session flag if needed */
		if (session->flags & FPN_CRYPTO(F_PARTIAL)) {
			session->flags &= ~ FPN_CRYPTO(F_PARTIAL);
		}

		switch (session->auth_alg) {
			case FPN_CRYPTO(AUTH_NULL):
				break;

			case FPN_CRYPTO(AUTH_MD5):
				md5_final(auth_digest, (uint8_t *)&auth_ctxt.md5);
				break;

			case FPN_CRYPTO(AUTH_SHA1):
				sha1_final(auth_digest, (uint8_t *)&auth_ctxt.sha1);
				break;

			case FPN_CRYPTO(AUTH_SHA256):
				sha256_final(auth_digest, (uint8_t *)&auth_ctxt.sha2);
				break;

			case FPN_CRYPTO(AUTH_SHA384):
				sha384_final(auth_digest, (uint8_t *)&auth_ctxt.sha2);
				break;

			case FPN_CRYPTO(AUTH_SHA512):
				sha512_final(auth_digest, (uint8_t *)&auth_ctxt.sha2);
				break;

			case FPN_CRYPTO(AUTH_HMACMD5):
				ctx_o.md5 = session->ctx_o.md5;
				HMAC_Final(auth_digest, (uint8_t *)&auth_ctxt.md5,
						   (uint8_t *)&ctx_o.md5, MD5_DIGEST_LENGTH,
						   md5_update, md5_final);
				break;

			case FPN_CRYPTO(AUTH_HMACSHA1):
				ctx_o.sha1 = session->ctx_o.sha1;
				HMAC_Final(auth_digest, (uint8_t *)&auth_ctxt.sha1,
						   (uint8_t *)&ctx_o.sha1, SHA1_DIGEST_LENGTH,
						   sha1_update, sha1_final);
				break;

			case FPN_CRYPTO(AUTH_HMACSHA256):
				ctx_o.sha2 = session->ctx_o.sha2;
				HMAC_Final(auth_digest, (uint8_t *)&auth_ctxt.sha2,
						   (uint8_t *)&ctx_o.sha2, SHA256_DIGEST_LENGTH,
						   sha256_update, sha256_final);
				break;

			case FPN_CRYPTO(AUTH_HMACSHA384):
				ctx_o.sha2 = session->ctx_o.sha2;
				HMAC_Final(auth_digest, (uint8_t *)&auth_ctxt.sha2,
						   (uint8_t *)&ctx_o.sha2, SHA384_DIGEST_LENGTH,
						   sha384_update, sha384_final);
				break;

			case FPN_CRYPTO(AUTH_HMACSHA512):
				ctx_o.sha2 = session->ctx_o.sha2;
				HMAC_Final(auth_digest, (uint8_t *)&auth_ctxt.sha2,
						   (uint8_t *)&ctx_o.sha2, SHA512_DIGEST_LENGTH,
						   sha512_update, sha512_final);
				break;

			case FPN_CRYPTO(AUTH_AES_XCBC):
				ctx_o.xcbc = session->ctx_o.xcbc;
				fpn_xcbc_final(&auth_ctxt.xcbc, &ctx_o.xcbc, auth_digest);
				break;

			case FPN_CRYPTO(AUTH_AES_GCM):
			case FPN_CRYPTO(AUTH_AES_GMAC):
				/* Do last mult operation */
				fpn_gcm_final(&auth_ctxt.gcm, auth_digest);
				break;
		}
	}

	/* Compare or store auth tag if needed */
	if (session->digest_len > 0) {
		if ((session->flags & FPN_CRYPTO(F_AUTH_CHECK)) &&
			!(session->flags & FPN_CRYPTO(F_ENCRYPT))) {
			if (memcmp(operation->auth_dst, auth_digest, session->digest_len)) {
				buffer->status = FPN_CRYPTO(FAILURE);
			}
		} else {
			fpn_memcpy(operation->auth_dst, auth_digest, session->digest_len);
		}
	}

	/* In async move end of processing to poll function */
	if (likely(operation->cb != NULL)) {
		/* Queue buffer */
		if (fpn_ring_enqueue(&core_conf->ring, buffer) < 0) {
			/* Force polling of queue */
			fpn_crypto_generic_poll(1);

			/* Free buffer */
			fpn_mempool_put(generic_buffer_pool, buffer);

			/* Return error */
			return FPN_CRYPTO(BUSY);
		}

		/* All is ok */
		ret = FPN_CRYPTO(SUCCESS);

		/* One more operation pending on this session */
		fpn_atomic_inc(&session->pending);

		/* One more operation pending on this core */
		core_conf->pending++;
	} else {
		/* Set return value to tag verification */
		ret = buffer->status;

		/* One more buffer processed */
		core_conf->statistics.nb_crypto++;

		/* Free buffer */
		fpn_mempool_put(generic_buffer_pool, buffer);
	}

	return ret;
}

/**
 * This function will fill a structure with statistics values of the library
 */
int fpn_crypto_generic_statistics(
    uint32_t lcore_id,                     /* Id of core                         */
    fpn_crypto_statistics_t * statistics   /* Statistics structure to fill       */
)
{
	/* Return error if no pointer passed */
	if (statistics == NULL)
		return (FPN_CRYPTO(FAILURE));

	/* Initialize stats structure */
	memset(statistics, 0, sizeof(fpn_crypto_statistics_t));

	if (lcore_id == FPN_CRYPTO(ALL_CORES)) {
		/* Cumulate stats */
		for (lcore_id=0 ; lcore_id<FPN_MAX_CORES ; lcore_id++) {
			if (generic_statistic[lcore_id] == NULL) continue;

			statistics->nb_crypto     += generic_statistic[lcore_id]->nb_crypto;
			statistics->out_of_space  += generic_statistic[lcore_id]->out_of_space;
			statistics->out_of_buffer += generic_statistic[lcore_id]->out_of_buffer;
			statistics->internal_error+= generic_statistic[lcore_id]->internal_error;
			statistics->nb_poll       += generic_statistic[lcore_id]->nb_poll;
			statistics->dummy_poll    += generic_statistic[lcore_id]->dummy_poll;
			statistics->timeout_flush += generic_statistic[lcore_id]->timeout_flush;
			statistics->bulk_flush    += generic_statistic[lcore_id]->bulk_flush;
		}

		/* Set global statistics */
		statistics->nb_session     = fpn_atomic_read(&generic_nb_session);
		statistics->out_of_session = fpn_atomic_read(&generic_out_of_session);
	} else {
		if (generic_statistic[lcore_id] != NULL) {
			*statistics = *generic_statistic[lcore_id];
		}
	}

	return(FPN_CRYPTO(SUCCESS));
}

/**
 * Initialize generic crypto
 */
int fpn_crypto_generic_init(
    uint32_t                        pool_size,   /* Buffers in pool          */
    uint32_t                        pool_cache,  /* Buffers in pool cache    */
    uint32_t                        nb_context   /* Number of SAs            */
)
{
	char pool_name[FPN_MEMPOOL_NAMESIZE];

	/* Set sessions pool name */
	snprintf(pool_name, FPN_MEMPOOL_NAMESIZE, "generic_crypto_session_pool");

	/* Get pool */
	generic_session_pool = fpn_mempool_lookup(pool_name);

	/* Allocate pool of sessions */
	if (generic_session_pool == NULL) {
		generic_session_pool = fpn_mempool_create(pool_name, nb_context,
		                                          sizeof(fpn_crypto_generic_session_t),
		                                          16, 0, NULL, NULL, NULL, NULL, 0);
		if (generic_session_pool == NULL) {
			fpn_printf("%s: Failed to allocate memory for session "
			           "pool\n", __func__);
			return FPN_CRYPTO(FAILURE);
		}
	}

	/* Set buffers pool name */
	snprintf(pool_name, FPN_MEMPOOL_NAMESIZE, "generic_crypto_buffer_pool");

	/* Get pool */
	generic_buffer_pool = fpn_mempool_lookup(pool_name);

	/* Limit pool cache to what fpn can do */
	if (pool_cache > FPN_MEMPOOL_CACHE_MAX_SIZE) {
		pool_cache = FPN_MEMPOOL_CACHE_MAX_SIZE;
	}

	/* Allocate pool of buffers */
	if (generic_buffer_pool == NULL) {
		generic_buffer_pool = fpn_mempool_create(pool_name, pool_size,
		                                         sizeof(fpn_crypto_generic_buffer_t),
		                                         pool_cache, 0, NULL, NULL, NULL, NULL, 0);
		if (generic_buffer_pool == NULL) {
			fpn_printf("%s: Failed to allocate memory for buffer "
			           "pool\n", __func__);
			return FPN_CRYPTO(FAILURE);
		}
	}

	return FPN_CRYPTO(SUCCESS);
}

/**
 * Exit from generic crypto
 */
int fpn_crypto_generic_exit(void) {
	/* Can not free mempools */
	return FPN_CRYPTO(SUCCESS);
}

/**
 * Per core initialization
 */
int fpn_crypto_generic_core_init(
    uint32_t                        rx_bulk,     /* Maximum frames received  */
    __fpn_maybe_unused uint32_t     tx_bulk,     /* Maximum frames to flush  */
    uint32_t                      * nb_inst      /* Number of instances      */
)
{
	fpn_crypto_generic_core_conf_t * core_conf;
	int core_num;

	/* Get core Id */
	core_num = fpn_get_core_num();

	/* Allocate memory for core configuration */
	core_conf = fpn_malloc(sizeof(fpn_crypto_generic_core_conf_t),
	                       FPN_CACHELINE_SIZE);
	if (core_conf == NULL) {
		fpn_printf("%s: Failed to allocate memory for core configuration\n",
		           __func__);
		return FPN_CRYPTO(FAILURE);
	}

	/* Set core conf */
	FPN_PER_CORE_VAR(core_conf) = core_conf;

	/* Store statistics location */
	generic_statistic[core_num] = &core_conf->statistics;

	/* Setup memory */
	memset(core_conf, 0, sizeof(fpn_crypto_generic_core_conf_t));
	core_conf->rx_bulk = rx_bulk;

	/* Initialize per core ring */
	fpn_ring_init(&core_conf->ring, "crypto_ring", FPN_CRYPTO_MAX_RING,
	              FPN_RING_F_SP_ENQ | FPN_RING_F_SC_DEQ);

	/* Set number of instances found */
	if (nb_inst != NULL) {
		* nb_inst = 1;
	}

	return FPN_CRYPTO(SUCCESS);
}

/**
 * Free per core ressources
 */
int fpn_crypto_generic_core_exit(void) {
	/* Free memory */
	fpn_free(FPN_PER_CORE_VAR(core_conf));
	FPN_PER_CORE_VAR(core_conf) = NULL;

	return FPN_CRYPTO(SUCCESS);
}

/**
 * Poll queue of crypto done
 */
int fpn_crypto_generic_poll(__fpn_maybe_unused uint32_t flush)
{
	fpn_crypto_generic_core_conf_t * core_conf;
	fpn_crypto_generic_session_t   * session;
	fpn_crypto_generic_buffer_t    * buffer;
	int                              nb_done = 0;

	/* Get core configuration */
	core_conf = FPN_PER_CORE_VAR(core_conf);

	/* Poll only if needed */
	if (core_conf->pending) {

		/* One more poll processed */
		core_conf->statistics.nb_poll++;

		/* Get all queued buffers */
		nb_done = 0;
		while ((!fpn_ring_empty(&core_conf->ring)) &&
		       (nb_done < core_conf->rx_bulk)) {
			struct sym_s * sym;

			/* Unqueue first buffer */
			fpn_ring_dequeue(&core_conf->ring, (void **) &buffer);

			/* Get symmetric info field */
			sym = &buffer->priv.sym;

			/* Store session used to send buffer */
			session = sym->session;

			/* One less operation pending on this session */
			fpn_atomic_dec(&session->pending);

			/* Close session if needed */
			if (unlikely(session->flags & FPN_CRYPTO_F_CLOSE)) {
				/* Free associated buffers */
				if (buffer->flags & FPN_CRYPTO(F_MBUF)) {
					m_freem(buffer->src);
					if (buffer->dst != buffer->src) {
						m_freem(buffer->dst);
					}
				}

				/* Free session if asked for
				 * test-and-set to ensure that 'pending' will not be seen null
				 * at the same time on the core that tries to free the session.
				 */
				if (fpn_atomic_test_and_set(&session->pending)) {
					fpn_crypto_generic_session_exit(session);
				}
			} else {
				/* Call callback */
				buffer->callback(buffer->param, buffer->dst, buffer->status);
			}

			/* One less request pending in reception */
			core_conf->pending--;

			/* One more buffer processed */
			core_conf->statistics.nb_crypto++;

			/* Return buffer to pool it comes from */
			fpn_mempool_put(generic_buffer_pool, buffer);

			/* One less to receive in a raw */
			nb_done++;
		}
	}

	return nb_done;
}
