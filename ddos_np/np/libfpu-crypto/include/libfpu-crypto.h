/*
 * Copyright 2013 6WIND S.A.
 */

/**
 * @file libfpu-crypto.h
 * @brief FPU crypto API.
 * This file implements an API to use crypto accelerators through fast path.
*/

#ifndef FPU_CRYPTO_H
#define FPU_CRYPTO_H

/* @cond */
#if __GNUC__ >= 4
    #define DSO_PUBLIC __attribute__ ((visibility ("default")))
    #define DSO_LOCAL  __attribute__ ((visibility ("hidden")))
#else
    #error Unsupported GCC version
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
/* @endcond */

/* Version string */
#define FPU_CRYPTO_VERSION      "1.0"

/* Error codes */
#define FPU_CRYPTO_SUCCESS      0      /**< No error                         */
#define FPU_CRYPTO_FAILURE      -1     /**< An error occured                 */

/* Flags */
#define FPU_CRYPTO_F_ENCRYPT    0x0001 /**< Set to encrypt, else decrypt     */
#define FPU_CRYPTO_F_WRITE_IV   0x0002 /**< Write IV in dstbuf on encrypt    */
#define FPU_CRYPTO_F_GEN_IV     0x0004 /**< Generate IV                      */
#define FPU_CRYPTO_F_PARTIAL    0x0010 /**< Partial buffer, don't finalize   */

/* Asymmetric crypto parameters */
#define FPU_CRYPTO_KMAXPARAM    16     /**< Maximum number of async params   */

/* Core statistics parameter */
#define FPU_CRYPTO_ALL_CORES    (uint32_t)-1 /**< Cumulative stats           */

/**
 * Hash algorithms supported
 */
typedef enum
{
	FPU_CRYPTO_AUTH_NULL = 0,          /**< No hash                          */
	FPU_CRYPTO_AUTH_MD5,               /**< 128 bits MD5                     */
	FPU_CRYPTO_AUTH_SHA1,              /**< 160 bits SHA1                    */
	FPU_CRYPTO_AUTH_SHA224,            /**< 224 bits SHA2 224                */
	FPU_CRYPTO_AUTH_SHA256,            /**< 256 bits SHA2 256                */
	FPU_CRYPTO_AUTH_SHA384,            /**< 384 bits SHA2 384                */
	FPU_CRYPTO_AUTH_SHA512,            /**< 512 bits SHA2 512                */
	FPU_CRYPTO_AUTH_HMACMD5,           /**< 128 bits HMAC MD5                */
	FPU_CRYPTO_AUTH_HMACSHA1,          /**< 160 bits HMAC SHA1               */
	FPU_CRYPTO_AUTH_HMACSHA224,        /**< 224 bits HMAC SHA2 224           */
	FPU_CRYPTO_AUTH_HMACSHA256,        /**< 256 bits HMAC SHA2 256           */
	FPU_CRYPTO_AUTH_HMACSHA384,        /**< 384 bits HMAC SHA2 384           */
	FPU_CRYPTO_AUTH_HMACSHA512,        /**< 512 bits HMAC SHA2 512           */
	FPU_CRYPTO_AUTH_AES128_XCBC,       /**< 128 bits XCBC                    */
	FPU_CRYPTO_AUTH_AES256_XCBC,       /**< 256 bits XCBC                    */
	FPU_CRYPTO_AUTH_AES512_XCBC,       /**< 512 bits XCBC                    */

	FPU_CRYPTO_AUTH_NUM
} fpu_hash_algo_t;

/**
 * Symmetric Crypto algorithms supported
 */
typedef enum {
	FPU_CRYPTO_ALGO_NULL = 0,          /**< No crypto                        */
	FPU_CRYPTO_ALGO_DES_CBC,           /**< DES block crypto                 */
	FPU_CRYPTO_ALGO_3DES_CBC,          /**< Triple DES block crypto          */
	FPU_CRYPTO_ALGO_AES_CBC,           /**< AES block crypto                 */
	FPU_CRYPTO_ALGO_AES_CFB1,          /**< AES CFB 1 crypto                 */
	FPU_CRYPTO_ALGO_AES_CFB8,          /**< AES CFB 8 crypto                 */
	FPU_CRYPTO_ALGO_AES_CFB128,        /**< AES CFB 128 crypto               */
	FPU_CRYPTO_ALGO_AES_CTR,           /**< Counter AES crypto               */
	FPU_CRYPTO_ALGO_AES_GCM,           /**< AES GCM crypto                   */
	FPU_CRYPTO_ALGO_DES_ECB,           /**< DES ECB crypto                   */
	FPU_CRYPTO_ALGO_3DES_ECB,          /**< Triple DES ECB crypto            */
	FPU_CRYPTO_ALGO_AES_ECB,           /**< AES ECB crypto                   */
	FPU_CRYPTO_ALGO_RC4,               /**< RC4 crypto                       */

	FPU_CRYPTO_ALGO_NUM
} fpu_crypto_algo_t;

/**
 * Asymmetric Crypto operations supported
 */
typedef enum {
	FPU_CRYPTO_KOPER_MOD_EXP = 0,      /**< Modular exponentiation           */
	FPU_CRYPTO_KOPER_MOD_INV,          /**< Modular invertion                */
	FPU_CRYPTO_KOPER_ECC_POINT_ADD,    /**< Elliptic Curve add               */
	FPU_CRYPTO_KOPER_ECC_POINT_DOUBLE, /**< Elliptic Curve double            */
	FPU_CRYPTO_KOPER_ECC_POINT_MUL,    /**< Elliptic Curve mult              */
	FPU_CRYPTO_KOPER_DH_GEN_KEY,       /**< Diffie Hellman gen key           */
	FPU_CRYPTO_KOPER_RSA_ENCRYPT,      /**< RSA encrypt                      */
	FPU_CRYPTO_KOPER_RSA_DECRYPT,      /**< RSA decrypt                      */
	FPU_CRYPTO_KOPER_RSA_GEN_KEY,      /**< RSA gen key                      */
	FPU_CRYPTO_KOPER_DSA_GEN_PARAM,    /**< DSA gen param                    */
	FPU_CRYPTO_KOPER_DSA_SIGN,         /**< DSA sign                         */
	FPU_CRYPTO_KOPER_DSA_VERIFY,       /**< DSA verify                       */
	FPU_CRYPTO_KOPER_ECDSA_SIGN,       /**< Elliptic Curve DSA sign          */
	FPU_CRYPTO_KOPER_ECDSA_VERIFY,     /**< Elliptic Curve DSA verify        */
	FPU_CRYPTO_KOPER_PRIME_TEST,       /**< Prime number test                */

	FPU_CRYPTO_KALGO_NUM
} fpu_crypto_koper_t;

/**
 * Flags associated with asymmetric crypto operations
 */
#define DH_PHASE1_KEY           0      /**< DH phase 1 key                   */
#define DH_PHASE2_KEY           1      /**< DH phase 2 key                   */
#define RSA_KEY_TYPE1           0      /**< RSA key type 1 (n,d)             */
#define RSA_KEY_TYPE2           1      /**< RSA key type 2 (p,q,dP,dQ,qInv)  */
#define DSA_PARAM_P             0      /**< DSA parameter P                  */
#define DSA_PARAM_G             1      /**< DSA parameter G                  */
#define DSA_PARAM_Y             2      /**< DSA parameter Y                  */
#define DSA_SIGN_R              1      /**< DSA sign R                       */
#define DSA_SIGN_S              2      /**< DSA sign S                       */
#define EC_TYPE_PRIME           0      /**< EC type prime                    */
#define EC_TYPE_BIN             1      /**< EC type binary                   */
#define PRIME_TEST_GCD          0x1    /**< GCD prime test                   */
#define PRIME_TEST_FERMAT       0x2    /**< Fermat prime test                */
#define PRIME_TEST_LUCAS        0x4    /**< Lucas prime test                 */
#define PRIME_TEST_MILLER       0x8    /**< Miller prime test                */


/**
 * Big numbers representation, in packed bytes, significant byte first
 */
typedef struct fpu_crparam_s {
	char          * ptr;               /**< Big num representation           */
	uint32_t        nbits;             /**< Big num size                     */
} fpu_crparam_t;

/**
 * Statistics structure
 */
typedef struct fpu_crypto_statistics_s {
	uint64_t        nb_session;        /**< Number of sessions created       */
	uint64_t        nb_crypto;         /**< Number of buffers processed      */
	uint64_t        nb_kop;            /**< Number of asymmetric operations  */
	uint64_t        nb_rand;           /**< Number of random operations      */
	uint64_t        out_of_space;      /**< Number of queue overflows        */
	uint64_t        out_of_buffer;     /**< Number of buffer shortages       */
	uint64_t        out_of_session;    /**< Number of session shortages      */
	uint64_t        internal_error;    /**< Number of internal errors        */
	uint64_t        nb_poll;           /**< Number of polling done           */
	uint64_t        dummy_poll;        /**< Number of dummy polls            */
	uint64_t        timeout_flush;     /**< Number of timeout flush          */
	uint64_t        bulk_flush;        /**< Number of bulk flush             */
} fpu_crypto_statistics_t;

/**
 * Session initialization for symmetric crypto
*
 * flags can contain following bits set:
 *
 * @ref FPU_CRYPTO_F_ENCRYPT
 */
typedef struct fpu_crypto_init_s {
	/* parameters for encryption */
	uint16_t        enc_alg;           /**< Algorithm to use                 */
	uint16_t        enc_klen;          /**< Key length, in bits              */
	char          * enc_key;           /**< Key to use                       */

	/* parameters for auth */
	uint16_t        auth_alg;          /**< Algorithm to use                 */
	uint16_t        auth_klen;         /**< Key length, in bits              */
	uint16_t        auth_dlen;         /**< Digest length, in bits           */
	char          * auth_key;          /**< Key to use                       */

	/* Session flags */
	uint16_t        flags;             /**< Session flags                    */
} fpu_crypto_init_t;

/**
 * Buffer descriptor
 */
typedef struct fpu_vec_s {
	void          * base;              /**< Base address.                    */
	size_t          len;               /**< Length.                          */
} fpu_vec_t;

/**
 * Buffer chain descriptor
 */
typedef struct fpu_buf_s {
	fpu_vec_t     * vec;               /**< pointer to array of vecs         */
	uint16_t        veccnt;            /**< number of vecs in array          */
} fpu_buf_t;

/**
 * Descriptor for symmetric crypto operation
 *
 * flags can contain following bits set:
 *
 * @ref FPU_CRYPTO_F_WRITE_IV
 * @ref FPU_CRYPTO_F_GEN_IV
 * @ref FPU_CRYPTO_F_PARTIAL
 */
typedef struct fpu_crypto_op_s {
	/* Global parameters */
	uint64_t        session;           /**< Session id                       */
	fpu_buf_t     * src;               /**< Data to be processed             */

	/* Crypto params (ignored if enc_alg set to NULL in session) */
	fpu_buf_t     * enc_dst;           /**< Output data                      */
	char          * enc_iv;            /**< IV to use, will be filled if
	                                        FPU_CRYPTO_F_GEN_IV flag is set  */
	uint32_t        enc_len;           /**< Size of data to encrypt          */
	uint16_t        enc_skip;          /**< Bytes to ignore from beginning   */
	uint16_t        enc_inject;        /**< How many bytes to skip from dst
	                                        (ignored if src == enc_dst)      */
	/* Authentication params (ignored if auth_alg set to NULL in session) */
	char          * auth_dst;          /**< Output auth if any               */
	uint32_t        auth_len;          /**< How many bytes to process        */
	uint16_t        auth_skip;         /**< Bytes to ignore from start       */

	/* Various lengthes */
	uint16_t        iv_len;            /**< Length of initialization vector  */

	/* Operation flags */
	uint16_t        flags;             /**< Operation flags                  */
} fpu_crypto_op_t;

/**
 * Descriptor for asymmetric crypto operation
 *
 * Description of param array according to op field:
 *
 * - op = @ref FPU_CRYPTO_KOPER_MOD_EXP : res = (arg ^ exp) MOD mod
 * @param[in]  param[0] = arg
 * @param[in]  param[1] = exp
 * @param[in]  param[2] = mod
 * @param[out] param[3] = res
 *
 * - op = @ref FPU_CRYPTO_KOPER_MOD_INV : res = (arg ^ -1) MOD mod
 * @param[in]  param[0] = arg
 * @param[in]  param[1] = mod
 * @param[out] param[2] = res
 *
 * - op = @ref FPU_CRYPTO_KOPER_ECC_POINT_ADD : P3 = P1 + P2
 * @param[in]  param[0] = P1x
 * @param[in]  param[1] = P1y
 * @param[in]  param[2] = P2x
 * @param[in]  param[3] = P2y
 * @param[out] param[4] = P3x
 * @param[out] param[5] = P3y
 *
 * - op = @ref FPU_CRYPTO_KOPER_ECC_POINT_DOUBLE : P2 = P1 + P1
 * @param[in]  param[0] = P1x
 * @param[in]  param[1] = P1y
 * @param[out] param[2] = P2x
 * @param[out] param[3] = P2y
 *
 * - op = @ref FPU_CRYPTO_KOPER_ECC_POINT_MUL : P3 = P1 x P2
 * @param[in]  param[0] = P1x
 * @param[in]  param[1] = P1y
 * @param[in]  param[2] = P2x
 * @param[in]  param[3] = P2y
 * @param[out] param[4] = P3x
 * @param[out] param[5] = P3y
 *
 * - op = @ref FPU_CRYPTO_KOPER_DH_GEN_KEY
 *  + flag = @ref DH_PHASE1_KEY : Phase 1 public key
 * @param[in]  param[0] = prime
 * @param[in]  param[1] = base
 * @param[in]  param[2] = priv
 * @param[out] param[3] = pub
 *  + flag = @ref DH_PHASE2_KEY : Phase 2 private key
 * @param[in]  param[0] = prime
 * @param[in]  param[1] = pub
 * @param[in]  param[2] = priv
 * @param[out] param[3] = secret
 *
 * - op = @ref FPU_CRYPTO_KOPER_RSA_ENCRYPT
 * @param[in]  param[0] = mod
 * @param[in]  param[1] = pub
 * @param[in]  param[2] = data
 * @param[out] param[3] = encrypt
 *
 * - op = @ref FPU_CRYPTO_KOPER_RSA_DECRYPT
 *  + flag = @ref RSA_KEY_TYPE1 : Type 1 private key
 * @param[in]  param[0] = data
 * @param[in]  param[1] = mod
 * @param[in]  param[2] = priv
 * @param[out] param[3] = decrypt
 *  + flag = @ref RSA_KEY_TYPE2 : Type 2 private key
 * @param[in]  param[0] = data
 * @param[in]  param[1] = p
 * @param[in]  param[2] = q
 * @param[in]  param[3] = dp
 * @param[in]  param[4] = dq
 * @param[in]  param[5] = qinv
 * @param[out] param[6] = decrypt
 *
 * - op = @ref FPU_CRYPTO_KOPER_RSA_GEN_KEY
 *  + flag = @ref RSA_KEY_TYPE1 : Type 1 private key
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = exp
 * @param[out] param[3] = mod
 * @param[out] param[4] = pub
 * @param[out] param[5] = priv
 *  + flag = @ref RSA_KEY_TYPE2 : Type 2 private key
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = exp
 * @param[out] param[3] = mod
 * @param[out] param[4] = pub
 * @param[out] param[5] = dp
 * @param[out] param[6] = dq
 * @param[out] param[7] = qinv
 *
 * - op = @ref FPU_CRYPTO_KOPER_DSA_GEN_PARAM
 *  + flag = @ref DSA_PARAM_P : P DSA parameter candidate generation
 * @param[in]  param[0] = x
 * @param[in]  param[1] = q
 * @param[out] param[2] = res
 *  + flag = @ref DSA_PARAM_G : G DSA parameter candidate generation
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = h
 * @param[out] param[3] = res
 *  + flag = @ref DSA_PARAM_Y : Y DSA parameter candidate generation
 * @param[in]  param[0] = p
 * @param[in]  param[1] = g
 * @param[in]  param[2] = priv
 * @param[out] param[3] = res
 *
 * - op = @ref FPU_CRYPTO_KOPER_DSA_SIGN
 *  + flag = @ref DSA_SIGN_R : Generate DSA R signature
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = g
 * @param[in]  param[3] = secret
 * @param[out] param[4] = R
 *  + flag = @ref DSA_SIGN_S : Generate DSA S signature
 * @param[in]  param[0] = q
 * @param[in]  param[1] = priv
 * @param[in]  param[2] = secret
 * @param[in]  param[4] = R
 * @param[in]  param[5] = z
 * @param[out] param[6] = S
 *  + flag = @ref DSA_SIGN_R | @ref DSA_SIGN_S : Generate both DSA signatures
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = g
 * @param[in]  param[3] = priv
 * @param[in]  param[4] = secret
 * @param[in]  param[5] = z
 * @param[out] param[6] = R
 * @param[out] param[7] = S
 *
 * - op = @ref FPU_CRYPTO_KOPER_DSA_VERIFY
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = g
 * @param[in]  param[3] = pub
 * @param[in]  param[4] = z
 * @param[in]  param[5] = R
 * @param[in]  param[6] = S
 *
 * - op = @ref FPU_CRYPTO_KOPER_ECDSA_SIGN
 *  + flag = @ref DSA_SIGN_R : Generate DSA R signature
 * @param[in]  param[0] = x
 * @param[in]  param[1] = y
 * @param[in]  param[2] = n
 * @param[in]  param[3] = q
 * @param[in]  param[4] = a
 * @param[in]  param[5] = b
 * @param[in]  param[6] = k
 * @param[out] param[7] = R
 *  + flag = @ref DSA_SIGN_S : Generate DSA S signature
 * @param[in]  param[0] = m
 * @param[in]  param[1] = d
 * @param[in]  param[2] = R
 * @param[in]  param[4] = k
 * @param[in]  param[5] = n
 * @param[out] param[6] = S
 *  + flag = @ref DSA_SIGN_R | @ref DSA_SIGN_S : Generate both DSA signatures
 * @param[in]  param[0] = x
 * @param[in]  param[1] = y
 * @param[in]  param[2] = n
 * @param[in]  param[3] = q
 * @param[in]  param[4] = a
 * @param[in]  param[5] = b
 * @param[in]  param[6] = k
 * @param[in]  param[7] = m
 * @param[in]  param[8] = d
 * @param[out] param[9] = R
 * @param[out] param[10] = S
 *
 * - op = @ref FPU_CRYPTO_KOPER_ECDSA_VERIFY
 * @param[in]  param[0] = x
 * @param[in]  param[1] = y
 * @param[in]  param[2] = n
 * @param[in]  param[3] = q
 * @param[in]  param[4] = a
 * @param[in]  param[5] = b
 * @param[in]  param[6] = m
 * @param[in]  param[7] = r
 * @param[in]  param[8] = R
 * @param[in]  param[9] = S
 * @param[in]  param[10] = xp
 * @param[in]  param[11] = yp
 *
 * - op = @ref FPU_CRYPTO_KOPER_PRIME_TEST
 * @param[in]  param[0] = prime
 */
typedef struct fpu_crypto_kop_s {
	/* Global parameters */
	fpu_crypto_koper_t op;             /**< Asymmetric crypto operation      */
	fpu_crparam_t param[FPU_CRYPTO_KMAXPARAM]; /**< Array of parameters      */
	uint16_t        iparams;           /**< Number of input parameters       */
	uint16_t        oparams;           /**< Number of output parameters      */
	uint16_t        flags;             /**< Operation flags                  */
} fpu_crypto_kop_t;

/**
 * Descriptor for DRBG operation
 */
typedef struct fpu_drbg_op_s {
	uint64_t        session;           /**< Session id                         */
	char          * buf;               /**< Data buffer                        */
	int             len;               /**< Data length                        */
} fpu_rbg_op_t;


/**
 * Initialize a session
 *
 * This function is used to initialize a cryptographic session
 *
 * @param[in] init
 *   initialization structure
 *
 * @return
 *   Return session Id or 0 on error.
 */
DSO_PUBLIC uint64_t fpu_crypto_session_new(fpu_crypto_init_t * init);

/**
 * Duplicate a session
 *
 * This function is used to duplicate a cryptographic session,
 * including keys and internal partial hash status
 *
 * @param[in] session
 *   session to duplicate
 *
 * @return
 *   Return session Id or 0 on error.
 */
DSO_PUBLIC uint64_t fpu_crypto_session_dup(uint64_t session);

/**
 * Close a session
 *
 * This function is used to free any memory allocated for a session
 *
 * @param[in] session
 *   Handle of session to close
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_crypto_session_free(uint64_t session);

/**
 * Start a symmetric crypto operation
 *
 * This function starts a crypto operation with the parameters
 * specified in the "operation" structure. The function returns 0 on
 * success, a negative value on error (-errno).
 *
 * In case of a block cipher, the data len must be a multiple of block
 * size. 'enc_iv' and 'auth_dst' must always point to contiguous data.
 * if enc_inject is not null, all injected data must be in the first
 * buffer.
 *
 * @param[in] operation
 *   Description of the operation to process
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_crypto_invoke(fpu_crypto_op_t * operation);

/**
 * Start an asymmetric crypto operation
 *
 * This function starts an asymmetric crypto operation with the
 * parameters specified in the "operation" structure. The function
 * returns 0 on success, a negative value on error (-errno).
 *
 * @param[in] operation
 *   Description of the operation to process
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_crypto_kinvoke(fpu_crypto_kop_t * operation);

/**
 * Recover statistics
 *
 * This function recover statistics
 *
 * @param[in] device
 *   Name of device to get statistics from. If NULL, statistics
 *   are cumulated on all supported devices
 * @param[in] core_id
 *   Index of core to get statistics from. If core_id is
 *   FPU_CRYPTO_ALL_CORES, statistics are cumulated on all
 *   running cores
 * @param[out] statistics
 *   Structure that will contain the statistics on return
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int fpu_crypto_statistics(char const * device, uint32_t core_id,
                                     fpu_crypto_statistics_t * statistics);

/**
 * Instantiate a DRBG session
 *
 * This function instantiates a new DRBG session.
 *
 * @return
 *   Return session Id or 0 on error.
 */
DSO_PUBLIC uint64_t fpu_drbg_session_new(void);

/**
 * Free a DRBG session
 *
 * This function frees a previously allocated DRBG session.
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_drbg_session_free(uint64_t session);

/**
 * Seed DRB generator
 *
 * This function is used to (re)seed the generator.
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_drbg_seed(fpu_rbg_op_t * op);

/**
 * Generate Pseudo random bytes
 *
 * This function is used to get pseudo random bytes from generator
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_drbg_generate(fpu_rbg_op_t * op);

/**
 * Generate random bytes
 *
 * This function is used to get random bytes
 *
 * @return
 *   FPU_CRYPTO_SUCCESS or FPU_CRYPTO_FAILURE
 */
DSO_PUBLIC int32_t fpu_nrbg_generate(fpu_rbg_op_t * op);


#endif /* FPU_CRYPTO_H */
