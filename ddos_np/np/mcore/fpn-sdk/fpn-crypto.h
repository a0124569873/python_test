/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _FPN_CRYPTO_H_
#define _FPN_CRYPTO_H_

#include "fpn.h"
#include "fpn-mbuf.h"
#include "fpn-crypto-algo.h"

/* These values should not be changed */
#define FPN_DECRYPT 0
#define FPN_ENCRYPT 1

/*
 * fpn synchronous crypto API
 *
 * Encrypt/Decrypt 'len' bytes of a mbuf at offset 'off', using the
 * key 'K64'. The length of data must be a multiple of blocksize
 * (which depends on used algorithm). Key and IV length also depend on
 * algorithm (it is specified in case of AES).
 *
 * We pass IV as input only.
 *
 * On some architectures (octeon only at this time), the iv is not
 * usedfor *encrypt() functions. The random IV is taken directly from
 * the cryptoproc.
 *

 static inline void fpn_des_cbc_encrypt(struct mbuf *m,
	uint16_t off, uint16_t mlen,
	const uint64_t *iv,
	const uint64_t *K64)

 static inline void fpn_des_cbc_encrypt(struct mbuf *m,
	uint16_t off, uint16_t mlen,
	const uint64_t *iv,
	const uint64_t *K64)

 static inline void fpn_3des_cbc_encrypt(struct mbuf *m,
	uint16_t off, uint16_t mlen,
	const uint64_t *iv,
	const uint64_t *K64)

 static inline void fpn_3des_cbc_decrypt(struct mbuf *m,
	uint16_t off, uint16_t mlen,
	const uint64_t *iv,
	const uint64_t *K64)

 static inline void fpn_aes_cbc_encrypt(struct mbuf *m,
	uint16_t off,
	uint16_t mlen,
	const uint64_t *iv,
	const uint64_t *K64,
	u_int key_len)

 static inline void fpn_aes_cbc_decrypt(struct mbuf *m,
	uint16_t off,
	uint16_t mlen,
	const uint64_t *iv,
	const uint64_t *K64,
	u_int key_len)

 *
 * HMAC API
 *
 * Process the HMAC signature of 'len' bytes of a mbuf at offset
 * 'off', using the key 'key'. The result is stored in the memory
 * pointed by the first parameter. The len is 16 bytes for md5 and 20
 * bytes for sha1.
 *
 * On most architectures, it only uses the auth key and does
 * not use nor modify 'ipad' and 'opad' parameters.
 *
 * On some other archs (octeon only at this time), it uses ipad and
 * opad that can be preprocessed in advance because they only depend
 * on the key. The buffer must be set to 0 if not initialized. In this
 * case, the function will process it as following:
 *     ipad = hash(0x363636...3636 ^ key)
 *     opad = hash(0x5c5c5c...5c5c ^ key)
 *

 static inline void fpn_hmac_md5(char *md5, const char *key,
	 const struct mbuf *m, uint16_t off, uint16_t len,
	 char *ipad, char *opad)

 static inline void fpn_hmac_sha1(char *sha1, const char *key,
	 const struct mbuf *m, uint16_t off, uint16_t len,
	 char *ipad, char *opad)

 *
 * AES-XCBC API
 *
 * Process the AES-XCBC signature of 'len' bytes of a mbuf at offset
 * 'off', using the key 'key'. The result is stored in the memory
 * pointed by 'aes_xcbc' parameter. The len of the digest is 16 bytes.
 *

 static inline void fpn_aes_xcbc_mac(char *aes_xcbc, const char *key,
	 const struct mbuf *m, uint16_t off, uint16_t len)

 */

/*
 * fpn asynchronous crypto API
 */
int fpn_crypto_async_cipher_auth(int enc_algo,
                                 const uint64_t *key_enc,
                                 u_int key_len,
                                 int cipher_src_off, unsigned int datalen,
                                 int iv_off, 
                                 int iv_len,
                                 int auth_algo,
                                 const char *key_auth,
                                 int auth_key_len,
                                 int auth_src_off, char *auth,
                                 unsigned int auth_len, int cipher_direction,
                                 struct mbuf *m, void *callback, void *priv);

int fpn_crypto_priv_alloc(void **sa_priv,
                          uint8_t direction, 
                          const uint64_t *key_enc,
                          u_int key_len,
                          const char *key_auth,
                          int enc_algo,
                          int auth_algo,
                          int esn);

int fpn_crypto_priv_free(void *sa_priv);

/*
 * Some architecture need to pre-calculate data depending on
 * algorithm. The functions fpn_crypto_priv_alloc and
 * fpn_crypto_priv_free are available for that purpose.
 * The implementation is not mandatory.
 */

/*
 * A pointer to a private 64-bit integer is supplied where the function can
 * store any architecture-specific data that it associates with the new SA.
 * This can be the address of a dynamically allocated data structure, for
 * instance, or just a unique SA identifier supplied by the hardware.
 *
 * int fpn_crypto_priv_alloc(void **sa_priv,
 *                           uint8_t direction, 
 *                           const uint64_t *key_enc,
 *                           u_int key_len,
 *                           const char *key_auth,
 *                           int enc_algo,
 *                           int auth_algo)
 */

/*
 * Free any architecture-specific data previously allocated by the
 * fpn_crypto_priv_alloc function.
 * The parameter "sa_priv" contains the private session
 * that was previously stored by the function fpn_crypto_priv_alloc.
 *
 * int fpn_crypto_priv_free(void *sa_priv)
 */

/* Definitions used in the cipher and auth macros.
 *
 * cipher_algo   : cipher algorithm as defined in fpn-crypto-algo.h
 * cipher_key    : key used for ciphering
 * cipher_key_len: length of the cipher key
 * cipher_src_off: offset to start of data to cipher
 * cipher_len    : length of data to cipher
 * iv_off        : offset to IV
 * iv_len        : length of IV
 * auth_algo     : authentication algorith as defined in fpn-crypto-algo.h
 * auth_key      : key used for authentication
 * auth_key_len  : length of the authentication key
 * auth_src_off  : offset to start of data to authenticate
 * auth_dst      : where to write the result of authentication
 * auth_len      : length of data to authenticate
 *
 * used only for HAVE_NOTINPLACE_CIPHER
 * m_src_off     : offset where to start the notinplace ciphering in src mbuf
 * m_dst_off     : offset where to start the notinplace ciphering in dst mbuf
 * m_dst         : mbuf where we write the result of ciphering
 *
 * encrypt       : FPN_DECRYPT or FPN_ENCRYPT
 *
 * m             : mbuf containing the data
 * callback      : callback to call after the cipher is done, of type
 *                 fpn_crypto_callback_t
 * priv          : the value of the 64-bit private data in the SA structure
 *
 *
 * Cipher+auth macro.
 *
 *  FPN_ASYNC_CRYPTO_CIPHER_AUTH(cipher_algo,
 *                               cipher_key,
 *                               cipher_key_len,
 *                               cipher_src_off,
 *                               cipher_len,
 *                               iv_off,
 *                               iv_len,
 *                               auth_algo,
 *                               auth_key,
 *                               auth_key_len,
 *                               auth_src_off,
 *                               auth_dst,
 *                               auth_len,
 *                               m_src_off,
 *                               m_dst_off,
 *                               m_dst,
 *                               encrypt,
 *                               m,
 *                               callback,
 *                               priv)
 *
 *
 * Auth only macro.
 *
 * FPN_ASYNC_CRYPTO_AUTH(auth_algo,
 *                       auth_key,
 *                       auth_key_len,
 *                       auth_src_off,
 *                       auth_dst,
 *                       auth_len,
 *                       m_src_off,
 *                       m_dst_off,
 *                       m_dst,
 *                       encrypt,
 *                       m,
 *                       callback,
 *                       priv)
 *
 *
 * Cipher only macro.
 *
 * FPN_ASYNC_CRYPTO_CIPHER(cipher_algo,
 *                         cipher_key,
 *                         cipher_key_len,
 *                         cipher_src_off,
 *                         cipher_len,
 *                         iv_off,
 *                         iv_len,
 *                         m_src_off,
 *                         m_dst_off,
 *                         m_dst,
 *                         encrypt,
 *                         m,
 *                         callback,
 *                         priv)
 */

#define FPN_ESP_HEADER_LEN 8  /* SPI + seq number */

#if !defined(CONFIG_MCORE_FPE_VFP)

#ifdef CONFIG_MCORE_ARCH_OCTEON
#include "octeon/crypto/fpn-octeon-hmd5.h"
#include "octeon/crypto/fpn-octeon-hsha1.h"
#include "octeon/crypto/fpn-octeon-hsha2.h"
#include "octeon/crypto/fpn-octeon-des.h"
#include "octeon/crypto/fpn-octeon-aes.h"
#endif /* CONFIG_MCORE_ARCH_OCTEON */

#ifdef CONFIG_MCORE_ARCH_XLP
#include "xlp/crypto/fpn-xlp-crypto.h"
#endif

#ifdef CONFIG_MCORE_ARCH_DPDK
#include "dpdk/crypto/fpn-dpdk-crypto.h"
#endif

#ifdef CONFIG_MCORE_ARCH_TILEGX
#include "tilegx/crypto/fpn-crypto-tilegx.h"
#endif

/* Only implemented on DPDK and TileGx architectures for now */
#if defined(CONFIG_MCORE_ARCH_DPDK) || \
    defined(CONFIG_MCORE_ARCH_TILEGX)

/**
 * Macros used to cipher/authenticate packets
 */
#define FPN_ASYNC_CRYPTO_CIPHER_AUTH(cipher_algo,			\
				     cipher_key,			\
				     cipher_key_len,			\
				     cipher_src_off,			\
				     cipher_len,			\
				     iv_off,				\
				     iv_len,				\
				     auth_algo,				\
				     auth_key,				\
				     auth_key_len,			\
				     auth_src_off,			\
				     auth_dst,				\
				     auth_len,				\
				     m_src_off,				\
				     m_dst_off,				\
				     m_dst,				\
				     encrypt,				\
				     m,					\
				     callback,				\
				     priv)				\
	fpn_crypto_async_cipher_auth(cipher_algo,				\
				     cipher_key,				\
				     cipher_key_len,			\
				     cipher_src_off,			\
				     cipher_len,				\
				     iv_off,				\
				     iv_len,				\
				     auth_algo,				\
				     auth_key,				\
				     auth_key_len,			\
				     auth_src_off,			\
				     (char *)auth_dst,			\
				     auth_len,				\
				     encrypt,				\
				     m,					\
				     callback,				\
				    (void *) (priv))

#define FPN_ASYNC_CRYPTO_AUTH(auth_algo,				\
			      auth_key,					\
			      auth_key_len,				\
			      auth_src_off,				\
			      auth_dst,					\
			      auth_len,					\
			      m_src_off,				\
			      m_dst_off,				\
			      m_dst,					\
			      encrypt,					\
			      m,					\
			      callback,					\
			      priv)					\
	fpn_crypto_async_cipher_auth(FP_EALGO_NULL,				\
				     NULL,				\
				     0,					\
				     0,					\
				     0,					\
				     0,					\
				     0,					\
				     auth_algo,				\
				     auth_key,				\
				     auth_key_len,			\
				     auth_src_off,			\
				     (char *)auth_dst,			\
				     auth_len,				\
				     encrypt,				\
				     m,					\
				     callback,				\
				    (void *) (priv))

#define FPN_ASYNC_CRYPTO_CIPHER(cipher_algo,				\
				cipher_key,				\
				cipher_key_len,				\
				cipher_src_off,				\
				cipher_len,				\
				iv_off,					\
				iv_len,					\
				m_src_off,				\
				m_dst_off,				\
				m_dst,					\
				encrypt,				\
				m,					\
				callback,				\
				priv)					\
	fpn_crypto_async_cipher_auth(cipher_algo,				\
				     cipher_key,				\
				     cipher_key_len,			\
				     cipher_src_off,			\
				     cipher_len,				\
				     iv_off,				\
				     iv_len,				\
				     FP_AALGO_NULL,			\
				     NULL,				\
				     0,					\
				     0,					\
				     NULL,				\
				     0,					\
				     encrypt,				\
				     m,					\
				     callback,				\
				    (void *) (priv))

/* On RTE, structures are defined in rte_crypto.h */
#ifndef CONFIG_MCORE_FPN_RTE_CRYPTO

#define FPN_CRYPTO(s)           FPN_CRYPTO_##s

/* Error codes */
#define FPN_CRYPTO_SUCCESS      0      /**< No error                         */
#define FPN_CRYPTO_FAILURE      -1     /**< An error occured                 */
#define FPN_CRYPTO_BUSY         -2     /**< Transmission queue is full       */

/* Flags */
#define FPN_CRYPTO_F_ENCRYPT    0x0001 /**< Set to encrypt, else decrypt     */
#define FPN_CRYPTO_F_WRITE_IV   0x0002 /**< Write IV in dstbuf on encrypt    */
#define FPN_CRYPTO_F_GEN_IV     0x0004 /**< Generate IV                      */
#define FPN_CRYPTO_F_MBUF       0x0008 /**< Src/dst are mbufs, else uio      */
#define FPN_CRYPTO_F_PARTIAL    0x0010 /**< Partial buffer, don't finalize   */
#define FPN_CRYPTO_F_AUTH_CHECK 0x0020 /**< Only check auth                  */

/* SSL crypto parameters */
#define FPN_CRYPTO_KMAXPARAM    16     /**< Maximum number of async params   */

/* Core statistics parameter */
#define FPN_CRYPTO_ALL_CORES    (uint32_t)-1 /**< Cumulative stats           */

/**
 * Authentication algorithms supported
 */
typedef enum
{
	FPN_CRYPTO_AUTH_NULL = 0,          /**< No hash                          */
	FPN_CRYPTO_AUTH_MD5,               /**< 128 bits MD5                     */
	FPN_CRYPTO_AUTH_SHA1,              /**< 160 bits SHA1                    */
	FPN_CRYPTO_AUTH_SHA224,            /**< 224 bits SHA2 224                */
	FPN_CRYPTO_AUTH_SHA256,            /**< 256 bits SHA2 256                */
	FPN_CRYPTO_AUTH_SHA384,            /**< 384 bits SHA2 384                */
	FPN_CRYPTO_AUTH_SHA512,            /**< 512 bits SHA2 512                */
	FPN_CRYPTO_AUTH_HMACMD5,           /**< 128 bits HMAC MD5                */
	FPN_CRYPTO_AUTH_HMACSHA1,          /**< 160 bits HMAC SHA1               */
	FPN_CRYPTO_AUTH_HMACSHA224,        /**< 224 bits HMAC SHA2 224           */
	FPN_CRYPTO_AUTH_HMACSHA256,        /**< 256 bits HMAC SHA2 256           */
	FPN_CRYPTO_AUTH_HMACSHA384,        /**< 384 bits HMAC SHA2 384           */
	FPN_CRYPTO_AUTH_HMACSHA512,        /**< 512 bits HMAC SHA2 512           */
	FPN_CRYPTO_AUTH_AES_XCBC,          /**< AES XCBC                         */
	FPN_CRYPTO_AUTH_AES_GCM,           /**< AES GCM                          */
	FPN_CRYPTO_AUTH_AES_GMAC,          /**< AES GMAC                         */

	FPN_CRYPTO_AUTH_NUM
} fpn_hash_algo_t;

/**
 * Crypto algorithms supported
 */
typedef enum {
	FPN_CRYPTO_ALGO_NULL = 0,          /**< No crypto                        */
	FPN_CRYPTO_ALGO_DES_CBC,           /**< DES block crypto                 */
	FPN_CRYPTO_ALGO_3DES_CBC,          /**< Triple DES block crypto          */
	FPN_CRYPTO_ALGO_AES_CBC,           /**< AES block crypto                 */
	FPN_CRYPTO_ALGO_AES_CTR,           /**< Counter AES crypto               */
	FPN_CRYPTO_ALGO_AES_GCM,           /**< AES GCM crypto                   */
	FPN_CRYPTO_ALGO_DES_ECB,           /**< DES ECB crypto                   */
	FPN_CRYPTO_ALGO_3DES_ECB,          /**< Triple DES ECB crypto            */
	FPN_CRYPTO_ALGO_AES_ECB,           /**< AES ECB crypto                   */
	FPN_CRYPTO_ALGO_RC4,               /**< RC4 crypto                       */

	FPN_CRYPTO_ALGO_NUM
} fpn_crypto_algo_t;

/**
 * SSL Crypto operations supported
 */
typedef enum {
	FPN_CRYPTO_KOPER_MOD_EXP = 0,      /**< Modular exponentiation           */
	FPN_CRYPTO_KOPER_MOD_INV,          /**< Modular invertion                */
	FPN_CRYPTO_KOPER_ECC_POINT_ADD,    /**< Elliptic Curve add               */
	FPN_CRYPTO_KOPER_ECC_POINT_DOUBLE, /**< Elliptic Curve double            */
	FPN_CRYPTO_KOPER_ECC_POINT_MUL,    /**< Elliptic Curve mult              */
	FPN_CRYPTO_KOPER_DH_GEN_KEY,       /**< Diffie Hellman gen key           */
	FPN_CRYPTO_KOPER_RSA_ENCRYPT,      /**< RSA encrypt                      */
	FPN_CRYPTO_KOPER_RSA_DECRYPT,      /**< RSA decrypt                      */
	FPN_CRYPTO_KOPER_RSA_GEN_KEY,      /**< RSA gen key                      */
	FPN_CRYPTO_KOPER_DSA_GEN_PARAM,    /**< DSA gen param                    */
	FPN_CRYPTO_KOPER_DSA_SIGN,         /**< DSA sign                         */
	FPN_CRYPTO_KOPER_DSA_VERIFY,       /**< DSA verify                       */
	FPN_CRYPTO_KOPER_ECDSA_SIGN,       /**< Elliptic Curve DSA sign          */
	FPN_CRYPTO_KOPER_ECDSA_VERIFY,     /**< Elliptic Curve DSA verify        */
	FPN_CRYPTO_KOPER_PRIME_TEST,       /**< Prime number test                */

	FPN_CRYPTO_KALGO_NUM
} fpn_crypto_koper_t;

/**
 * Flags associated with asymmetric crypto operations
 */
#define FPN_DH_PHASE1_KEY                   0
#define FPN_DH_PHASE2_KEY                   1
#define FPN_RSA_KEY_TYPE1                   0
#define FPN_RSA_KEY_TYPE2                   1
#define FPN_DSA_PARAM_P                     0
#define FPN_DSA_PARAM_G                     1
#define FPN_DSA_PARAM_Y                     2
#define FPN_DSA_SIGN_R                      1
#define FPN_DSA_SIGN_S                      2
#define FPN_EC_TYPE_PRIME                   0
#define FPN_EC_TYPE_BIN                     1
#define FPN_PRIME_TEST_GCD                  0x01
#define FPN_PRIME_TEST_FERMAT               0x02
#define FPN_PRIME_TEST_LUCAS                0x04
#define FPN_PRIME_TEST_MILLER               0x08

/**
 * Big numbers representation, in packed bytes, significant byte first
 */
typedef struct fpn_crparam_s {
	char          * ptr;               /**< Big num representation           */
	uint32_t        nbits;             /**< Big num size                     */
} fpn_crparam_t;

/**
 * Statistics structure
 */
typedef struct fpn_crypto_statistics_s {
	uint64_t        nb_session;        /**< Number of sessions created       */
	uint64_t        nb_crypto;         /**< Number of buffers processed      */
	uint64_t        nb_kop;            /**< Number of assymetric operations  */
	uint64_t        nb_rand;           /**< Number of random operations      */
	uint64_t        out_of_space;      /**< Number of queue overflows        */
	uint64_t        out_of_buffer;     /**< Number of buffer shortages       */
	uint64_t        out_of_session;    /**< Number of session shortages      */
	uint64_t        internal_error;    /**< Number of internal errors        */
	uint64_t        nb_poll;           /**< Number of polling done           */
	uint64_t        dummy_poll;        /**< Number of dummy polls            */
	uint64_t        timeout_flush;     /**< Number of timeout flush          */
	uint64_t        bulk_flush;        /**< Number of bulk flush             */
} fpn_crypto_statistics_t;

/**
 * Crypto callback
 *
 * callback called on asynchronous operation completion
 *
 * @param opaque
 *   User defined parameter passed to the operation invoke function.
 * @param dest
 *   destination buffer depends on invoked operation:
 *      fpn_crypto_invoke : enc_dst value (or a valid copy of the fpn_vec_t
 *          pointed by enc_dst if fpn_buf_t are used).
 *      fpn_crypto_kinvoke : a valid copy of the parm array of the
 *          fpn_crypto_kop_t parameter structure.
 *      fpn_crypto_drbg_generate, fpn_crypto_drbg_seed,
 *          fpn_crypto_nrbg_generate : pointer to the output buffer.
 * @param res
 *   Operation result : FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
typedef void (*fpn_crypto_callback_t)(void *opaque, void *dest, int res);

/**
 * Session initialization for symmetric crypto
 *
 * flags can contain following bits set:
 *
 * @ref FPN_CRYPTO_F_ENCRYPT
 * @ref FPN_CRYPTO_F_AUTH_CHECK
 *
 * @warning fields have special meaning in GCM/GMAC modes.
 *
 *   - in GCM mode:
 *     - the field @ref enc_alg must be set to FPN_CRYPTO_ALGO_AES_GCM,
 *     - the field @ref auth_alg must be set to FPN_CRYPTO_AUTH_AES_GCM,
 *     - the field @ref auth_key is unused, the crypto key is located in
 *       the field @ref enc_key whose length is indicated in the field
 *       @ref enc_klen,
 *     - the field @ref auth_klen contains the length in bytes of the AAD
 *       prepended to cipher text for authentication, instead of the
 *       authentication key length.
 *     Other fields have normal meaning.
 *
 *   - in GMAC mode:
 *     - the field @ref enc_alg must be set to FPN_CRYPTO_ALGO_NULL,
 *     - the field @ref auth_alg must be set to FPN_CRYPTO_AUTH_AES_GMAC,
 *     - the key is located in the field @ref auth_key whose length is
 *       indicated in the field @ref auth_klen.
 *     Other fields have normal meaning.
 *
 *   - GCM/GMAC modes may not work on some implementations if
 *     FPN_CRYPTO_F_AUTH_CHECK is not set on decrypt direction.
 */
typedef struct fpn_crypto_init_s {
	/* parameters for encryption */
	uint16_t        enc_alg;           /**< Algorithm to use                   */
	uint16_t        enc_klen;          /**< Key length, in bits                */
	char const    * enc_key;           /**< Key to use                         */

	/* parameters for auth */
	uint16_t        auth_alg;          /**< Algorithm to use                   */
	uint16_t        auth_klen;         /**< Key length, in bits                */
	uint16_t        auth_dlen;         /**< Digest length, in bits             */
	char const    * auth_key;          /**< Key to use                         */

	/* Session flags */
	uint16_t        flags;             /**< Session flags                      */
} fpn_crypto_init_t;

/**
 * Buffer descriptor
 */
typedef struct fpn_vec_s {
	void          * base;              /**< Virtual Base address.              */
	uintptr_t       phys;              /**< Physical base address. Buffers
	                                        will be copied if phys addr is not
	                                        provided                           */
	size_t          len;               /**< Length.                            */
} fpn_vec_t;

/**
 * Buffer chain descriptor
 */
typedef struct fpn_buf_s {
	fpn_vec_t     * vec;               /**< pointer to array of vecs           */
	uint16_t        veccnt;            /**< number of vecs in array            */
} fpn_buf_t;

/**
 * Session Descriptor
 */
 typedef struct fpn_session_s {
	void          * dev;               /**< crypto module managing session     */
 } fpn_crypto_session_t;

/**
 * Descriptor for symmetric crypto operation
 *
 * flags can contain following bits set:
 *
 * @ref FPN_CRYPTO_F_WRITE_IV
 * @ref FPN_CRYPTO_F_GEN_IV
 * @ref FPN_CRYPTO_F_MBUF
 * @ref FPN_CRYPTO_F_PARTIAL
 *
 * @warning in GMAC mode, enc_iv must point to a valid 12 bytes IV location.
 *
 */
typedef struct fpn_crypto_op_s {
	/* Global parameters */
	void          * opaque;            /**< Opaque pointer, passed to callback */
	fpn_crypto_callback_t cb;          /**< Callback function, if set to null,
	                                        request is synchronous.            */
	fpn_crypto_session_t * session;    /**< Session id                         */
	void          * src;               /**< Data to be processed (uio or mbuf) */

	/* Crypto params (ignored if enc_alg set to NULL in session) */
	void          * enc_dst;           /**< Output data (uio or mbuf)          */
	char          * enc_iv;            /**< IV to use, will be filled if
	                                        FPN_CRYPTO_F_GEN_IV flag is set    */
	uint32_t        enc_len;           /**< Size of data to encrypt            */
	uint16_t        enc_skip;          /**< Bytes to ignore from src beginning */
	uint16_t        enc_inject;        /**< How many bytes to skip from dst
	                                        (ignored if src == enc_dst)        */
	/* Authentication params (ignored if auth_alg set to NULL in session) */
	char          * auth_dst;          /**< Output auth or auth to check       */
	uint32_t        auth_len;          /**< How many bytes to process          */
	uint16_t        auth_skip;         /**< Bytes to ignore from start         */

	/* Operation flags */
	uint16_t        flags;             /**< Operation flags                    */
} fpn_crypto_op_t;

/**
 * Descriptor for asymmetric crypto operation
 *
 * Description of param array according to op field:
 *
 * - op = @ref FPN_CRYPTO_KOPER_MOD_EXP : res = (arg ^ exp) MOD mod
 * @param[in]  param[0] = arg
 * @param[in]  param[1] = exp
 * @param[in]  param[2] = mod
 * @param[out] param[3] = res
 *
 * - op = @ref FPN_CRYPTO_KOPER_MOD_INV : res = (arg ^ -1) MOD mod
 * @param[in]  param[0] = arg
 * @param[in]  param[1] = mod
 * @param[out] param[2] = res
 *
 * - op = @ref FPN_CRYPTO_KOPER_ECC_POINT_ADD : P3 = P1 + P2
 * @param[in]  param[0] = P1x
 * @param[in]  param[1] = P1y
 * @param[in]  param[2] = P2x
 * @param[in]  param[3] = P2y
 * @param[out] param[4] = P3x
 * @param[out] param[5] = P3y
 *
 * - op = @ref FPN_CRYPTO_KOPER_ECC_POINT_DOUBLE : P2 = P1 + P1
 * @param[in]  param[0] = P1x
 * @param[in]  param[1] = P1y
 * @param[out] param[2] = P2x
 * @param[out] param[3] = P2y
 *
 * - op = @ref FPN_CRYPTO_KOPER_ECC_POINT_MUL : P3 = P1 x P2
 * @param[in]  param[0] = P1x
 * @param[in]  param[1] = P1y
 * @param[in]  param[2] = P2x
 * @param[in]  param[3] = P2y
 * @param[out] param[4] = P3x
 * @param[out] param[5] = P3y
 *
 * - op = @ref FPN_CRYPTO_KOPER_DH_GEN_KEY
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
 * - op = @ref FPN_CRYPTO_KOPER_RSA_ENCRYPT
 * @param[in]  param[0] = mod
 * @param[in]  param[1] = pub
 * @param[in]  param[2] = data
 * @param[out] param[3] = encrypt
 *
 * - op = @ref FPN_CRYPTO_KOPER_RSA_DECRYPT
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
 * - op = @ref FPN_CRYPTO_KOPER_RSA_GEN_KEY
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
 * - op = @ref FPN_CRYPTO_KOPER_DSA_GEN_PARAM
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
 * - op = @ref FPN_CRYPTO_KOPER_DSA_SIGN
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
 * - op = @ref FPN_CRYPTO_KOPER_DSA_VERIFY
 * @param[in]  param[0] = p
 * @param[in]  param[1] = q
 * @param[in]  param[2] = g
 * @param[in]  param[3] = pub
 * @param[in]  param[4] = z
 * @param[in]  param[5] = R
 * @param[in]  param[6] = S
 *
 * - op = @ref FPN_CRYPTO_KOPER_ECDSA_SIGN
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
 * - op = @ref FPN_CRYPTO_KOPER_ECDSA_VERIFY
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
 * - op = @ref FPN_CRYPTO_KOPER_PRIME_TEST
 * @param[in]  param[0] = prime
 */
typedef struct fpn_crypto_kop_s {
	/* Global parameters */
	void          * opaque;            /**< Opaque pointer, passed to callback */
	fpn_crypto_callback_t cb;          /**< Callback function, if set to null,
	                                        request is synchronous.            */

	fpn_crypto_koper_t op;             /**< Asymmetric crypto operation        */
	fpn_crparam_t   param[FPN_CRYPTO_KMAXPARAM]; /**< Array of parameters      */
	uint16_t        iparams;           /**< Number of input parameters         */
	uint16_t        oparams;           /**< Number of output parameters        */
	uint16_t        flags;             /**< Flags                              */
} fpn_crypto_kop_t;

/**
 * Descriptor for DRBG operation
 */
typedef struct fpn_drbg_op_s {
	/* Global parameters */
	void          * opaque;            /**< Opaque pointer, passed to callback */
	fpn_crypto_callback_t cb;          /**< Callback function, if set to null,
	                                        request is synchronous.            */

	fpn_crypto_session_t * session;    /**< Session id                         */
	char          * buf;               /**< Data buffer                        */
	int             len;               /**< Data length                        */
} fpn_rbg_op_t;

#endif

/**
 * Create a session
 *
 * This function creates a session. The type of the pointer is opaque and
 * depends on the engine.
 *
 * @param[in] init
 *   initialization structure
 *
 * @return
 *   Return NULL on error.
 */
fpn_crypto_session_t * fpn_crypto_session_new(fpn_crypto_init_t * init);


/**
 * Recover session parameters
 *
 * This function is used to recover digest length and block length in bytes
 *   used by the encrypt/auth algorithms of the session
 *
 * @param[in] session
 *   session to get parameters from
 * @param[out] block_len
 *   crypto algorithm block length
 * @param[out] digest_len
 *   authentication algorithm digest length
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or negative value on failure
 */
int fpn_crypto_session_params(fpn_crypto_session_t * session,
                              uint16_t * block_len, uint16_t * digest_len);

/**
 * Duplicate a session
 *
 * This function duplicates a session. The type of the pointer is opaque and
 * depends on the engine. The duplication includes keys and internal
 * state of partial hash
 *
 * @param[in] session
 *   session to duplicate
 *
 * @return
 *   Return NULL on error.
 */
fpn_crypto_session_t * fpn_crypto_session_dup(fpn_crypto_session_t * session);

/**
 * Free a session
 *
 * This function is used to free a session. A session should not be freed if 
 * callbacks are pending for this session.
 *
 * @param[in] session
 *   Id of session to close
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or negative value on failure
 */
int fpn_crypto_session_free(fpn_crypto_session_t * session);

/**
 * Start a symmetric crypto operation
 *
 * This function starts a crypto operation with the parameters
 * specified in the "operation" structure. The function returns 0 on
 * success, a negative value on error (-errno).
 *
 * If the "operation" parameter was dynamically allocated by the user, it can
 * be freed once fpn_crypto_invoke() has returned: even for asynchronous
 * operations, the fpn crypto layer does not reference this memory area.
 *
 * In case of a block cipher, the data len must be a multiple of block
 * size. When using mbufs, the output mbuf must have the correct length:
 * m_append() should be called by the user before
 * crypto_invoke().
 *
 * 'enc_iv' and 'auth_dst' always point to contiguous data.
 * if processing is done on a mbuf, auth_dst MUST be located in one mbuf
 * of the buffer chain
 *
 * @param[in] operation
 *   Description of the operation to process
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or negative value on failure
 */
int fpn_crypto_invoke(fpn_crypto_op_t * operation);

/**
 * Start an asymmetric crypto operation
 *
 * This function starts an asymmetric crypto operation with the
 * parameters specified in the "operation" structure. The function
 * returns 0 on success, a negative value on error (-errno).
 *
 * If the "operation" parameter was dynamically allocated by the user, it
 * can be freed once fpn_crypto_invoke() has returned: even for
 * asynchronous operations, the fpn crypto layer does not reference
 * this memory area.
 *
 * @param[in] operation
 *   Description of the operation to process
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or negative value on failure
 */
int fpn_crypto_kinvoke(fpn_crypto_kop_t * operation);

/**
 * Instantiate a DRBG session
 *
 * This function instantiates a new DRBG session.
 *
 * @return
 *   Return session Id or NULL on error.
 */
fpn_crypto_session_t *fpn_drbg_session_new(void);

/**
 * Free a DRBG session
 *
 * This function frees a previously allocated DRBG session.
 *
 * @return
 *   None.
 */
int fpn_drbg_session_free(fpn_crypto_session_t * session);

/**
 * Seed DRB generator
 *
 * This function is used to (re)seed the generator.
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_drbg_seed(fpn_rbg_op_t * op);

/**
 * Generate Pseudo random bytes
 *
 * This function is used to get pseudo random bytes from generator
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_drbg_generate(fpn_rbg_op_t * op);

/**
 * Generate random bytes
 *
 * This function is used to get random bytes
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_nrbg_generate(fpn_rbg_op_t * op);

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
 *   FPN_CRYPTO(ALL_CORES), statistics are cumulated on all
 *   running cores
 * @param[out] statistics
 *   Structure that will contain the statistics on return
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or negative value on failure
 */
int fpn_crypto_statistics(char const *device, uint32_t core_id,
                          fpn_crypto_statistics_t * statistics);

/**
 * Initialize library
 *
 * This function setup memory pools and initialize memory used by the
 * library
 *
 * @param[in] pool_size
 *   Number of buffers in pool
 * @param[in] pool_cache
 *   Number of buffers in pool cache of each core
 * @param[in] nb_context
 *   Max number of unidirectionnal SAs supported
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_crypto_init(uint32_t pool_size,  uint32_t pool_cache,
                    uint32_t nb_context);

/**
 * Exit library
 *
 * This function frees any memory allocated by fpn_crypto_init function.
 *   All cores must have call fpn_crypto_core_exit before calling
 *   fpn_crypto_exit.
 *
 * @return
 *   FPN_CRYPTO(SUCCESS)
 *
 * @see fpn_crypto_core_exit()
 */
int fpn_crypto_exit(void);

/**
 * Initialize per core structures
 *
 * This function configure per core structures
 *
 * @param[in] rx_bulk
 *   Maximum number of frames received in a row by fpn_crypto_receive
 *   function
 * @param[in] tx_bulk
 *   Number of frames stored before triggering a flush of the Tx queue.
 * @param[out] nb_inst
 *   Number of instances managed by this core
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_crypto_core_init(uint32_t rx_bulk, uint32_t tx_bulk, uint32_t * nb_inst);

/**
 * Reset per core structures
 *
 * This function frees any memory allocated by fpn_crypto_core_init
 *   function.
 *
 * @warning : all sessions opened on this core must be closed before
 *   calling fpn_crypto_core_exit
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_crypto_core_exit(void);

/**
 * Poll per core queues
 *
 * This function polls per core rx queues.
 *
 * @param[in] flush
 *   When non null, tells the function to also flush the per core tx queues
 *
 * @return
 *   number of buffers processed
 */
int fpn_crypto_poll(uint32_t flush);

#endif

#endif /* elif !CONFIG_MCORE_FPE_VFP */

#endif /* _FPN_CRYPTO_H_ */
