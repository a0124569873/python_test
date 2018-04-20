/*
 * Copyright(c) 2012  6WIND, All rights reserved.
 */
#ifndef _FPN_DPDK_CRYPTO_H_
#define _FPN_DPDK_CRYPTO_H_

/* RTE crypto implementations */

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO

#include <rte_crypto.h>

/*
 *
 * DEFINES
 *
 */

/* FPN crypto defines */

#define FPN_CRYPTO(s)           RTE_CRYPTO_##s


/*
 *
 * TYPES
 *
 */

/**
 * Enumerated values
 */

typedef rte_hash_algo_t         fpn_hash_algo_t;
typedef rte_crypto_algo_t       fpn_crypto_algo_t;
typedef rte_crypto_koper_t      fpn_crypto_koper_t;

/**
 * Buffer vectors
 */
typedef rte_vec_t               fpn_vec_t;
typedef rte_buf_t               fpn_buf_t;

/**
 * Big numbers representation, in packed bytes, significant byte first
 */
typedef rte_crparam_t           fpn_crparam_t;

/**
 * Crypto callback
 */
typedef rte_crypto_callback_t   fpn_crypto_callback_t;

/**
 * Crypto session
 */
typedef rte_crypto_session_t    fpn_crypto_session_t;

/**
 * Session initialization for symmetric crypto
 */
typedef rte_crypto_init_t       fpn_crypto_init_t;

/**
 * Operation description for asymmetric crypto
 */
typedef rte_crypto_op_t         fpn_crypto_op_t;

/**
 * Operation description for asymmetric crypto
 */
typedef rte_crypto_kop_t        fpn_crypto_kop_t;

/**
 * Operation description for random operations
 */
typedef rte_rbg_op_t            fpn_rbg_op_t;

/**
 * Crypto statistics
 */
typedef rte_crypto_statistics_t fpn_crypto_statistics_t;

/* Mark rte functions as being hookable */
FPN_HOOK_DECLARE(rte_crypto_session_new)
FPN_HOOK_DECLARE(rte_crypto_session_params)
FPN_HOOK_DECLARE(rte_crypto_session_dup)
FPN_HOOK_DECLARE(rte_crypto_session_free)
FPN_HOOK_DECLARE(rte_crypto_invoke)
FPN_HOOK_DECLARE(rte_crypto_kinvoke)
FPN_HOOK_DECLARE(rte_crypto_statistics)
FPN_HOOK_DECLARE(rte_crypto_init)
FPN_HOOK_DECLARE(rte_crypto_exit)
FPN_HOOK_DECLARE(rte_crypto_core_init)
FPN_HOOK_DECLARE(rte_crypto_core_exit)
FPN_HOOK_DECLARE(rte_crypto_poll)
FPN_HOOK_DECLARE(rte_crypto_configure)
FPN_HOOK_DECLARE(rte_drbg_session_new)
FPN_HOOK_DECLARE(rte_drbg_session_free)
FPN_HOOK_DECLARE(rte_drbg_seed)
FPN_HOOK_DECLARE(rte_drbg_generate)
FPN_HOOK_DECLARE(rte_nrbg_generate)

#endif

#endif
