/*
 * Copyright(c) 2013 6WIND
 */
 
#ifndef _FPN_CRYPTO_GENERIC_H_
#define _FPN_CRYPTO_GENERIC_H_

#include "fpn.h"
#include "fpn-mbuf.h"
#include "fpn-crypto.h"

/**
 * Create a session
 *
 * This function creates a session. 
 *
 * @param[in] init
 *   initialization structure
 *
 * @return
 *   Return NULL on error.
 */
fpn_crypto_session_t * fpn_crypto_generic_session_new(fpn_crypto_init_t * init);


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
int fpn_crypto_generic_session_params(fpn_crypto_session_t * session,
                                      uint16_t * block_len, uint16_t * digest_len);

/**
 * Duplicate a session
 *
 * This function duplicates a session. The duplication includes keys and internal
 * state of partial hash
 *
 * @param[in] session
 *   session to duplicate
 *
 * @return
 *   Return NULL on error.
 */
fpn_crypto_session_t * fpn_crypto_generic_session_dup(fpn_crypto_session_t * session);

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
int fpn_crypto_generic_session_free(fpn_crypto_session_t * session);

/**
 * Start a symmetric crypto operation
 *
 * This function starts a crypto operation with the parameters
 * specified in the "operation" structure. The function returns 0 on
 * success, a negative value on error (-errno).
 *
 * If the "operation" parameter was dynamically allocated by the user, it can
 * be freed once fpn_crypto_generic_invoke() has returned: even for asynchronous
 * operations, the fpn crypto layer does not reference this memory area.
 *
 * In case of a block cipher, the data len must be a multiple of block
 * size. When using mbufs, the output mbuf must have the correct length:
 * m_append() should be called by the user before crypto_invoke().
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
int fpn_crypto_generic_invoke(fpn_crypto_op_t * operation);

/**
 * Start an asymmetric crypto operation
 *
 * This function starts an asymmetric crypto operation with the
 * parameters specified in the "operation" structure. The function
 * returns 0 on success, a negative value on error (-errno).
 *
 * If the "operation" parameter was dynamically allocated by the user, it
 * can be freed once fpn_crypto_generic_invoke() has returned: even for
 * asynchronous operations, the fpn crypto layer does not reference
 * this memory area.
 *
 * @param[in] operation
 *   Description of the operation to process
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or negative value on failure
 */
int fpn_crypto_generic_kinvoke(fpn_crypto_kop_t * operation);

/**
 * Instantiate a DRBG session
 *
 * This function instantiates a new DRBG session.
 *
 * @return
 *   Return session Id or NULL on error.
 */
fpn_crypto_session_t *fpn_drbg_generic_session_new(void);

/**
 * Free a DRBG session
 *
 * This function frees a previously allocated DRBG session.
 *
 * @return
 *   None.
 */
int fpn_drbg_generic_session_free(fpn_crypto_session_t * session);

/**
 * Seed DRB generator
 *
 * This function is used to (re)seed the generator.
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_drbg_generic_seed(fpn_rbg_op_t * op);

/**
 * Generate Pseudo random bytes
 *
 * This function is used to get pseudo random bytes from generator
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_drbg_generic_generate(fpn_rbg_op_t * op);

/**
 * Generate random bytes
 *
 * This function is used to get random bytes
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_nrbg_generic_generate(fpn_rbg_op_t * op);

/**
 * Recover statistics
 *
 * This function recover statistics
 *
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
int fpn_crypto_generic_statistics(uint32_t core_id,
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
int fpn_crypto_generic_init(uint32_t pool_size,  uint32_t pool_cache,
                            uint32_t nb_context);

/**
 * Exit library
 *
 * This function frees any memory allocated by fpn_crypto_generic_init function.
 *   All cores must have call fpn_crypto_generic_core_exit before calling
 *   fpn_crypto_generic_exit.
 *
 * @return
 *   FPN_CRYPTO(SUCCESS)
 *
 * @see fpn_crypto_generic_core_exit()
 */
int fpn_crypto_generic_exit(void);

/**
 * Initialize per core structures
 *
 * This function configure per core structures
 *
 * @param[in] rx_bulk
 *   Maximum number of frames received in a row by fpn_crypto_generic_receive
 *   function
 * @param[in] tx_bulk
 *   Unused
 * @param[out] nb_inst
 *   Number of instances managed by this core
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_crypto_generic_core_init(uint32_t rx_bulk, uint32_t tx_bulk, uint32_t * nb_inst);

/**
 * Reset per core structures
 *
 * This function frees any memory allocated by fpn_crypto_generic_core_init
 *   function.
 *
 * @warning : all sessions opened on this core must be closed before
 *   calling fpn_crypto_generic_core_exit
 *
 * @return
 *   FPN_CRYPTO(SUCCESS) or FPN_CRYPTO(FAILURE)
 */
int fpn_crypto_generic_core_exit(void);

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
int fpn_crypto_generic_poll(uint32_t flush);

#endif /* _FPN_CRYPTO_GENERIC_H_ */
