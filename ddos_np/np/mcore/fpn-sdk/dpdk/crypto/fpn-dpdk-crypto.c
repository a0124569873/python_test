/*
 * Copyright(c) 2011  6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fpn-crypto.h"

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
#include "crypto/fpn-crypto-generic.h"
#endif

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO

/* If hooks are not defined, these functions must not be defined */
/* else real processing rte_crypto_xxx functions will never be called */
#ifdef CONFIG_MCORE_FPN_HOOK

/* RTE crypto stub, will be used if rte_crypto library is not dynamically linked */
/* at runtime */
/**
 * Create a session.
 */
rte_crypto_session_t * rte_crypto_session_new(__fpn_maybe_unused rte_crypto_init_t * init)
{
	return NULL;
}
FPN_HOOK_REGISTER(rte_crypto_session_new)

/**
 * Get some session parameters
 */
int rte_crypto_session_params(__fpn_maybe_unused rte_crypto_session_t * fpn_session,
                              __fpn_maybe_unused uint16_t * block_len,
                              __fpn_maybe_unused uint16_t * digest_len)
{
	return FPN_CRYPTO(FAILURE);
}
FPN_HOOK_REGISTER(rte_crypto_session_params)

/**
 * Duplicate a session.
 */
rte_crypto_session_t * rte_crypto_session_dup(__fpn_maybe_unused rte_crypto_session_t * orig)
{
	return NULL;
}
FPN_HOOK_REGISTER(rte_crypto_session_dup)

/**
 * Free a session. Wait until all pending calls are done
 */
int rte_crypto_session_free(__fpn_maybe_unused rte_crypto_session_t * arg)
{
	return FPN_CRYPTO(FAILURE);
}
FPN_HOOK_REGISTER(rte_crypto_session_free)

/**
 * Do crypto operation
 */
int rte_crypto_invoke(__fpn_maybe_unused rte_crypto_op_t * operation)
{
	return FPN_CRYPTO(FAILURE);
}
FPN_HOOK_REGISTER(rte_crypto_invoke)

/**
 * No statistics
 */
int rte_crypto_statistics(
	__fpn_maybe_unused char const *device,                    /* Device name */
	__fpn_maybe_unused uint32_t lcore_id,                     /* Id of core                         */
	__fpn_maybe_unused rte_crypto_statistics_t * statistics   /* Statistics structure to fill       */
)
{
	return (FPN_CRYPTO(FAILURE));
}
FPN_HOOK_REGISTER(rte_crypto_statistics)

/**
 * Initialize stub crypto
 */
int rte_crypto_init(
	__fpn_maybe_unused uint32_t     pool_size,   /* Buffers in pool          */
	__fpn_maybe_unused uint32_t     pool_cache,  /* Buffers in pool cache    */
	__fpn_maybe_unused uint32_t     nb_context   /* Number of SAs            */
)
{
	printf("No support for hardware acceleration of crypto operations\n");
	return FPN_CRYPTO(SUCCESS);
}
FPN_HOOK_REGISTER(rte_crypto_init)

/**
 * Exit from stub crypto
 */
int rte_crypto_exit(void) {
	return FPN_CRYPTO(SUCCESS);
}
FPN_HOOK_REGISTER(rte_crypto_exit)

/**
 * Per core initialization
 */
int rte_crypto_core_init(
	__fpn_maybe_unused uint32_t     rx_bulk,     /* Maximum frames received  */
	__fpn_maybe_unused uint32_t     tx_bulk,     /* Maximum frames to flush  */
	__fpn_maybe_unused uint32_t   * nb_inst      /* Number of instances      */
)
{
	return FPN_CRYPTO(SUCCESS);
}
FPN_HOOK_REGISTER(rte_crypto_core_init)

/**
 * Free per core ressources
 */
int rte_crypto_core_exit(void) {
	return FPN_CRYPTO(SUCCESS);
}
FPN_HOOK_REGISTER(rte_crypto_core_exit)

/**
 * Poll queue of crypto done
 */
int rte_crypto_poll(__fpn_maybe_unused uint32_t flush)
{
	return 0;
}
FPN_HOOK_REGISTER(rte_crypto_poll)

/**
 * Passed parameters
 */
void rte_crypto_configure(__fpn_maybe_unused char **params,
                          __fpn_maybe_unused unsigned int count)
{
}
FPN_HOOK_REGISTER(rte_crypto_configure)

/**
 * Start an asymmetric crypto operation
 */
int rte_crypto_kinvoke(__fpn_maybe_unused fpn_crypto_kop_t * operation)
{
	return (FPN_CRYPTO(FAILURE));
}
FPN_HOOK_REGISTER(rte_crypto_kinvoke)

/**
 * Instantiate a DRBG session
 */
fpn_crypto_session_t *rte_drbg_session_new(void)
{
    return(NULL);
}
FPN_HOOK_REGISTER(rte_drbg_session_new)

/**
 * Free a DRBG session
 */
int rte_drbg_session_free(__fpn_maybe_unused fpn_crypto_session_t * session)
{
	return FPN_CRYPTO(FAILURE);
}
FPN_HOOK_REGISTER(rte_drbg_session_free)

/**
 * Seed DRB generator
 */
int rte_drbg_seed(__fpn_maybe_unused fpn_rbg_op_t * op)
{
	return (FPN_CRYPTO(FAILURE));
}
FPN_HOOK_REGISTER(rte_drbg_seed)

/**
 * Generate Pseudo random bytes
 */
int rte_drbg_generate(__fpn_maybe_unused fpn_rbg_op_t * op)
{
	return (FPN_CRYPTO(FAILURE));
}
FPN_HOOK_REGISTER(rte_drbg_generate)

/**
 * Generate random bytes
 */
int rte_nrbg_generate(__fpn_maybe_unused fpn_rbg_op_t * op)
{
	return (FPN_CRYPTO(FAILURE));
}
FPN_HOOK_REGISTER(rte_nrbg_generate)

#endif /* CONFIG_MCORE_FPN_HOOK */
#endif /* CONFIG_MCORE_FPN_RTE_CRYPTO */

/* RTE implementation of FPN crypto */

/**
 * Create a session.
 */
fpn_crypto_session_t * fpn_crypto_session_new(__fpn_maybe_unused fpn_crypto_init_t * init)
{
	fpn_crypto_session_t * session = NULL;

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	/* Default, use RTE */
	session = (fpn_crypto_session_t *) FPN_HOOK_CALL(rte_crypto_session_new)(init);
#endif

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	/* No RTE session, fallback on generic implementation */
	if (session == NULL) {
		session = fpn_crypto_generic_session_new(init);

		/* Setup dev header to NULL to mark generic implementation */
		if (session != NULL) {
			session->dev = NULL;
		}
	}
#endif

	return(session);
}

/**
 * Recover session parameters
 */
int fpn_crypto_session_params(__fpn_maybe_unused fpn_crypto_session_t * session,
                              __fpn_maybe_unused uint16_t * block_len,
                              __fpn_maybe_unused uint16_t * digest_len)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	if (session->dev == NULL)
		return fpn_crypto_generic_session_params(session, block_len, digest_len);
#endif
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_crypto_session_params)(session, block_len, digest_len);
#endif
	return ret;
}

/**
 * Duplicate a session.
 */
fpn_crypto_session_t * fpn_crypto_session_dup(__fpn_maybe_unused fpn_crypto_session_t * session)
{
	fpn_crypto_session_t *new_session = NULL;

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	if (session->dev == NULL)
		return fpn_crypto_generic_session_dup(session);
#endif
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	new_session = FPN_HOOK_CALL(rte_crypto_session_dup)(session);
#endif
	return new_session;
}

/**
 * Free the session. A session should not be freed if callbacks are
 * pending for this session.
 */
int fpn_crypto_session_free(__fpn_maybe_unused fpn_crypto_session_t * session)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	if (session->dev == NULL)
		return fpn_crypto_generic_session_free(session);
#endif
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_crypto_session_free)(session);
#endif
	return ret;
}

/**
 * Start a symmetric crypto operation
 */
int fpn_crypto_invoke(__fpn_maybe_unused fpn_crypto_op_t * operation)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	fpn_crypto_session_t * session = (fpn_crypto_session_t *) operation->session;
	if (session->dev == NULL)
		return fpn_crypto_generic_invoke(operation);
#endif
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_crypto_invoke)(operation);
#endif
	return ret;
}

/**
 * Start an asymmetric crypto operation
 */
int fpn_crypto_kinvoke(__fpn_maybe_unused fpn_crypto_kop_t * operation)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_crypto_kinvoke)(operation);
#endif
	return ret;
}

/**
 * Instantiate a DRBG session
 */
fpn_crypto_session_t *fpn_drbg_session_new(void)
{
	fpn_crypto_session_t *session = NULL;

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	session = FPN_HOOK_CALL(rte_drbg_session_new)();
#endif
	return session;
}

/**
 * Free a DRBG session
 */
int fpn_drbg_session_free(__fpn_maybe_unused fpn_crypto_session_t * session)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_drbg_session_free)(session);
#endif
	return ret;
}

/**
 * Seed DRB generator
 */
int fpn_drbg_seed(__fpn_maybe_unused fpn_rbg_op_t * op)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_drbg_seed)(op);
#endif
	return ret;
}

/**
 * Generate Pseudo random bytes
 */
int fpn_drbg_generate(__fpn_maybe_unused fpn_rbg_op_t * op)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_drbg_generate)(op);
#endif
	return ret;
}

/**
 * Generate random bytes
 */
int fpn_nrbg_generate(__fpn_maybe_unused fpn_rbg_op_t * op)
{
	int ret = FPN_CRYPTO(FAILURE);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret = FPN_HOOK_CALL(rte_nrbg_generate)(op);
#endif
	return ret;
}

/**
 * Recover statistics
 */
int fpn_crypto_statistics(__fpn_maybe_unused char const *device,
                          __fpn_maybe_unused uint32_t core_id,
                          __fpn_maybe_unused fpn_crypto_statistics_t * statistics)
{
	int ret = FPN_CRYPTO(SUCCESS);

	if ((device == NULL) || (device[0] == 0)) {
#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
		fpn_crypto_statistics_t stats;
#endif

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
		/* Get RTE statistics */
		ret += FPN_HOOK_CALL(rte_crypto_statistics)(device, core_id, statistics);
#endif

#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
		/* Sum up with generic statistics */
		ret += fpn_crypto_generic_statistics(core_id, &stats);

		/* Cumulate statistics */
		statistics->nb_session     += stats.nb_session;
		statistics->nb_crypto      += stats.nb_crypto;
		statistics->nb_kop         += stats.nb_kop;
		statistics->nb_rand        += stats.nb_rand;
		statistics->out_of_space   += stats.out_of_space;
		statistics->out_of_buffer  += stats.out_of_buffer;
		statistics->out_of_session += stats.out_of_session;
		statistics->internal_error += stats.internal_error;
		statistics->nb_poll        += stats.nb_poll;
		statistics->dummy_poll     += stats.dummy_poll;
		statistics->timeout_flush  += stats.timeout_flush;
		statistics->bulk_flush     += stats.bulk_flush;
#endif
	} else {
#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
		if (!strcmp(device, "generic")) {
			return fpn_crypto_generic_statistics(core_id, statistics);
		}
#endif
#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
		ret = FPN_HOOK_CALL(rte_crypto_statistics)(device, core_id, statistics);
#endif
	}

	return ret;
}

/**
 * Initialize crypto drivers
 */
int fpn_crypto_init(__fpn_maybe_unused uint32_t pool_size,
                    __fpn_maybe_unused uint32_t pool_cache,
                    __fpn_maybe_unused uint32_t nb_context)
{
	int ret = FPN_CRYPTO(SUCCESS);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret |= FPN_HOOK_CALL(rte_crypto_init)(pool_size, pool_cache, nb_context);
#endif
#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	ret |= fpn_crypto_generic_init(pool_size, pool_cache, nb_context);
#endif

	return(ret);
}

/**
 * Initialize per core parts
 */
int fpn_crypto_core_init(__fpn_maybe_unused uint32_t rx_bulk,
                         __fpn_maybe_unused uint32_t tx_bulk,
                         __fpn_maybe_unused uint32_t *nb_inst)
{
	int ret = FPN_CRYPTO(SUCCESS);

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret |= FPN_HOOK_CALL(rte_crypto_core_init)(rx_bulk, tx_bulk, nb_inst);
#endif
#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	ret |= fpn_crypto_generic_core_init(rx_bulk, tx_bulk, nb_inst);
#endif

	return(ret);
}

/**
 * This function will receive buffers processed by the devices handled by this
 *   core and the corresponding callback will be called. 
 */
int fpn_crypto_poll(__fpn_maybe_unused uint32_t flush)
{
	int ret = 0;

#ifdef CONFIG_MCORE_FPN_RTE_CRYPTO
	ret += FPN_HOOK_CALL(rte_crypto_poll)(flush);
#endif
#ifdef CONFIG_MCORE_FPN_CRYPTO_GENERIC
	ret += fpn_crypto_generic_poll(flush);
#endif

	return(ret);
}
