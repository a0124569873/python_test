/*
 * Copyright(c) 2014 6WIND
 */
#ifndef __FP_IPSEC_COMMON_H__
#define __FP_IPSEC_COMMON_H__

#include "fpn.h"
#include "fpn-gc.h"
#include "fpn-crypto.h"

#define FP_DIR_IN  0
#define FP_DIR_OUT 1
#define FP_DIR_NUM 2

typedef struct {
	fpn_spinlock_t           lock;              /* SA replay window lock */
#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
	void                   * priv[FP_DIR_NUM];  /* Crypto priv pointers */
	uint8_t                  snapshot;          /* Counter snapshot */
#endif
} __fpn_cache_aligned fp_sa_ctx_t;

FPN_DECLARE_SHARED(fp_sa_ctx_t, sa_ctx[FP_MAX_SA_ENTRIES]);

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
typedef struct {
	struct fpn_gc_object     gc;                /* Garbage collector object */
	void                   * session;           /* Crypto session */
} fp_sa_gc_t;

extern void fp_crypto_session_free(struct fpn_gc_object * gc);

static inline int fp_check_sa(fp_sa_entry_t * sa, fp_sa_ctx_t * ctx,
                              uint8_t dir)
{
	/* Set counter/snapshot volatile to force reload on each access */
	volatile uint8_t * counter = &sa->counter;
	volatile uint8_t * snapshot = &ctx->snapshot;
	int ret = 0;

	/* Check if SA is modified by FPM or if session is not yet created */
	/* in this direction */
	if (unlikely((*snapshot != *counter) ||
	             (ctx->priv[dir] == NULL))) {

		/* SA stuff need to be created, try to get the lock */
		if (fpn_spinlock_trylock(&ctx->lock)) {
			int encrypt = (dir == FP_DIR_OUT ? FPN_ENCRYPT : FPN_DECRYPT);

			/* Check again snapshot value once we are locked; If job has */
			/* been done by another core, current counter value will */
			/* equal snapshot, so nothing will be done */
			if (*snapshot != *counter) {
				int i;

				/* Prepare garbage collector */
				for (i=0 ; i<FP_DIR_NUM ; i++) {
					if (ctx->priv[i] != NULL) {
						fp_sa_gc_t * sa_gc;

						/* Allocate some memory for garbage collector */
						sa_gc = fpn_malloc(sizeof(fp_sa_gc_t), 0);

						/* If memory can not be allocated */
						if (sa_gc == NULL) {
							/* Release lock */
							fpn_spinlock_unlock(&ctx->lock);

							/* Stop everything, will be retried later */
							return -1;
						}

						/* Store priv pointer in structure */
						sa_gc->session = ctx->priv[i];

						/* Call garbage collector */
						fpn_gc(&sa_gc->gc, fp_crypto_session_free);

						/* Reset pointer */
						ctx->priv[i] = NULL;
					}
				}

				/* Update snapshot */
				*snapshot = *counter;
			}

			/* Allocate a session in the desired direction if needed */
			if ((ctx->priv[dir] == NULL) &&
			    (fpn_crypto_priv_alloc(&ctx->priv[dir], encrypt,
			                           (uint64_t*)&sa->key_enc,
			                           sa->key_enc_len,
			                           sa->key_auth,
			                           sa->alg_enc,
			                           sa->alg_auth,
			                           sa->flags & FP_SA_FLAG_ESN) < 0)) {
				/* Drop packet */
				ret = -1;
			}

			/* Release lock */
			fpn_spinlock_unlock(&ctx->lock);
		} else {
			/* Someone is certainly doing the same job on another core */
			/* Drop packet */
			ret = -1;
		}
	}

	/* All is done */
	return ret;
}
#endif

#ifdef CONFIG_MCORE_IPSEC_IPV6
FPN_DECLARE_SHARED(fp_sa_ctx_t, sa6_ctx[FP_MAX_IPV6_SA_ENTRIES]);

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
static inline int fp_check_sa6(fp_v6_sa_entry_t * sa, fp_sa_ctx_t * ctx,
                               uint8_t dir)
{
	/* Set counter/snapshot volatile to force reload on each access */
	volatile uint8_t * counter = &sa->counter;
	volatile uint8_t * snapshot = &ctx->snapshot;
	int ret = 0;

	/* Check if SA is modified by FPM or if session is not yet created */
	/* in this direction */
	if (unlikely((*snapshot != *counter) ||
	             (ctx->priv[dir] == NULL))) {

		/* SA stuff need to be created, try to get the lock */
		if (fpn_spinlock_trylock(&ctx->lock)) {
			int encrypt = (dir == FP_DIR_OUT ? FPN_ENCRYPT : FPN_DECRYPT);

			/* Check again snapshot value once we are locked; If job has */
			/* been done by another core, current counter value will */
			/* equal snapshot, so nothing will be done */
			if (*snapshot != *counter) {
				int i;

				/* Prepare garbage collector */
				for (i=0 ; i<FP_DIR_NUM ; i++) {
					if (ctx->priv[i] != NULL) {
						fp_sa_gc_t * sa_gc;

						/* Allocate some memory for garbage collector */
						sa_gc = fpn_malloc(sizeof(fp_sa_gc_t), 0);

						/* If memory can not be allocated */
						if (sa_gc == NULL) {
							/* Release lock */
							fpn_spinlock_unlock(&ctx->lock);

							/* Stop everything, will be retried later */
							return -1;
						}

						/* Store priv pointer in structure */
						sa_gc->session = ctx->priv[i];

						/* Call garbage collector */
						fpn_gc(&sa_gc->gc, fp_crypto_session_free);

						/* Reset pointer */
						ctx->priv[i] = NULL;
					}
				}

				/* Update snapshot */
				*snapshot = *counter;
			}

			/* Allocate a session in the desired direction if needed */
			if ((ctx->priv[dir] == NULL) &&
			    (fpn_crypto_priv_alloc(&ctx->priv[dir], encrypt,
			                           (uint64_t*)&sa->key_enc,
			                           sa->key_enc_len,
			                           sa->key_auth,
			                           sa->alg_enc,
			                           sa->alg_auth,
			                           sa->flags & FP_SA_FLAG_ESN) < 0)) {
				/* Drop packet */
				ret = -1;
			}

			/* Release lock */
			fpn_spinlock_unlock(&ctx->lock);
		} else {
			/* Someone is certainly doing the same job on another core */
			/* Drop packet */
			ret = -1;
		}
	}

	/* All is done */
	return ret;
}
#endif
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */

#endif
