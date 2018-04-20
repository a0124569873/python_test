/*
 * Copyright(c) 2014 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "fpn-gc.h"
#include "fpn-crypto.h"
#include "fp-ipsec-common.h"

#ifdef CONFIG_MCORE_FPN_CRYPTO_ASYNC
/* Callback used by garbage collector to free crypto sessions */
void fp_crypto_session_free(struct fpn_gc_object * gc)
{
	fp_sa_gc_t * sa_gc;

	/* Get SA context from gc object */
	sa_gc = fpn_containerof(gc, fp_sa_gc_t, gc);

	/* Release previously allocated sessions */
	fpn_crypto_priv_free(sa_gc->session);

	/* Free memory allocated for this operation */
	fpn_free(sa_gc);
}
#endif
