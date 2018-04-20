/*
 * general_inline_functions.h
 */

#include "../ng_ddos.h"
#include "read_fp_shared.h"

#ifndef __GENERAL_INLINE_FUNCTIONS_H_
#define __GENERAL_INLINE_FUNCTIONS_H_

#if defined(__FastPath__)

static inline int send_pkt_to_kernel(struct mbuf *m, meta_p meta)
{
	fp_sp_exception(m);
	m = NULL;
	NG_FREE_META(meta);
	return FP_DONE;
}

#endif


#endif /* __GENERAL_INLINE_FUNCTIONS_H_ */
