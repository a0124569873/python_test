/*
 * Copyright(c) 2013 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-log.h"
#include "fp-ip.h"

#include "netipsec/fp-ah.h"
#include "netipsec/fp-esp.h"
#include "netinet/fp-udp.h"

#include "fp-fpib.h"
#include "fp-ipsec-common.h"
#include "fp-ipsec-input.h"
#include "fp-ipsec-lookup.h"
#include "fp-ipsec-replay.h"
#include "fpn-crypto.h"
#include "fp-dscp.h"

#include "fp-svti-lookup.h"

#define TRACE_IPSEC_IN(level, fmt, args...) do {			\
		FP_LOG(level, IPSEC_IN, fmt "\n", ## args);		\
} while(0)

uint32_t ipsec4_svti_lookup(struct mbuf *m, fp_sa_entry_t *sa)
{
	uint32_t hash;
	int idx;

	/* check if an svti interface is cached in the SA and if the cache
	 * entry is still valid. If yes return it.
	 */
	if (fp_shared->svti[sa->svti_idx].genid == sa->svti_genid) {
		TRACE_IPSEC_IN(FP_LOG_DEBUG,
		"%s: cached svti ifuid %08"PRIx32" still valid\n",
		__FUNCTION__, ntohl(fp_shared->svti[sa->svti_idx].ifuid));
		return fp_shared->svti[sa->svti_idx].ifuid;
	}

	/* find an svti interface matching the SA addresses and vrfid */
	hash = fp_svti_hash(sa->dst4, sa->src4, sa->vrfid);
	fp_hlist_for_each(idx, &fp_shared->svti_hash[hash],
			  fp_shared->svti, hlist) {

		if (sa->vrfid == fp_shared->svti[idx].link_vrfid &&
		    sa->dst4 == fp_shared->svti[idx].laddr &&
		    sa->src4 == fp_shared->svti[idx].raddr) {
			break;
		}
	}
	sa->svti_idx = idx;
	sa->svti_genid = fp_shared->svti[idx].genid;

	TRACE_IPSEC_IN(FP_LOG_DEBUG,
		"%s: new svti ifuid %08"PRIx32"\n",
		__FUNCTION__, ntohl(fp_shared->svti[sa->svti_idx].ifuid));

	return idx ? fp_shared->svti[idx].ifuid : 0;
}

