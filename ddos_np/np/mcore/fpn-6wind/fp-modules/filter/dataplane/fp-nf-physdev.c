/* Copyright 2014 6WIND S.A. */

#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"

#include "fp-nf-tables.h"

#define FWINV(bool, invflg) ((bool) ^ !!(invert & invflg))
static int nf_physdev_match(struct mbuf *m, uint8_t bitmask, uint8_t invert,
			    char *physindev, uint8_t physindev_len,
			    char *physoutdev, uint8_t physoutdev_len,
			    const fp_ifnet_t *indev,
			    const fp_ifnet_t *outdev)
{
#ifdef CONFIG_MCORE_EBTABLES
	const fp_ifnet_t *actual_indev, *actual_outdev;
	const char *actual_inifname, *actual_outifname = NULL;
	unsigned long ret;

	/* Not a bridged packet */
	if (!m_priv(m)->fp_phys_mask) {
#endif
		/* doesn't match if any one of the options is set (without inversion) */
		if (bitmask & FP_XT_PHYSDEV_OP_BRIDGED &&
		    !(invert & FP_XT_PHYSDEV_OP_BRIDGED))
			return NF_IP_MATCH_NO;
		if (bitmask & FP_XT_PHYSDEV_OP_ISIN &&
		    !(invert & FP_XT_PHYSDEV_OP_ISIN))
			return NF_IP_MATCH_NO;
		if (bitmask & FP_XT_PHYSDEV_OP_ISOUT &&
		    !(invert & FP_XT_PHYSDEV_OP_ISOUT))
			return NF_IP_MATCH_NO;
		if (bitmask & FP_XT_PHYSDEV_OP_IN &&
		    !(invert & FP_XT_PHYSDEV_OP_IN))
			return NF_IP_MATCH_NO;
		if (bitmask & FP_XT_PHYSDEV_OP_OUT &&
		    !(invert & FP_XT_PHYSDEV_OP_OUT))
			return NF_IP_MATCH_NO;
		return NF_IP_MATCH_YES;
#ifdef CONFIG_MCORE_EBTABLES
	}

	/* m_input_port contains the physical interface the packet was received from. */
	if (!(actual_indev = fp_ifuid2ifnet(fp_port2ifuid(m_input_port(m))))) {
		TRACE_NF(FP_LOG_ERR, "%s() with input_port not matching any actual iface",
			 __func__);
		return FP_DROP;
	}

	actual_inifname = actual_indev->if_name;

	/* m2ifnet(m) should be the actual bridge output iface (if known) */
	actual_outdev = m2ifnet(m);
	if (actual_outdev)
		actual_outifname = actual_outdev->if_name;

	TRACE_NF(FP_LOG_DEBUG, "mbuf's physin: \"%s\", physout: \"%s\"",
		 actual_inifname, actual_outifname);

	/* This only makes sense in the FORWARD and POSTROUTING chains */
	if (bitmask & FP_XT_PHYSDEV_OP_BRIDGED &&
	    (FWINV(!(m_priv(m)->fp_phys_mask & FP_BRNF_BRIDGED),
		   FP_XT_PHYSDEV_OP_BRIDGED)))
		return NF_IP_MATCH_NO;

	if ((bitmask & FP_XT_PHYSDEV_OP_ISIN &&
	     FWINV(!actual_inifname, FP_XT_PHYSDEV_OP_ISIN)) ||
	    (bitmask & FP_XT_PHYSDEV_OP_ISOUT &&
	     FWINV(!actual_outifname, FP_XT_PHYSDEV_OP_ISOUT)))
		return NF_IP_MATCH_NO;

	if (!(bitmask & FP_XT_PHYSDEV_OP_IN))
		goto match_outdev;

	ret = fpn_fast_memcmp(actual_inifname, physindev,
			      physindev_len);

	if (FWINV(!!ret, FP_XT_PHYSDEV_OP_IN))
		return NF_IP_MATCH_NO;

match_outdev:
	if (!(bitmask & FP_XT_PHYSDEV_OP_OUT))
		return NF_IP_MATCH_YES;

	if (!actual_outifname)
		return NF_IP_MATCH_NO;

	ret = fpn_fast_memcmp(actual_outifname, physoutdev,
			      physoutdev_len);

	if (FWINV(!!ret, FP_XT_PHYSDEV_OP_OUT))
	    return NF_IP_MATCH_NO;

	return NF_IP_MATCH_YES;
#endif /* CONFIG_MCORE_EBTABLES */
}
#undef FWINV


#define phys r->l2_opt.physdev
#ifdef CONFIG_MCORE_NETFILTER_IPV6
int nf6_physdev_match(struct mbuf *m, struct fp_nf6rule *r,
		      const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	return nf_physdev_match(m, phys.bitmask, phys.invert,
				phys.physindev, phys.physindev_len,
				phys.physoutdev, phys.physoutdev_len,
				indev, outdev);

}
#endif

int nf4_physdev_match(struct mbuf *m, struct fp_nfrule *r,
		     const fp_ifnet_t *indev, const fp_ifnet_t *outdev)
{
	return nf_physdev_match(m, phys.bitmask, phys.invert,
				phys.physindev, phys.physindev_len,
				phys.physoutdev, phys.physoutdev_len,
				indev, outdev);
}
#undef phys
