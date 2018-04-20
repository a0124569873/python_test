/*
 * Copyright(c) 2014 6WIND
 */
#ifndef __FP_VNB_H__
#define __FP_VNB_H__

#if CONFIG_MCORE_VNB_MAX_NS > 1
#define fp_get_vnb_ns() (fp_vnb_shared->data_ns)
#else
#define fp_get_vnb_ns() 0
#endif

#define IFF_NG_ETHER     0x01 /* VNB: ether node is connected to lower hook */
#define IFF_NG_EIFACE    0x02 /* VNB: eiface node is bound to interface */
#define IFF_NG_IFACE     0x04 /* VNB: iface node is bound to interface */

#define IFP2IDX(ifp) (unsigned long)((ifp) - fp_shared->ifnet.table)
#define IFP2FLAGS(ifp, ns) fp_vnb_shared->if_ops[IFP2IDX(ifp)].if_vnb_flags[ns]

typedef struct {
	union {
		uint64_t p; /* max sizeof pointer */
		void *priv;
	} u;
} fp_p_t;

typedef struct {
	fp_p_t ether;     /* used by ng_ether */
	fp_p_t eiface;    /* used by ng_eiface */
	fp_p_t raw;       /* used by ng_iface */
} fp_if_vnb_ops_t;

typedef struct ng_if_ops {
	uint8_t if_vnb_flags[CONFIG_MCORE_VNB_MAX_NS];
	fp_if_vnb_ops_t if_vnb_ops[CONFIG_MCORE_VNB_MAX_NS] __attribute__((aligned(8)));
} ng_if_ops_t;

typedef struct fp_vnb_shared_mem {
	uint32_t               expected_seqnum;
#if CONFIG_MCORE_VNB_MAX_NS > 1
	uint32_t               data_ns;
#endif
	ng_if_ops_t            if_ops[FP_MAX_IFNET];
} fp_vnb_shared_mem_t;

#ifdef __FastPath__
FPN_DECLARE_SHARED(uint16_t, vnb_moduid);
FPN_DECLARE_SHARED(fp_vnb_shared_mem_t *, fp_vnb_shared);
#endif

#endif /* __FP_VNB_H__ */
