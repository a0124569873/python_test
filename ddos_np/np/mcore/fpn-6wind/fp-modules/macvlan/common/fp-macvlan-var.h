/*
 * Copyright 2014 6WIND S.A.
 */

#ifndef __FP_MACVLAN_H__
#define __FP_MACVLAN_H__

/* Bridge magic number */
#define FP_MACVLAN_MAGIC32 19781215

/* Maximum number of MACVLAN interfaces per physical interface */
#ifdef CONFIG_MCORE_MACVLAN_IFACE_MAX
#define FP_MACVLAN_IFACE_MAX		CONFIG_MCORE_MACVLAN_IFACE_MAX
#else
#define FP_MACVLAN_IFACE_MAX		4	
#endif

/* Maximum number of link interfaces providing MACVLAN */
#ifdef CONFIG_MCORE_MACVLAN_LINKIFACE_MAX
#define FP_MACVLAN_LINKIFACE_MAX	CONFIG_MCORE_MACVLAN_LINKIFACE_MAX + 1
#else
#define FP_MACVLAN_LINKIFACE_MAX	32
#endif

typedef struct {
	uint32_t    ifuid;          /* macvlan ifuid */
#define FP_MACVLAN_MODE_UNKNOWN     0
#define FP_MACVLAN_MODE_PRIVATE     1
#define FP_MACVLAN_MODE_PASSTHRU    2
	uint32_t    mode;
} fp_macvlan_iface_t;

typedef struct {
	uint32_t            link_ifuid;     /* ifuid of the link interface */
	fp_macvlan_iface_t  macvlan_iface[FP_MACVLAN_IFACE_MAX];
} fp_macvlan_linkiface_t;

typedef struct fp_macvlan_shared_mem {
	/* MACVLAN interfaces */
	fp_macvlan_linkiface_t  macvlan_linkiface[FP_MACVLAN_LINKIFACE_MAX];
	uint32_t	            magic;
	/* Keep in last place, preserved on shared mem initialization */
	uint16_t                mod_uid;
} fp_macvlan_shared_mem_t;

#define FP_MACVLAN_SHARED "fp-share-macvlan"
int fp_addifnet_macvlaninfo(uint32_t ifuid, uint32_t link_ifuid,
			    uint32_t mode);
int fp_delifnet_macvlaninfo(uint32_t ifuid);
int fp_updateifnet_macvlaninfo(uint32_t ifuid, uint32_t mode);

void fp_macvlan_init_shmem(int graceful);

#endif /* __FP_MACVLAN_H__ */
