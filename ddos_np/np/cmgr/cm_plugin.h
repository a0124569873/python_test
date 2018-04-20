/*
 * Copyright (c) 2014 6WIND
 */

#ifndef __CM_PLUGIN_H_
#define __CM_PLUGIN_H_

#include <inttypes.h>
#include <sys/queue.h>
#include <syslog.h>
#include <errno.h>
#include <linux/netlink.h>

#include "fpm.h"
#include "cm_dump.h"

#define _DEF_CONF(x) CM_##x

/* Cache manager config variables
 */
enum {
	_DEF_CONF(CONFIG_CACHEMGR_MULTIBLADE),
	_DEF_CONF(CONFIG_PORTS_CACHEMGR_DEF_NFCT_DISABLE),
	_DEF_CONF(CONFIG_CACHEMGR_DIAG),
	_DEF_CONF(CONFIG_CACHEMGR_NF_UID),
	_DEF_CONF(CONFIG_CACHEMGR_NF_LSN),
	_DEF_CONF(CONFIG_CACHEMGR_AUDIT),
	_DEF_CONF(CONFIG_CACHEMGR_NF_DEV),
	_DEF_CONF(CONFIG_PORTS_CACHEMGR_NF_RULE_NAT),
	_DEF_CONF(CONFIG_HA6W_SUPPORT),
	_DEF_CONF(RTM_GETNETCONF),
	_DEF_CONF(IFLA_IPTUN_MAX),
	_DEF_CONF(CONFIG_PORTS_CACHEMGR_NETNS),
	_DEF_CONF(CONFIG_CACHEMGR_VXLAN),
	_DEF_CONF(CONFIG_CACHEMGR_VLAN),
	_DEF_CONF(CONFIG_CACHEMGR_BRIDGE),
	_DEF_CONF(CONFIG_CACHEMGR_BONDING),
	_DEF_CONF(CONFIG_CACHEMGR_GRE),
	_DEF_CONF(CONFIG_CACHEMGR_MACVLAN),
	_DEF_CONF(CONFIG_CACHEMGR_EBTABLES),

	__CM_CONFIG_MAX
};

extern const char *_cm_get_config(int config_var);

/* Use this macro to check if a cache manager option is enabled.
 *
 * If the config variable if defined, this macro returns a string containing
 * the variable name. Otherwise, it returns NULL.
 */
#define cm_get_config(x) _cm_get_config(CM_##x)

/* Send High Availability check request, if the feature is enabled
 */
extern void cm_do_has_check_request(void);

#define _PF(f) case f: str = #f ; break;

/* Default is to use our own allocator: free() does not return
 * memory fast enough.
 */
#define USE_QUEUE_ALLOC 1


#ifdef USE_QUEUE_ALLOC
#include <queue_alloc.h>
extern qa_mem_t qa_mem;
#endif

#define CM_ERROR 1

#ifdef USE_QUEUE_ALLOC
#define CM_MALLOC_NO_RET(x,size)   (x = qa_alloc(&qa_mem, size, 0))
#define CM_CALLOC_NO_RET(c,x,size) (x = qa_alloc(&qa_mem, c*size, QA_ZERO_MEM))
#else
#define CM_MALLOC_NO_RET(x,size)   (x = malloc(size))
#define CM_CALLOC_NO_RET(c,x,size) (x = calloc(c, size))
#endif

#define CM_CALLOC(c,x,size)                                             \
{                                                                       \
	CM_CALLOC_NO_RET(c,x,size);                                     \
	if (!x) {							\
		syslog(LOG_ERR, "%s: could not alloc memory\n", __func__); \
		return -ENOMEM;                                         \
	}                                                               \
}

#define CM_MALLOC(x,size)                                               \
{                                                                       \
	CM_MALLOC_NO_RET(x,size);                                       \
	if (!x) {                                                       \
		syslog(LOG_ERR, "%s: could not alloc memory\n", __func__); \
		return -ENOMEM;                                         \
	}                                                               \
}

#ifdef USE_QUEUE_ALLOC
#define CM_FREE(x) qa_free(&qa_mem, x)
#else
#define CM_FREE(x) free(x)
#endif

#define CM_ARRAY_SIZE(x)	(int)(sizeof(x)/(sizeof(x[0])))

/* message family (for XXX2str functions) */
#define MSG_FAMILY_RTM  		1
#define MSG_FAMILY_RTM_MULTICAST 	4
#define MSG_FAMILY_IFACE        6
#define MSG_FAMILY_ADDR         7
#define MSG_FAMILY_NEIGH        8
#define MSG_FAMILY_VNB		10
#define MSG_FAMILY_VNB_DUMP	11
#define MSG_FAMILY_XFRM		12
#define MSG_FAMILY_BLADE        13
#define MSG_FAMILY_NETCONF      14
#define MSG_FAMILY_DIAG         15

/* nl_dump.c */
extern const char *rtm_type2str(u_int16_t);

/* fpm.c */
extern int fpm_enqueue (struct cp_hdr *m, void *);
#define post_msg(x)    fpm_enqueue((x),NULL)

/* main.c */
extern int cm_debug_level;

#endif /* __CM_PLUGIN_H_ */
