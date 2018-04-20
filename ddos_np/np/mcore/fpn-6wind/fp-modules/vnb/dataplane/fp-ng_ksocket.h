#ifndef _NETGRAPH_KSOCKET_H_
#define _NETGRAPH_KSOCKET_H_

#include "fp-vnb.h"

#define ERROUT(x) do {				\
		error = (x);			\
		VNB_TRAP("error %d", error);	\
		goto done;			\
	}					\
	while (0)

/* Node type name and magic cookie */
#define NG_KSOCKET_NODE_TYPE	"ksocket"
#define NGM_KSOCKET_COOKIE	942710669

/* For NGM_KSOCKET_SETOPT and NGM_KSOCKET_GETOPT control messages */
struct ng_ksocket_sockopt {
	int32_t		level;		/* second arg of [gs]etsockopt() */
	int32_t		name;		/* third arg of [gs]etsockopt() */
	u_char		value[0];	/* fourth arg of [gs]etsockopt() */
};

/* Max length socket option we can return via NGM_KSOCKET_GETOPT
   XXX This should not be necessary, we should dynamically size
   XXX the response. Until then.. */
#define NG_KSOCKET_MAX_OPTLEN	1024

/* Keep this in sync with the above structure definition */
#define NG_KSOCKET_SOCKOPT_INFO(svtype)	{			\
	  { "level",		&ng_parse_int32_type, 0	},	\
	  { "name",		&ng_parse_int32_type, 0	},	\
	  { "value",		(svtype), 0		},	\
	  { NULL, NULL, 0 }						\
}

/* Netgraph commands */
enum {
	NGM_KSOCKET_BIND = 1,
	NGM_KSOCKET_LISTEN,
	NGM_KSOCKET_ACCEPT,
	NGM_KSOCKET_CONNECT,
	NGM_KSOCKET_GETNAME,
	NGM_KSOCKET_GETPEERNAME,
	NGM_KSOCKET_SETOPT,
	NGM_KSOCKET_GETOPT,
	NGM_KSOCKET_REUSE_DGRAM,
	NGM_KSOCKET_SETVRFID,
	NGM_KSOCKET_ALLOCMETA,
	NGM_KSOCKET_STATUS,
};

/* Meta information ID's */
#define NG_KSOCKET_META_SOCKADDR	1	/* data is struct sockaddr */

int ng_ksocket_init(void);

#endif /* _NETGRAPH_KSOCKET_H_ */

