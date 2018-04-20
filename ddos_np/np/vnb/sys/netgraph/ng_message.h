
/*
 * ng_message.h
 *
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_message.h,v 1.4.2.5 2002/07/02 23:44:02 archie Exp $
 * $Whistle: ng_message.h,v 1.12 1999/01/25 01:17:44 archie Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_NG_MESSAGE_H_
#define _NETGRAPH_NG_MESSAGE_H_ 1

#include "alignment.h"

/* ASCII string size limits */
#define NG_TYPELEN	31	/* max type name len (32 with null) */
#define NG_HOOKLEN	31	/* max hook name len (32 with null) */
#define NG_NODELEN	31	/* max node name len (32 with null) */
#define NG_PATHLEN	511	/* max path len     (512 with null) */
#define NG_CMDSTRLEN	31	/* max command string (32 with null) */

#define NG_TYPESIZ	(NG_TYPELEN + 1)
#define NG_HOOKSIZ	(NG_HOOKLEN + 1)
#define NG_NODESIZ	(NG_NODELEN + 1)
#define NG_PATHSIZ	(NG_PATHLEN + 1)
#define NG_CMDSTRSIZ	(NG_CMDSTRLEN + 1)

#define NG_TEXTRESPONSE 1024	/* allow this length for a text response */

/* Type of a unique node ID */
#define ng_ID_t unsigned int
/* We reserve 1 bit to split ID allocated
 * by the control plane from ID allocated by
 * the fast path.
 */
#define VNB_ID_BITS      (sizeof(ng_ID_t) * 8 - 1)
#define VNB_ID_FP        (1u << VNB_ID_BITS)
#define VNB_ID_MASK      (VNB_ID_FP - 1U)
#define VNB_ID_SET_CP(x) ((x) & ~VNB_ID_FP)
#define VNB_ID_SET_FP(x) ((x) | VNB_ID_FP)

/* A netgraph message */
struct ng_mesg {
	struct	ng_msghdr {
		u_char		version;		/* must == NG_VERSION */
		u_char		spare;			/* pad to 2 bytes */
		u_int16_t	arglen;			/* length of data */
		u_int32_t	flags;			/* message status */
		u_int32_t	token;			/* match with reply */
		u_int32_t	typecookie;		/* node's type cookie */
		u_int32_t	cmd;			/* command identifier */
		u_int32_t	nodeid;			/* node identifier */
		char		cmdstr[NG_CMDSTRLEN+1];	/* cmd string + \0 */
	} header;
	char data[]; /* placeholder for actual data */
} ALIGN_ATTRIB ;

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_NG_MESG_INFO(dtype)	{			\
	  { "version",		&ng_parse_uint8_type, 0	},	\
	  { "spare",		&ng_parse_uint8_type, 0	},	\
	  { "arglen",		&ng_parse_uint16_type, 0},	\
	  { "flags",		&ng_parse_hint32_type, 0},	\
	  { "token",		&ng_parse_uint32_type, 0},	\
	  { "typecookie",	&ng_parse_uint32_type, 0},	\
	  { "cmd",		&ng_parse_uint32_type, 0},	\
	  { "nodeid",		&ng_parse_uint32_type, 0},	\
	  { "cmdstr",		&ng_parse_cmdbuf_type, 0},	\
	  { "data",		(dtype), 0		},	\
	  { NULL, NULL, 0 }					\
}

/* Negraph type binary compatibility field */
#define NG_VERSION	3

/* Flags field flags */
#define NGF_ORIG	0x0000		/* the msg is the original request */
#define NGF_RESP	0x0001		/* the message is a response */
#define NGF_ASCII	0x0002		/* VNB must first translate it from ASCII to binary */

/*
 * Here we describe the "generic" messages that all nodes inherently
 * understand. With the exception of NGM_TEXT_STATUS, these are handled
 * automatically by the base netgraph code.
 */

/* Generic message type cookie */
#define NGM_GENERIC_COOKIE	851672668

/* Generic messages defined for this type cookie */
#define	NGM_SHUTDOWN		1	/* shut down node */
#define NGM_MKPEER		2	/* create and attach a peer node */
#define NGM_CONNECT		3	/* connect two nodes */
#define NGM_NAME		4	/* give a node a name */
#define NGM_RMHOOK		5	/* break a connection btw. two nodes */
#define	NGM_NODEINFO		6	/* get nodeinfo for the target */
#define	NGM_LISTHOOKS		7	/* get list of hooks on node */
#define	NGM_LISTNAMES		8	/* list all globally named nodes */
#define	NGM_LISTNODES		9	/* list all nodes, named and unnamed */
#define	NGM_LISTTYPES		10	/* list all installed node types */
#define	NGM_TEXT_STATUS		11	/* (optional) get text status report */
#define	NGM_BINARY2ASCII	12	/* convert struct ng_mesg to ascii */
#define	NGM_ASCII2BINARY	13	/* convert ascii to struct ng_mesg */
#define	NGM_TEXT_CONFIG		14	/* (optional) get/set text config */
#define NGM_CONNECT_FORCE	15	/* connect-force two nodes */
#define NGM_CLILISTNAMES        58  /* list all globally named nodes */
#define NGM_CLILISTNODES        59  /* list all nodes, named and unnamed */
#define NGM_FINDNODE		60	/* find a node which is not used */
#define NGM_INSPEER         61
#define NGM_INSNODE         62
#define NGM_BYPASS          63
#define NGM_NULL            64  /* Msg to check msg loss between CP and FPM */
#define NGM_MKPEER_ID       65	/* create and attach a peer node and specify its ID */
#define NGM_DUMPNODES       66
#define NGM_SHOWHTABLES     67  /* Dump the repartition inside the hook hash table */
#define NGM_MKETHER         68  /* create a ng_ether node */
#define NGM_MKPEER_GET_NODEID		69	/* create and attach a peer node, and return its node id */


/* for graceful restart */
struct ng_nl_node {
	char name[NG_NODELEN + 1];
	char type[NG_TYPELEN + 1];
	uint32_t id;
	uint32_t numhooks;
} __attribute__ ((packed));

struct ng_nl_nodepriv {
	uint32_t data_len;
	char data[];
} __attribute__ ((packed));

struct ng_nl_hook {
	char name[NG_HOOKLEN + 1];
	char peername[NG_NODELEN + 1];
	uint32_t peernodeid;
} __attribute__ ((packed));

struct ng_nl_hookpriv {
	uint32_t data_len;
	char data[];
} __attribute__ ((packed));

struct ng_nl_status {
	u_char version;
	u_char pad1;
	uint16_t pad2;
	uint32_t count;
	uint32_t total_count;
} __attribute__ ((packed));

/* netlink commands */
enum {
	VNB_C_UNSPEC,
	VNB_C_DUMP,
	VNB_C_NEW,
	__VNB_C_MAX,
};
#define VNB_C_MAX (__VNB_C_MAX + 1)

/* generic structure for encapsulation vnb information  */

/* vnb netlink header message is ng_msghdr */
enum vnb_nl_attrs {
	VNBA_NONE,
	VNBA_MSGHDR,
	VNBA_MSGPATH,
	VNBA_MSGDATA,
	VNBA_MSGASCIIDATA,
	VNBA_SEQNUM,
	__VNBA_MAX,
};
#define VNBA_MAX	(__VNBA_MAX - 1)

/* genl attributes */
enum vnb_nl_dump_attrs {
	VNBA_DUMP_NONE = 0,
	VNBA_DUMP_STATUS,
	VNBA_DUMP_NODE,
	VNBA_DUMP_NODE_PRIV,
	VNBA_DUMP_HOOK_LIST,
	VNBA_DUMP_HOOK,
	VNBA_DUMP_HOOK_PRIV,
	__VNBA_DUMP_MAX,
};
#define VNBA_DUMP_MAX	(__VNBA_DUMP_MAX - 1)

/* Structure used for NGM_MKPEER and NGM_MKPEER_ID */
struct ngm_mkpeer {
	char	type[NG_TYPELEN + 1];			/* peer type */
	char	ourhook[NG_HOOKLEN + 1];		/* hook name */
	char	peerhook[NG_HOOKLEN + 1];		/* peer hook name */
	u_int32_t nodeid;				/* ID of the new node */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_MKPEER_INFO()	{			\
	  { "type",		&ng_parse_typebuf_type, 0},	\
	  { "ourhook",		&ng_parse_hookbuf_type, 0},	\
	  { "peerhook",		&ng_parse_hookbuf_type, 0},	\
	  { "nodeid",		&ng_parse_uint32_type, 0},	\
	  { NULL, NULL, 0 }					\
}

/* Structure used for NGM_INSPEER */
struct ngm_inspeer {
	char	type[NG_TYPELEN + 1];			/* peer type */
	char	ourhook[NG_HOOKLEN + 1];		/* hook name */
	char	peerhook[NG_HOOKLEN + 1];		/* peer hook name */
	char	peerhook2[NG_HOOKLEN + 1];		/* peer 2nd hook name */
	u_int32_t nodeid;				/* ID of the new node */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_INSPEER_INFO()	{			\
	  { "type",		&ng_parse_typebuf_type, 0	},	\
	  { "ourhook",		&ng_parse_hookbuf_type, 0	},	\
	  { "peerhook",		&ng_parse_hookbuf_type, 0	},	\
	  { "peerhook2",	&ng_parse_hookbuf_type, 0	},	\
	  { "nodeid",		&ng_parse_uint32_type, 0},	\
	  { NULL, NULL, 0 }						\
}

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_MKETHER_INFO()	{			\
	  { "ifname",		&ng_parse_typebuf_type, 0	},	\
	  { "nodeid",		&ng_parse_uint32_type, 0},	\
	  { NULL, NULL, 0 }						\
}

/* Structure used for NGM_CONNECT */
struct ngm_connect {
	char	path[NG_PATHLEN + 1];			/* peer path */
	char	ourhook[NG_HOOKLEN + 1];		/* hook name */
	char	peerhook[NG_HOOKLEN + 1];		/* peer hook name */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_CONNECT_INFO()	{			\
	  { "path",		&ng_parse_pathbuf_type, 0},	\
	  { "ourhook",		&ng_parse_hookbuf_type, 0},	\
	  { "peerhook",		&ng_parse_hookbuf_type, 0},	\
	  { NULL, NULL, 0 }					\
}

/* Structure used for NGM_INSNODE */
struct ngm_insnode {
	char	path[NG_PATHLEN + 1];			/* peer path */
	char	ourhook[NG_HOOKLEN + 1];		/* hook name */
	char	peerhook[NG_HOOKLEN + 1];		/* peer hook name */
	char	peerhook2[NG_HOOKLEN + 1];		/* peer 2nd hook name */
	u_int32_t nodeid;				/* ID of the new hook */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_INSNODE_INFO()	{			\
	  { "path",		&ng_parse_pathbuf_type, 0	},	\
	  { "ourhook",		&ng_parse_hookbuf_type, 0	},	\
	  { "peerhook",		&ng_parse_hookbuf_type, 0	},	\
	  { "peerhook2",	&ng_parse_hookbuf_type, 0	},	\
	  { "nodeid",		&ng_parse_uint32_type, 0},	\
	  { NULL, NULL, 0 }						\
}

/* Structure used for NGM_BYPASS */
struct ngm_bypass {
	char	ourhook[NG_HOOKLEN + 1];		/* hook name */
	char	ourhook2[NG_HOOKLEN + 1];		/* hook name */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_BYPASS_INFO()	{			\
	  { "ourhook",		&ng_parse_hookbuf_type, 0	},	\
	  { "ourhook2",		&ng_parse_hookbuf_type, 0	},	\
	  { NULL, NULL, 0 }						\
}

/* Structure used for NGM_NAME */
struct ngm_name {
	char	name[NG_NODELEN + 1];			/* node name */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_NAME_INFO()	{				\
	  { "name",		&ng_parse_nodebuf_type, 0},	\
	  { NULL, NULL, 0 }					\
}

/* Structure used for NGM_RMHOOK */
struct ngm_rmhook {
	char	ourhook[NG_HOOKLEN + 1];		/* hook name */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_RMHOOK_INFO()	{			\
	  { "hook",		&ng_parse_hookbuf_type, 0},	\
	  { NULL, NULL, 0 }					\
}

/* Structure used for NGM_NODEINFO */
struct nodeinfo {
	char		name[NG_NODELEN + 1];	/* node name (if any) */
        char    	type[NG_TYPELEN + 1];   /* peer type */
	ng_ID_t		id;			/* unique identifier */
	u_int32_t	hooks;			/* number of active hooks */
	u_int16_t	vnb_ns;
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_NODEINFO_INFO()	{			\
	  { "name",		&ng_parse_nodebuf_type, 0},	\
	  { "type",		&ng_parse_typebuf_type, 0},	\
	  { "id",		&ng_parse_hint32_type, 0},	\
	  { "hooks",		&ng_parse_uint32_type, 0},	\
	  { NULL, NULL, 0 }						\
}

/* Structure used for NGM_LISTHOOKS */
struct linkinfo {
	char		ourhook[NG_HOOKLEN + 1];	/* hook name */
	char		peerhook[NG_HOOKLEN + 1];	/* peer hook */
	struct nodeinfo	nodeinfo;
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_LINKINFO_INFO(nitype)	{		\
	  { "ourhook",		&ng_parse_hookbuf_type, 0},	\
	  { "peerhook",		&ng_parse_hookbuf_type, 0},	\
	  { "nodeinfo",		(nitype),   0		},	\
	  { NULL, NULL, 0 }					\
}

struct hooklist {
	struct nodeinfo nodeinfo;		/* node information */
	struct linkinfo link[];			/* info about each hook */
} ALIGN_ATTRIB ;

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_HOOKLIST_INFO(nitype,litype)	{		\
	  { "nodeinfo",		(nitype), 0	},		\
	  { "linkinfo",		(litype), 0	},		\
	  { NULL, NULL, 0 }					\
}

/* Structure used for NGM_LISTNAMES/NGM_LISTNODES */
struct namelist {
	u_int32_t	numnames;		/* nodes contained in this message */
	u_int32_t	totalnames;		/* total nodes contained in netgraph system */
	struct nodeinfo	nodeinfo[];
};

/* structure used for NGM_LISTNAMES/NGM_LISTNODES, from ngctl to VNB */
struct listoffset{
#define DEFAULT_LIST_OFFSET 	0	/* from starting line to show information */
#define DEFAULT_LIST_COUNT	0	/* UDP message limits to 64 KB, a proper nodes
					 * count can be selected. Default is no limit. */
#define DEFAULT_MAX_LIST_COUNT  200
	u_int32_t	offset;			/* from where start to list nodes */
	u_int32_t	count;			/* how many nodes are about to list */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_LISTNODES_INFO(niarraytype)	{		\
	  { "numnames",		&ng_parse_uint32_type, 0},	\
	  { "nodeinfo",		(niarraytype), 0	},	\
	  { NULL, NULL, 0 }					\
}

/* Structure used for NGM_LISTTYPES */
struct typeinfo {
	char		type_name[NG_TYPELEN + 1];	/* name of type */
	u_int32_t	numnodes;			/* number alive */
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_TYPEINFO_INFO()		{		\
	  { "typename",		&ng_parse_typebuf_type, 0},	\
	  { "numnodes",		&ng_parse_uint32_type, 0},	\
	  { NULL, NULL, 0 }					\
}

struct typelist {
	u_int32_t	numtypes;
	struct typeinfo	typeinfo[];
};

/* Keep this in sync with the above structure definition */
#define NG_GENERIC_TYPELIST_INFO(tiarraytype)	{		\
	  { "numtypes",		&ng_parse_uint32_type, 0},	\
	  { "typeinfo",		(tiarraytype), 0	},	\
	  { NULL, NULL, 0 }					\
}

struct htable_fields {
	u_int32_t size;
	u_int32_t nb_elt;
	u_int32_t more_than_10;
	u_int32_t more_than_5;
	u_int32_t more_than_2;
	u_int32_t more_than_1;
	u_int32_t max;
	u_int32_t non_empty_average;
};

#define NG_GENERIC_HTABLE_FIELDS_INFO() {				\
		{ "size", &ng_parse_uint32_type, 0 },			\
		{ "nb_elt", &ng_parse_uint32_type, 0 },			\
		{ "more_than_10", &ng_parse_uint32_type, 0 },		\
		{ "more_than_5", &ng_parse_uint32_type, 0 },		\
		{ "more_than_2", &ng_parse_uint32_type, 0 },		\
		{ "more_than_1", &ng_parse_uint32_type, 0 },		\
		{ "max", &ng_parse_uint32_type, 0 },			\
		{ "non_empty_average", &ng_parse_uint32_type, 0 },	\
		{ NULL, NULL, 0 }					\
}

struct showhtables {
	struct htable_fields namenodes;
	struct htable_fields idnodes;
	struct htable_fields namehooks;
};

#define NG_GENERIC_SHOWHTABLES_INFO(htable_type) {	\
		{ "namenodes", (htable_type), 0 },	\
		{ "idnodes", (htable_type), 0 },	\
		{ "namehooks", (htable_type), 0 },	\
		{ NULL, NULL, 0 }			\
}

/*
 * For netgraph nodes that are somehow associated with file descriptors
 * (e.g., a device that has a /dev entry and is also a netgraph node),
 * we define a generic ioctl for requesting the corresponding nodeinfo
 * structure and for assigning a name (if there isn't one already).
 *
 * For these to you need to also #include <sys/ioccom.h>.
 */

#define NGIOCGINFO	_IOR('N', 40, struct nodeinfo)	/* get node info */
#define NGIOCSETNAME	_IOW('N', 41, struct ngm_name)	/* set node name */

#define NG_OPT_METADATA		1	/* struct meta_header +
					 * N x (struct meta_field_header + data) */
#define NG_OPT_MARK		2	/* set skb->mark (uint32_t) */

struct meta_header {
	u_int32_t len;		/* total len of data excluding this field */
	char      options[];	/* data starts here */
};

struct meta_field_header {
	u_int32_t cookie;	/* cookie for the field. Skip fields you don't
				 * know about (same cookie as in messgaes) */
	u_int16_t  type;	/* field ID */
	u_int16_t  len;		/* total len of this field including extra
				 * data */
	char	data[];		/* data starts here */
};

#ifdef _KERNEL

/*
 * set VNB_WITH_MSG_POST to 1 to configure the support of asynchronous
 * posted messages.
 */
#define VNB_WITH_MSG_POST 0

/*
 * Allocate and initialize a netgraph message "msg" with "len"
 * extra bytes of argument. Sets "msg" to NULL if fails.
 * Does not initialize token.
 */
#if VNB_WITH_MSG_POST
/*
 * To enable NG control messages to be asynchronously sent by a NG nodes
 * data path functions through the new "ng_post_msg" introduced for this
 * purpose, extra space must be allocated at the end of the message data
 * buffer for a "ng_defer_msg" structure, with needed alignment padding bytes.
 * The "ng_defer_msg" data structure is used t temporarily record the message
 * into a pending FIFO list while the global NG control lock is hold.
 */
struct ng_post_msg {
	struct ng_mesg *next_mesg; /* in pending list */
	ng_ID_t        node_id;    /* of message's destination node */
};

#define NG_MESG_TO_POST_MSG(ng_m) \
	(struct ng_post_msg*) ((char*) ng_m +			  \
			       sizeof(struct ng_mesg) + ng_m->header.arglen + \
			       (sizeof(struct ng_mesg) + ng_m->header.arglen + sizeof(void*) - 1) / sizeof(void*))

#define NG_MKMESSAGE(msg, cookie, cmdid, len, how)			\
	do {								\
	  int p_len = (len) + sizeof(void*) - 1 + sizeof(ng_post_msg);	\
	  if (sizeof(struct ng_mesg) + p_len > 65535) {			\
	    msg = NULL;							\
	    break;							\
	  }								\
	  MALLOC((msg), struct ng_mesg *, sizeof(struct ng_mesg)	\
		 + p_len, M_NETGRAPH, (how));				\
	  if ((msg) == NULL)						\
	    break;							\
	  bzero((msg), sizeof(struct ng_mesg) + (len));			\
	  (msg)->header.version = NG_VERSION;				\
	  (msg)->header.typecookie = (cookie);				\
	  (msg)->header.cmd = (cmdid);					\
	  (msg)->header.arglen = (len);					\
	  strncpy((msg)->header.cmdstr, #cmdid,				\
	    sizeof((msg)->header.cmdstr) - 1);				\
	} while (0)
#else
#define NG_MKMESSAGE(msg, cookie, cmdid, len, how)			\
	do {								\
	  if (sizeof(struct ng_mesg) + len > 65535) {			\
	    msg = NULL;							\
	    break;							\
	  }								\
	  MALLOC((msg), struct ng_mesg *, sizeof(struct ng_mesg)	\
		 + len, M_NETGRAPH, (how));				\
	  if ((msg) == NULL)						\
	    break;							\
	  bzero((msg), sizeof(struct ng_mesg) + (len));			\
	  (msg)->header.version = NG_VERSION;				\
	  (msg)->header.typecookie = (cookie);				\
	  (msg)->header.cmd = (cmdid);					\
	  (msg)->header.arglen = (len);					\
	  strncpy((msg)->header.cmdstr, #cmdid,				\
	    sizeof((msg)->header.cmdstr) - 1);				\
	} while (0)
#endif /* VNB_WITH_MSG_POST */

/*
 * Allocate and initialize a response "rsp" to a message "msg"
 * with "len" extra bytes of argument. Sets "rsp" to NULL if fails.
 */
#define NG_MKRESPONSE(rsp, msg, len, how)				\
	do {								\
	  if (sizeof(struct ng_mesg) + len > 65535) {			\
	    rsp = NULL;							\
	    break;							\
	  }								\
	  MALLOC((rsp), struct ng_mesg *, sizeof(struct ng_mesg)	\
	    + (len), M_NETGRAPH, (how));				\
	  if ((rsp) == NULL)						\
	    break;							\
	  bzero((rsp), sizeof(struct ng_mesg) + (len));			\
	  (rsp)->header.version = NG_VERSION;				\
	  (rsp)->header.arglen = (len);					\
	  (rsp)->header.token = (msg)->header.token;			\
	  (rsp)->header.typecookie = (msg)->header.typecookie;		\
	  (rsp)->header.cmd = (msg)->header.cmd;			\
	  bcopy((msg)->header.cmdstr, (rsp)->header.cmdstr,		\
	    sizeof((rsp)->header.cmdstr));				\
	  (rsp)->header.flags |= NGF_RESP;				\
	} while (0)

#endif /* _KERNEL */

#endif /* _NETGRAPH_NG_MESSAGE_H_ */

