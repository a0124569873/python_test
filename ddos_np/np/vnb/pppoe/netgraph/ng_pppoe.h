
/*
 * ng_pppoe.h
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
 * $FreeBSD: src/sys/netgraph/ng_pppoe.h,v 1.7.2.5 2002/06/17 02:19:06 brian Exp $
 * $Whistle: ng_pppoe.h,v 1.7 1999/10/16 10:16:43 julian Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */

#ifndef _NETGRAPH_PPPOE_H_
#define _NETGRAPH_PPPOE_H_

#define PPPOE_HDR_LEN 6 /* 1 + 1 + 2 + 2 (PPP ver+type, code, ses_id, len) */

/********************************************************************
 * Netgraph hook constants etc.
 ********************************************************************/
/* Node type name. This should be unique among all netgraph node types */
#define NG_PPPOE_NODE_TYPE	"pppoe"

#define NGM_PPPOE_COOKIE		939032003

/* Number of active sessions we can handle */
#define	PPPOE_NUM_SESSIONS		500 /* for now */
#define	PPPOE_SERVICE_NAME_SIZE		64 /* for now */

/* Hook names */
#define NG_PPPOE_HOOK_ETHERNET	"ethernet"
#define NG_PPPOE_HOOK_PADI	"PADI"    /* default PADI requests come here */
#define NG_PPPOE_HOOK_S_LEADIN	"service" /* PADO responses from PADI */
#define NG_PPPOE_HOOK_C_LEADIN	"client"  /* Connect message starts this */
#define NG_PPPOE_HOOK_DEBUG	"debug"

/**********************************************************************
 * Netgraph commands understood by this node type.
 * FAIL, SUCCESS, CLOSE and ACNAME are sent by the node rather than received.
 ********************************************************************/
enum cmd {
	NGM_PPPOE_SET_FLAG = 1,
	NGM_PPPOE_CONNECT  = 2,	/* Client, Try find this service */
	NGM_PPPOE_LISTEN   = 3,	/* Server, Await a request for this service */
	NGM_PPPOE_OFFER    = 4,	/* Server, hook X should respond (*) */
	NGM_PPPOE_SUCCESS  = 5,	/* State machine connected */
	NGM_PPPOE_FAIL     = 6,	/* State machine could not connect */
	NGM_PPPOE_CLOSE    = 7,	/* Session closed down */
	NGM_PPPOE_SERVICE  = 8,	/* additional Service to advertise (in PADO) */
	NGM_PPPOE_ACNAME   = 9,	/* AC_NAME for informational purposes */
	NGM_PPPOE_GET_STATUS = 10, /* data in/out */
	NGM_PPPOE_SESSIONID  = 11,  /* Session_ID for informational purposes */
	NGM_PPPOE_CLR_STATUS = 12, /* clear statistics */
	NGM_PPPOE_GETCLR_STATUS = 13, /* get statistics (data in/out) then clear 'em */
	NGM_PPPOE_SET_MACFILTER = 14, /* configure filtering on src MAC address */
	NGM_PPPOE_GET_MACFILTER = 15, /* get current MAC filter conf */
};

/***********************
 * Structures passed in the various netgraph command messages.
 ***********************/
/* This structure is returned by the NGM_PPPOE_GET_STATUS command */
struct ngpppoestat {
	u_int64_t   packets_in;	/* packets in from ethernet */
	u_int64_t   packets_out;	/* packets out towards ethernet */
	u_int64_t   packets_exc;	/* exceptions FP to CP */
	u_int64_t   sessp_malloc;	/* number of malloc'ed sessp structs */
	u_int64_t   sessp_free;	/* number of free'd sessp structs */
	u_int64_t   negp_malloc;	/* number of malloc'ed sessp structs */
	u_int64_t   negp_free;	/* number of free'd sessp structs */
	u_int64_t   success_sent;	/* number of free'd sessp structs */
	u_int64_t   m_copy_fail;	/* number of failing m_copypacket */
	u_int64_t   mcopy_nb;   /* nb of use of m_copypacket */
};

/* Keep this in sync with the above structure definition */
#define NGPPPOE_STATS_TYPE_INFO { \
	  { "packets_in",	&ng_parse_uint64_type, 0 }, \
	  { "packets_out", 	&ng_parse_uint64_type, 0 }, \
	  { "packets_exc", 	&ng_parse_uint64_type, 0 }, \
	  { "sessp_malloc",	&ng_parse_uint64_type, 0 }, \
	  { "sessp_free", 	&ng_parse_uint64_type, 0 }, \
	  { "negp_malloc", 	&ng_parse_uint64_type, 0 }, \
	  { "negp_free", 	&ng_parse_uint64_type, 0 }, \
	  { "success_sent", 	&ng_parse_uint64_type, 0 }, \
	  { "m_copy_fail", 	&ng_parse_uint64_type, 0 }, \
	  { "mcopy_nb", 	&ng_parse_uint64_type, 0 }, \
	  { NULL, NULL, 0 } \
}

/*
 * When this structure is accepted by the NGM_PPPOE_CONNECT command :
 * The data field is MANDATORY.
 * The session sends out a PADI request for the named service.
 *
 *
 * When this structure is accepted by the NGM_PPPOE_LISTEN command.
 * If no service is given this is assumed to accept ALL PADI requests.
 * This may at some time take a regexp expression, but not yet.
 * Matching PADI requests will be passed up the named hook.
 *
 *
 * When this structure is accepted by the NGM_PPPOE_OFFER command:
 * The AC-NAme field is set from that given and a PADI
 * packet is expected to arrive from the session control daemon, on the
 * named hook. The session will then issue the appropriate PADO
 * and begin negotiation.
 */
struct ngpppoe_init_data {
	char	hook[NG_HOOKLEN + 1];	/* hook to monitor on */
	u_int16_t	data_len;		/* Length of the service name */
	char	data[];		/* init data goes here */
}__attribute__((packed));

/* Keep this in sync with the above structure definition */
#define NGPPPOE_INIT_TYPE_INFO { \
	  { "hook",	&ng_parse_hookbuf_type, 0 }, \
	  { "data_len", 	&ng_parse_uint16_type, 0 }, \
	  { NULL, NULL, 0 } \
}

/*
 * This structure is used by the asychronous success and failure messages.
 * (to report which hook has failed or connected). The message is sent
 * to whoever requested the connection. (close may use this too).
 *
 * Extension for sending back private data when the connection is OK.
 */
struct ngpppoe_sts {
	char	hook[NG_HOOKLEN + 1]; /* hook associated with event session */
	uint8_t peer_mac[VNB_ETHER_ADDR_LEN]; /* mac address for the peer */
	u_int16_t	Session_ID;
	char	repeater; /* whether the link is for a repeater or a server */
} ALIGN_ATTRIB ;

/* Keep this in sync with the above structure definition */
#define NGPPPOE_STS_TYPE_INFO { \
	  { "hook",	&ng_parse_hookbuf_type, 0 }, \
	  { "peer_mac", 	&ng_ether_enaddr_type, 0 }, \
	  { "Session_ID",	&ng_parse_uint16_type, 0 }, \
	  { NULL, NULL, 0 } \
}

/* This structure is returned by the NGM_PPPOE_SET/GET_MACFILTER commands */
struct ngpppoe_mac_filter {
	u_int8_t    mac_addr_lsb;	/* lsb value for match */
	u_int8_t    nb_valid_bits;	/* number of lsb bits to use */
};

/* Keep this in sync with the above structure definition */
#define NGPPPOE_MACF_TYPE_INFO { \
	  { "mac_addr_lsb",	&ng_parse_uint8_type, 0 }, \
	  { "nb_valid_bits", 	&ng_parse_uint8_type, 0 }, \
	  { NULL, NULL, 0 } \
}


/********************************************************************
 * Constants and definitions specific to pppoe
 ********************************************************************/

#define PPPOE_TIMEOUT_LIMIT 64
#define PPPOE_OFFER_TIMEOUT 16
#define PPPOE_INITIAL_TIMEOUT 2

/* Codes to identify message types */
#define PADI_CODE	0x09
#define PADO_CODE	0x07
#define PADR_CODE	0x19
#define PADS_CODE	0x65
#define PADT_CODE	0xa7

/* Tag identifiers */
#if VNB_BYTE_ORDER == VNB_BIG_ENDIAN
#define PTT_EOL		(0x0000)
#define PTT_SRV_NAME	(0x0101)
#define PTT_AC_NAME	(0x0102)
#define PTT_HOST_UNIQ	(0x0103)
#define PTT_AC_COOKIE	(0x0104)
#define PTT_VENDOR 	(0x0105)
#define PTT_RELAY_SID	(0x0106)
#define PTT_SRV_ERR     (0x0201)
#define PTT_SYS_ERR  	(0x0202)
#define PTT_GEN_ERR  	(0x0203)

#define ETHERTYPE_PPPOE_DISC	0x8863	/* pppoe discovery packets     */
#define ETHERTYPE_PPPOE_SESS	0x8864	/* pppoe session packets       */
#define ETHERTYPE_PPPOE_STUPID_DISC 0x3c12 /* pppoe discovery packets 3com? */
#define ETHERTYPE_PPPOE_STUPID_SESS 0x3c13 /* pppoe session packets   3com? */
#define PPPOE_SESS_LCP		0xc021	/* PPP LCP packets     */
#define PPPOE_SESS_IPCP		0x8021	/* PPP IPCP packets    */

#else
#define PTT_EOL		(0x0000)
#define PTT_SRV_NAME	(0x0101)
#define PTT_AC_NAME	(0x0201)
#define PTT_HOST_UNIQ	(0x0301)
#define PTT_AC_COOKIE	(0x0401)
#define PTT_VENDOR 	(0x0501)
#define PTT_RELAY_SID	(0x0601)
#define PTT_SRV_ERR     (0x0102)
#define PTT_SYS_ERR  	(0x0202)
#define PTT_GEN_ERR  	(0x0302)

#define ETHERTYPE_PPPOE_DISC	0x6388	/* pppoe discovery packets     */
#define ETHERTYPE_PPPOE_SESS	0x6488	/* pppoe session packets       */
#define ETHERTYPE_PPPOE_STUPID_DISC 0x123c /* pppoe discovery packets 3com? */
#define ETHERTYPE_PPPOE_STUPID_SESS 0x133c /* pppoe session packets   3com? */
#define PPPOE_SESS_LCP		0x21c0	/* PPP LCP packets     */
#define PPPOE_SESS_IPCP		0x2180	/* PPP IPCP packets    */
#endif

struct pppoe_tag {
	u_int16_t tag_type;
	u_int16_t tag_len;
}__attribute__ ((packed));

#define PPPOE_TAG_DATA(tp) (((char *)(tp)) + sizeof(struct pppoe_tag))

struct pppoe_hdr{
	unsigned int ver:4;
	unsigned int type:4;
	u_int8_t code;
	u_int16_t sid;
	u_int16_t length;
}__attribute__ ((packed));

#define PPPOE_HDR_DATA(hp)				\
	(struct pppoe_tag *)(((unsigned char *)(hp)) +	\
			     sizeof(struct pppoe_hdr))

struct pppoe_full_hdr {
	struct vnb_ether_header eh;
	struct pppoe_hdr ph;
}__attribute__ ((packed));

union	packet {
	struct pppoe_full_hdr	pkt_header;
	u_int8_t	bytes[2048];
};

struct datatag {
        struct pppoe_tag hdr;
	u_int8_t        data[PPPOE_SERVICE_NAME_SIZE];
} __attribute__((packed));


/*
 * Define the order in which we will place tags in packets
 * this may be ignored
 */
/* for PADI */
#define TAGI_SVC 0
#define TAGI_HUNIQ 1
/* for PADO */
#define TAGO_ACNAME 0
#define TAGO_SVC 1
#define TAGO_COOKIE 2
#define TAGO_HUNIQ 3
/* for PADR */
#define TAGR_SVC 0
#define TAGR_HUNIQ 1
#define TAGR_COOKIE 2
/* for PADS */
#define TAGS_ACNAME 0
#define TAGS_SVC 1
#define TAGS_COOKIE 2
#define TAGS_HUNIQ 3
/* for PADT */

#endif /* _NETGRAPH_PPPOE_H_ */

