/*
 * Copyright(c) 2007 6WIND
 * $Id: netfpc_var.h,v 1.9 2010-06-08 15:08:29 guerin Exp $
 */
#ifndef _NETFPC_VAR_H_
#define _NETFPC_VAR_H_

struct netfpc_hdr {
	uint16_t type;
	uint16_t len;
	char data[0];
} __attribute__ ((packed));

#define NETFPC_HDRSIZE sizeof(struct netfpc_hdr)
#define IPPROTO_NETFPC 142

#define NETFPC_MSGTYPE_VNB_RESET 0
#define NETFPC_MSGTYPE_VNB 1
#define NETFPC_MSGTYPE_VNBDATA 2
#define NETFPC_MSGTYPE_NEWIF 3
#define NETFPC_MSGTYPE_DELIF 4
#define NETFPC_MSGTYPE_REPLAYWIN 5
#define NETFPC_MSGTYPE_TC 6
#define NETFPC_MSGTYPE_EQOS 7
#define NETFPC_MSGTYPE_REPLAYWIN6 8
#define NETFPC_MSGTYPE_FPDEBUG 9
#define NETFPC_MSGTYPE_ACK 10
#define NETFPC_MSGTYPE_VNBDUMP 11
#define NETFPC_MSGTYPE_GR_START 12
#define NETFPC_MSGTYPE_SET_MTU 13
#define NETFPC_MSGTYPE_SET_MAC 14
#define NETFPC_MSGTYPE_SET_FLAGS 15
#define NETFPC_MSGTYPE_RPC_CLIENT 16

/* for NETFPC_MSGTYPE_NEWIF and NETFPC_MSGTYPE_DELIF messages */
struct netfpc_if_msg {
	uint32_t ifuid;
	union {
		uint32_t vnb_nodeid;
		uint8_t vnb_keep_node;
	};
	int32_t error;
} __attribute__ ((packed));

struct netfpc_tc {
	uint32_t type;
#define NETFPC_TC_SET_PARAMS  0
#define NETFPC_TC_GET_PARAMS  1
#define NETFPC_TC_GET_STATS   2
#define NETFPC_TC_RESET_STATS 3
	int32_t error;
#define NETFPC_TC_ERROR_INVALID_CMD   1
#define NETFPC_TC_ERROR_INVALID_PARAM 2
#define NETFPC_TC_ERROR_TRUNCATED     3
	uint32_t id;
#define NETFPC_TC_ID_ALL 0xFFFFFFFF
};

/* keep it sync with cp_vnb_dump_attr structure in fpc.h */
struct netfpc_vnbdump_attr {
	uint32_t type;
	uint32_t len;
	char data[0];
};

struct netfpc_vnbdump_msg {
	uint32_t attr_count;
	uint32_t len;
};

struct netfpc_tc_params {
	uint32_t flags;
#define NETFPC_TC_F_BYTE_POLICING 0x1
#define NETFPC_TC_F_COLOR_AWARE   0x2

	uint64_t cir;   /* Committed Information Rate */
	uint64_t eir;   /* Excess Information Rate */
	uint32_t cbs;   /* Committed Burst Size */
	uint32_t ebs;   /* Excess Burst Size */
};

struct netfpc_tc_stats {
	uint64_t green_packets;
	uint64_t green_bytes;
	uint64_t yellow_packets;
	uint64_t yellow_bytes;
	uint64_t red_packets;
	uint64_t red_bytes;
};

struct netfpc_eqos {
	uint32_t type;
#define NETFPC_EQOS_GET_STATS    0
#define NETFPC_EQOS_RESET_STATS  1
#define NETFPC_EQOS_GET_PARAMS	 2
	int32_t error;
#define NETFPC_EQOS_ERROR_INVALID_CMD   1
#define NETFPC_EQOS_ERROR_INVALID_PARAM 2
#define NETFPC_EQOS_ERROR_TRUNCATED     3
	uint16_t queue_id;
	uint8_t queue_idx;
	uint8_t port_id;
#define NETFPC_EQOS_QUEUEID_ALL 0xFFFF
#define NETFPC_EQOS_PORTID_ALL 0xFF
} __attribute__ ((packed));

struct netfpc_eqos_stats {
	uint16_t queue_id;
	uint8_t  port_id;
	uint8_t  queue_idx;
	uint32_t currentQueueLength;
	uint32_t highestQueueLength;
	uint32_t discardPacketsG;
	uint32_t discardPacketsY;
	uint32_t discardPacketsR;
	uint64_t discardBytesG;
	uint64_t discardBytesY;
	uint64_t discardBytesR;
} __attribute__ ((packed));

struct netfpc_eqos_params {
	uint16_t queue_id;
	uint8_t  port_id;
	uint8_t  queue_idx;
	uint8_t  discardAlgorithm;
#define NETFPC_EQOS_DISC_TAILDROP  0
#define NETFPC_EQOS_DISC_WRED      1
#define NETFPC_EQOS_DISC_NONE      2

	union {
		/*
		 * WRED Params:
		 *   DP0 is the Green traffic
		 *   DP1 is the Yellow traffic
		 *   DP2 is the Red traffic
		 */
		struct {
			uint32_t dpGmin;   /* min threshold  for DP0 */
			uint32_t dpGmax;   /* max threshhold for DP0 */
			uint32_t dpGprob;  /* drop probability in DP0 range */
			uint32_t dpYmin;   /* min threshhold for DP1 */
			uint32_t dpYmax;   /* max threshhold for DP1 */
			uint32_t dpYprob;  /* drop probability in DP1 range */
			uint32_t dpRmin;   /* min threshhold for DP2 */
			uint32_t dpRmax;   /* max threshhold for DP2 */
			uint32_t dpRprob;  /* drop probability in DP2 range */
			uint32_t movingAverage; /* forgetting factor */
		} red;

		/* TailDrop Params */
		struct {
			uint32_t dpGmax;    /* discard threshhold in bytes for DP0 */
			uint32_t dpYmax;    /* discard threshhold in bytes for DP1 */
			uint32_t dpRmax;    /* discard threshhold in bytes for DP2 */
		} taildrop;
	} ud;
} __attribute__ ((packed));

/* for NETFPC_MSGTYPE_ACK messages */
struct netfpc_ack_msg {
	int32_t error;
} __attribute__ ((packed));

/* for NETFPC_MSGTYPE_SET_MTU messages */
struct netfpc_mtu_msg {
	uint32_t ifuid;
	uint32_t mtu;
	int32_t error;
} __attribute__ ((packed));

/* for NETFPC_MSGTYPE_SET_MAC messages */
struct netfpc_mac_msg {
	uint32_t ifuid;
	int32_t error;
	uint8_t mac[6];
} __attribute__ ((packed));

/* for NETFPC_MSGTYPE_SET_FLAGS messages */
struct netfpc_flags_msg {
	uint32_t ifuid;
	int32_t error;
	uint32_t flags;
} __attribute__ ((packed));

#define NETFPC_RPC_ADD_CLIENT 0
#define NETFPC_RPC_DEL_CLIENT 1
struct netfpc_rpc_msg {
	uint8_t cmd;
	char shmem_name[64];
} __attribute__ ((packed));
#endif
