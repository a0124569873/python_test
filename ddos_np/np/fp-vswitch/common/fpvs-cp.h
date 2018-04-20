/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef FPVS_CP_H_
#define FPVS_CP_H_

#define FPVS_FLOW_TIMEOUT_MS 5000
#ifndef FPVS_INVALID_PORT
#define FPVS_INVALID_PORT		((uint32_t)-1)
#endif

#define CMD_FPVS_BASE	0x0E0000

#define CMD_FPVS_SET	(CMD_FPVS_BASE + 1)
#define CMD_FPVS_FLOW	(CMD_FPVS_BASE + 2)
#define CMD_FPVS_PRUNE	(CMD_FPVS_BASE + 3)

#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif

struct cp_fpvs_port {
	char		ifname[IFNAMSIZ];
	uint32_t	port_id;
	uint32_t	type;
	uint16_t	tun_dstport;
};

#define CM_FPVS_FLOW_ADD	1
#define CM_FPVS_FLOW_DEL	2

#define FLOW_TNL_F_CSUM          1
#define FLOW_TNL_F_KEY           2
#define FLOW_TNL_F_DONT_FRAGMENT 4


struct cp_fpvs_flow {
	uint32_t	flags;
	uint16_t	flow_len;
	uint16_t	action_len;
	void		*data;
};

struct cp_flow_key {
	struct {
		uint64_t id;
		uint32_t src;
		uint32_t dst;
		uint16_t flags;
		uint8_t tos;
		uint8_t ttl;
	} tunnel;
	uint32_t recirc_id;
	struct {
		uint32_t ovsport;
	} l1;
	struct {
		uint8_t src[6];
		uint8_t dst[6];
		uint16_t ether_type;
		uint16_t vlan_tci;
	} l2;
	struct {
		uint32_t mpls_lse;
	} l2_5;
	struct {
		uint8_t proto;
		uint8_t tos;
		uint8_t ttl;
		uint8_t frag;
		union {
			struct {
				uint32_t src;
				uint32_t dst;
				struct {
					uint8_t sha[6];
					uint8_t tha[6];
				} arp;
			} ip;
			struct {
				uint32_t src[4];
				uint32_t dst[4];
				uint32_t label;
				struct {
					uint32_t target[4];
					uint8_t sll[6];
					uint8_t tll[6];
				} ndp;
			} ip6;
		};
	} l3;
	struct {
		uint16_t sport;
		uint16_t dport;
		uint16_t flags;
	} l4;
};

#endif /* FPVS_CP_H_ */
