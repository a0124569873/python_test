/*
 * Copyright (c) 2007 6WIND
 */

#ifndef __FP_NETFILTER_H__
#define __FP_NETFILTER_H__

#ifdef FP_NF_STATS_PER_CORE
#define FP_NF_STATS_INC(st, field)          FP_STATS_PERCORE_INC(st, field)
#define FP_NF_STATS_ADD(st, field, val)     FP_STATS_PERCORE_ADD(st, field, val)
#define FP_NF_STATS_NUM                     FPN_MAX_CORES
#else
#define FP_NF_STATS_INC(st, field)          FP_STATS_INC(st, field)
#define FP_NF_STATS_ADD(st, field, val)     FP_STATS_ADD(st, field, val)
#define FP_NF_STATS_NUM                     1
#endif

#ifdef CONFIG_MCORE_NF_TABLE_PER_VR
#define FP_NF_MAX_VR  FP_MAX_VR
#else
#define FP_NF_MAX_VR  1
#endif

/* #define FP_DEBUG_NF_TABLE_NAT 1 */

#define FP_NF_TABLE_FILTER          0
#define FP_NF_TABLE_MANGLE          1
#define FP_NF_TABLE_NAT             2
#define FP_NF_TABLE_NUM             3
#define FP_NF6_TABLE_NUM            2

/* used as a flag in nf_conf */
#define FP_NF_FLAG_FORCE_NAT_CONNTRACK (FP_NF_TABLE_NUM+0)
/* #define FP_NF_FLAG_xxx              (FP_NF_TABLE_NUM+1) */

/* Maximum number of netfilter rules in shared memory. */
#ifdef CONFIG_MCORE_NF_MAXRULES
#define FP_NF_MAXRULES               CONFIG_MCORE_NF_MAXRULES
#else
#define FP_NF_MAXRULES               3072
#endif

#define FP_NF_MAXNAMELEN             32

/* IP Hooks */
#define FP_NF_IP_PRE_ROUTING         0
#define FP_NF_IP_LOCAL_IN            1
#define FP_NF_IP_FORWARD             2
#define FP_NF_IP_LOCAL_OUT           3
#define FP_NF_IP_POST_ROUTING        4
#define FP_NF_IP_NUMHOOKS            5

#define FP_NF_FILTER_TABLE           "filter"
#define FP_NF_MANGLE_TABLE           "mangle"
#define FP_NF_NAT_TABLE              "nat"

#define FP_NF_STANDARD_TARGET         ""
#define FP_NF_ERROR_TARGET            "ERROR"

/* Responses from hook functions. */
#define FP_NF_CONTINUE               -2
#define FP_NF_EXCEPTION              -1
#define FP_NF_DROP                    0
#define FP_NF_ACCEPT                  1
#define FP_NF_STOLEN                  2
#define FP_NF_QUEUE                   3
#define FP_NF_REPEAT                  4
#define FP_NF_STOP                    5
#define FP_NF_MAX_VERDICT             FP_NF_STOP

/* for each hook, we have a bitfield for each enabled table */
typedef struct {
	uint64_t enabled_hook[FP_NF_MAX_VR][FP_NF_IP_NUMHOOKS];
} fp_nf_conf_t;

typedef struct fp_nfrule_stats_s {
	uint64_t pcnt;                  /* Packet counter */
	uint64_t bcnt;                  /* Byte counters */
} __fpn_cache_aligned fp_nfrule_stats_t;

struct fp_nfrule {
	uint32_t uid;
	struct {
#define FP_NF_TARGET_TYPE_STANDARD    1
#define FP_NF_TARGET_TYPE_ERROR       2
#define FP_NF_TARGET_TYPE_MARK_V2     3
#define FP_NF_TARGET_TYPE_DSCP        4
#define FP_NF_TARGET_TYPE_REJECT      5
#define FP_NF_TARGET_TYPE_LOG         6
#define FP_NF_TARGET_TYPE_ULOG        7
#define FP_NF_TARGET_TYPE_SNAT        8
#define FP_NF_TARGET_TYPE_DNAT        9		
#define FP_NF_TARGET_TYPE_MASQUERADE 10
#define FP_NF_TARGET_TYPE_TCPMSS     11
#define FP_NF_TARGET_TYPE_DEV        12
#define FP_NF_TARGET_TYPE_CHECKSUM   13
		uint8_t type;
		union {
			struct {
#define FP_NF_IPT_RETURN              (-FP_NF_REPEAT - 1)
				int verdict;
			} standard;
#define FP_NF_ERRORNAME 0
#if FP_NF_ERRORNAME
			struct {
				char errorname[FP_NF_MAXNAMELEN];
			} error;
#endif
			struct {
				uint32_t mark;
				uint32_t mask;
			} mark;
			struct {
				uint8_t dscp;
			} dscp;
#ifdef FP_DEBUG_NF_TABLE_NAT
			struct {
				uint32_t min_ip;
				uint32_t max_ip;

				uint16_t min_port;
				uint16_t max_port;
			} nat;
#endif /* FP_DEBUG_NF_TABLE_NAT */
			struct {
#define FP_NF_DEV_FLAG_SET_MARK      0x01
				uint32_t flags;
				uint32_t mark;
				uint32_t ifname_len;
				uint32_t ifname_hash;
				char ifname[FP_IFNAMSIZ];
			} dev;
		} data;
	} target;

	union {
		struct {
			uint32_t src;                            /* Source IP addr */
			uint32_t dst;                            /* Destination IP addr */
			uint32_t smsk;                           /* Mask for src IP addr */
			uint32_t dmsk;                           /* Mask for dest IP addr */
			char iniface[FP_IFNAMSIZ];
			uint8_t iniface_len;
			char outiface[FP_IFNAMSIZ];
			uint8_t outiface_len;
			uint16_t proto;                          /* Protocol, 0 = ANY */
#define FP_NF_IPT_F_FRAG              0x01                       /* Set if rule is a fragment rule */
#define FP_NF_IPT_F_GOTO              0x02                       /* Set if jump is a goto */
#define FP_NF_IPT_F_MASK              0x03                       /* All possible flag bits mask. */
			uint8_t flags;
#define FP_NF_IPT_INV_VIA_IN          0x01                       /* Invert the sense of IN IFACE. */
#define FP_NF_IPT_INV_VIA_OUT         0x02                       /* Invert the sense of OUT IFACE */
#define FP_NF_IPT_INV_TOS             0x04                       /* Invert the sense of TOS. */
#define FP_NF_IPT_INV_SRCIP           0x08                       /* Invert the sense of SRC IP. */
#define FP_NF_IPT_INV_DSTIP           0x10                       /* Invert the sense of DST IP. */
#define FP_NF_IPT_INV_FRAG            0x20                       /* Invert the sense of FRAG. */
#define FP_NF_IPT_INV_PROTO           0x40                       /* Invert the sense of PROTO. */
#define FP_NF_IPT_INV_MASK            0x7F                       /* All possible flag bits mask. */
			uint8_t invflags;
		} ipv4;
	} l2;

	struct {
#define FP_NF_l2OPT_DSCP              0x01
#define FP_NF_l2OPT_RATELIMIT         0x02
#define FP_NF_l2OPT_FRAG              0x04                       /* only for IPv6 */
#define FP_NF_l2OPT_MARK              0x08
#define FP_NF_l2OPT_RPFILTER          0x10
#define FP_NF_l2OPT_MAC               0x20
#define FP_NF_l2OPT_PHYSDEV           0x40
		uint8_t opt;
		uint8_t dscp;                                    /* DSCP word */
		uint8_t invdscp;                                 /* Inverse DSCP */
#define FP_NF_VRFID_UNSPECIFIED       0xFFFF
		uint16_t vrfid;					 /* VRF ID */
#define FP_NF_RPF_LOOSE               0x01
#define FP_NF_RPF_VALID_MARK          0x02
#define FP_NF_RPF_ACCEPT_LOCAL        0x04
#define FP_NF_RPF_INVERT              0x08
		uint8_t rpf_flags;
		struct {
			uint32_t credit;
			uint32_t credit_cap;
			uint32_t cost;
			uint64_t prev;
		} rateinfo;
		struct {
			uint32_t mark;
			uint32_t mask;
			uint8_t invert;
		} mark;
		struct {
			unsigned char srcaddr[6];
			int invert;
		} mac;
		struct {
			char    physindev[FP_IFNAMSIZ];
			uint8_t physindev_len;
			char    physoutdev[FP_IFNAMSIZ];
			uint8_t physoutdev_len;
#define FP_XT_PHYSDEV_OP_IN           0x01
#define FP_XT_PHYSDEV_OP_OUT          0x02
#define FP_XT_PHYSDEV_OP_BRIDGED      0x04
#define FP_XT_PHYSDEV_OP_ISIN         0x08
#define FP_XT_PHYSDEV_OP_ISOUT        0x10
#define FP_XT_PHYSDEV_OP_MASK         (0x20 - 1)
			uint8_t	invert;
			uint8_t	bitmask;
		} physdev;
	} l2_opt;

	struct {
#define FP_NF_L3_TYPE_NONE            0
#define FP_NF_L3_TYPE_UDP             1
#define FP_NF_L3_TYPE_TCP             2
#define FP_NF_L3_TYPE_ICMP            3
#define FP_NF_L3_TYPE_SCTP            4
		uint8_t type;
		union {
			struct {
				uint16_t spts[2];                /* Source port range. */
				uint16_t dpts[2];                /* Destination port range. */
#define FP_NF_IPT_UDP_INV_SRCPT       0x01                       /* Invert the sense of source ports. */
#define FP_NF_IPT_UDP_INV_DSTPT       0x02                       /* Invert the sense of dest ports. */
#define FP_NF_IPT_UDP_INV_MASK        0x03                       /* All possible flags. */
				uint8_t invflags;
			} udp;

			struct {
				uint16_t spts[2];                /* Source port range. */
				uint16_t dpts[2];                /* Destination port range. */
				uint8_t option;                  /* TCP Option iff non-zero*/
				uint8_t flg_mask;                /* TCP flags mask byte */
				uint8_t flg_cmp;                 /* TCP flags compare byte */
#define FP_NF_IPT_TCP_INV_SRCPT       0x01                       /* Invert the sense of source ports. */
#define FP_NF_IPT_TCP_INV_DSTPT       0x02                       /* Invert the sense of dest ports. */
#define FP_NF_IPT_TCP_INV_FLAGS       0x04                       /* Invert the sense of TCP flags. */
#define FP_NF_IPT_TCP_INV_OPTION      0x08                       /* Invert the sense of option test. */
#define FP_NF_IPT_TCP_INV_MASK        0x0F                       /* All possible flags. */
				uint8_t invflags;
			} tcp;

		        struct {
				uint16_t spts[2];
				uint16_t dpts[2];
				/* Bit mask of chunks to be matched according to RFC 2960 */
#define FP_NF_SCTP_CHUNKMAP_SIZE      256
				uint32_t chunkmap[FP_NF_SCTP_CHUNKMAP_SIZE / (sizeof(uint32_t) * 8)];
#define FP_NF_SCTP_CHUNK_MATCH_ANY    0x01                       /* Match if any of the chunk types are present */
#define FP_NF_SCTP_CHUNK_MATCH_ALL    0x02                       /* Match if all of the chunk types are present */
#define FP_NF_SCTP_CHUNK_MATCH_ONLY   0x04                       /* Match if these are the only chunk types present */
				uint32_t chunk_match_type;
#define FP_NF_IPT_NUM_SCTP_FLAGS      4
				struct {
					uint8_t chunktype;
					uint8_t flag;
					uint8_t flag_mask;
				} flag_info[FP_NF_IPT_NUM_SCTP_FLAGS];
#define FP_NF_IPT_SCTP_SRC_PORTS      0x01
#define FP_NF_IPT_SCTP_DEST_PORTS     0x02
#define FP_NF_IPT_SCTP_CHUNK_TYPES    0x04
				uint32_t flags;
				uint32_t invflags;

				uint8_t flag_count;
			} sctp;

			struct {
				uint8_t type;                    /* Type to match */
				uint8_t code[2];                 /* Range of code */
#define FP_NF_IPT_ICMP_INV            0x01                       /* Invert the sense of type/code test */
				uint8_t invflags;
			} icmp;
		} data;
#define FP_NF_L3_STATE_ESTABLISHED	1
#define FP_NF_L3_STATE_EXCEPTION	2
		uint8_t state;                                   /* state of the flow */
	} l3;

	struct {
#define FP_NF_l3OPT_MULTIPORT       0x01
#define FP_NF_l3OPT_IPRANGE       	  0x02
		u_int8_t opt;
		struct fp_nfrule_multiport {
#define FP_NF_MULTIPORT_FLAG_SRC 1
#define FP_NF_MULTIPORT_FLAG_DST 2
#define FP_NF_MULTIPORT_FLAG_ANY 3
			u_int8_t flags;                            /* Type of comparison */
			u_int8_t count;                            /* Number of ports */
#define FP_NF_MULTIPORT_SIZE 15
			u_int16_t ports[FP_NF_MULTIPORT_SIZE];     /* Ports */
			u_int8_t pflags[FP_NF_MULTIPORT_SIZE];     /* Port flags */
			u_int8_t invert;                           /* Invert flag */
		} multiport;
		struct fp_nfrule_iprange{
			union  {
				uint32_t		all[4];
				uint32_t		ip;
				uint32_t		ip6[4];
				struct fp_in_addr	in;
				struct fp_in6_addr	in6;
			}src_min, src_max, dst_min, dst_max;
			uint8_t flags;
		}iprange;	
	} l3_opt;

	fp_nfrule_stats_t stats[FP_NF_STATS_NUM];
	//veda_ddos iptables dispatch use
	uint32_t dispatch;
	uint32_t syns;
	uint32_t speed;

	/*string match information*/
	#define FP_NF_STRING_MAX_ALGO_NAME_SIZE 16	
	#define FP_NF_STRING_MAX_PATTERN_SIZE 128
	#define FP_NF_OPT_STRING           0x01
	struct fp_nfrule_string{
		u_int8_t opt;
		struct {
			u_int16_t  from_offset;
			u_int16_t  to_offset;
			u_int8_t	  algo[FP_NF_STRING_MAX_ALGO_NAME_SIZE];
			u_int8_t 	  pattern[FP_NF_STRING_MAX_PATTERN_SIZE];
			u_int8_t  patlen;
			union {
				struct {
					u_int8_t  invert;
				} v0;

				struct {
					u_int8_t  flags;
				} v1;
			} u;
		} string;
	} string_opt;

};

typedef struct fp_nftable {
#ifdef CONFIG_MCORE_NFTABLE_SEQNUM
	uint32_t         fpnftable_seqnum;
#endif
	uint32_t         fpnftable_rules_count;
	uint32_t         fpnftable_valid_hooks;                   /* What hooks you will enter in */
	uint32_t         fpnftable_hook_entry[FP_NF_IP_NUMHOOKS]; /* Hook entry points */
	uint32_t         fpnftable_underflow[FP_NF_IP_NUMHOOKS];  /* Underflow points */
} fp_nftable_t;


/* Fast Path tuple hash order for conntracks. */
#ifdef CONFIG_MCORE_NF_CT_HASH_ORDER
#define FP_NF_CT_HASH_ORDER CONFIG_MCORE_NF_CT_HASH_ORDER
#else
#define FP_NF_CT_HASH_ORDER   16
#endif
#define FP_NF_CT_HASH_SIZE    (1<<FP_NF_CT_HASH_ORDER)

/* Maximum number of conntrack entries in fastpath. */
#ifdef CONFIG_MCORE_NF_CT_MAX
#define FP_NF_CT_MAX       CONFIG_MCORE_NF_CT_MAX
#else
#define FP_NF_CT_MAX       1024
#endif

#ifdef CONFIG_MCORE_NF_CT_CPEID
#ifdef CONFIG_MCORE_NF_CT_HASH_CPEID_ORDER
#define FP_NF_CT_HASH_CPEID_ORDER CONFIG_MCORE_NF_CT_HASH_CPEID_ORDER
#else
#define FP_NF_CT_HASH_CPEID_ORDER   16
#endif
#define FP_NF_CT_HASH_CPEID_SIZE    (1<<FP_NF_CT_HASH_CPEID_ORDER)
#endif

enum fp_nf_ip_conntrack_dir
{
	FP_NF_IP_CT_DIR_ORIGINAL = 0,
	FP_NF_IP_CT_DIR_REPLY,
	FP_NF_IP_CT_DIR_MAX
};

struct fp_nfct_stats {
#ifdef CONFIG_MCORE_NF_CT_BYTES
	uint32_t bytes;
#endif
	uint32_t packets;
	uint64_t			   start_time;		//the first packet in this dir direction
	uint64_t			   pre_time;
};

union fp_nfct_tuple_id {
	uint32_t u32;
	struct {
		uint32_t     index:31,
			     dir:1;
	} s;
};

#ifdef CONFIG_MCORE_NF_CT_CPEID
#define FP_NF_CT_HASH_PREV_CPEID(entry) \
	((uint32_t) (((entry).tuple[FP_NF_IP_CT_DIR_ORIGINAL].half_hash_prev_cpeid << 16) + \
		     (entry).tuple[FP_NF_IP_CT_DIR_REPLY].half_hash_prev_cpeid))

#define FP_NF_CT_SET_HASH_PREV_CPEID(entry, index) {			\
		(entry).tuple[FP_NF_IP_CT_DIR_ORIGINAL].half_hash_prev_cpeid =  (uint16_t) (index >> 16); \
		(entry).tuple[FP_NF_IP_CT_DIR_REPLY].half_hash_prev_cpeid = (uint16_t) (index & 0x0000FFFF); \
	}
#endif

struct fp_nfct_tuple_h {
	uint32_t               src;
	uint32_t               dst;
	uint16_t               sport;
	uint16_t               dport;
#ifdef CONFIG_MCORE_VRF
	uint16_t               vrfid;
#endif
	uint8_t                proto;
	uint8_t                dir;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	/*
	 * Due to memory constraints, we need this entry to optimize the usage
	 * of the RAM when millions of active sessions are used
	 */
	uint16_t               half_hash_prev_cpeid;
#endif
	union fp_nfct_tuple_id hash_next;
};

struct fp_nfct_entry {
	struct fp_nfct_tuple_h tuple[FP_NF_IP_CT_DIR_MAX]; /* MUST BE the first field */
	union {
		uint32_t               next_available;
		uint32_t               uid;
	};
#ifdef CONFIG_MCORE_NF_CT_CPEID
	uint32_t               hash_next_cpeid;
#endif
	uint8_t                flag;
#define FP_NFCT_FLAG_VALID      0x01
#define FP_NFCT_FLAG_UPDATE     0x02
#define FP_NFCT_FLAG_SNAT       0x04
#define FP_NFCT_FLAG_DNAT       0x08
#define FP_NFCT_FLAG_ASSURED    0x10
#define FP_NFCT_FLAG_FROM_CPE   0x20
#define FP_NFCT_FLAG_TO_CPE     0x40
#define FP_NFCT_FLAG_END        0x80
	struct fp_nfct_stats   counters[FP_NF_IP_CT_DIR_MAX];
};

typedef struct fp_nfct {
	uint32_t               fp_nfct_count;
	/* This is used to remember from where to start from when looking
	   for a free entry in conntrack table */
	uint32_t               next_ct_available;
#ifdef CONFIG_MCORE_NF_CT_CPEID
	uint32_t               fp_nfct_hash_cpeid[FP_NF_CT_HASH_CPEID_SIZE];
#endif
	union fp_nfct_tuple_id fp_nfct_hash[FP_NF_CT_HASH_SIZE];
	struct fp_nfct_entry   fp_nfct[FP_NF_CT_MAX];
} fp_nfct_t;


#if defined(CONFIG_MCORE_NETFILTER_CACHE) || defined(CONFIG_MCORE_NETFILTER_IPV6_CACHE)

/* number of cache elements in fp_shared */
#ifdef CONFIG_MCORE_NF_MAX_CACHE_ORDER
#define FP_NF_MAX_CACHE_ORDER        CONFIG_MCORE_NF_MAX_CACHE_ORDER
#else
#define FP_NF_MAX_CACHE_ORDER        14
#endif

#define FP_NF_MAX_CACHE_SIZE         (1 << FP_NF_MAX_CACHE_ORDER)
#define FP_NF_MAX_CACHE_MASK         (FP_NF_MAX_CACHE_SIZE-1)

/* sizeof stored headers starting at IP layer, in bytes. The value is
 * defined in order to have sizeof(fp_nf_rule_cache_entry_t) == 64 */
#define FP_NF_CACHED_HDR_LEN_32     9  /* 9 words = 36 bytes */

#define FP_NF_CACHE_STATE_FREE       0 /* not used */
#define FP_NF_CACHE_STATE_USED       1 /* correctly filled */

/* size is 28 + FP_NF_CACHED_HDR_LEN */
typedef struct fp_nf_rule_cache_entry {
	uint32_t next;          /* next idx if chained (used in hash table) */
	uint8_t hdr_len32;      /* len of stored headers (in 32 bits words) */
	uint8_t hook_num;
	uint8_t table_num;
#define FP_NF_CACHE_FLAG_DIRECT_ACCEPT  0x01  /* standart target accept and only one rule in the cache */
#define FP_NF_CACHE_FLAG_IN_HASH_TABLE  0x02
#define FP_NF_CACHE_FLAG_MORE_RULES     0x04
	uint8_t flags;    /* offset of this field MUST be keep in sync
	                     with fp_nf_rule_cache_extended_entry_t */
	fpn_uintptr_t rule __attribute__ ((aligned(8))); /* associated rule, pointer is only valid in FP */
	uint32_t in_ifuid;    /* 0 if not available */
	uint32_t out_ifuid;   /* 0 if not available */

	uint16_t vrid;
	uint8_t ct_state;       /* conntrack state if needed */
	uint8_t state;          /* FREE or USED */

	uint32_t hdr[FP_NF_CACHED_HDR_LEN_32]; /* store the masked packet */
} fp_nf_rule_cache_entry_t;

#define FP_NF_MAX_CACHED_RULES  (((sizeof(fp_nf_rule_cache_entry_t) - 8) / sizeof(fpn_uintptr_t)) + 1)
typedef struct fp_nf_rule_cache_extended_entry {
	fp_nf_rule_cache_entry_t base;
	uint8_t ext_pad[6];
	uint8_t ext_nbrules;
	uint8_t ext_flags;    /* this MUST have the same offset as in base structure */
	fpn_uintptr_t ext_rule[FP_NF_MAX_CACHED_RULES - 1];
} fp_nf_rule_cache_extended_entry_t;

/* the start of the structures have to stay synchronized */
typedef fp_nf_rule_cache_entry_t fp_nf_rule_cache_common_entry_t;

#endif /* CONFIG_MCORE_NETFILTER_CACHE || defined(CONFIG_MCORE_NETFILTER_IPV6_CACHE) */

const char *fp_hook_name(int hook);
const char *fp_table_name(int table);
uint8_t fp_nf_table_id(const char *tblname);

void fp_nfct_add_hash(uint32_t hash, union fp_nfct_tuple_id id);
void fp_nfct_del_hash(uint32_t hash, struct fp_nfct_tuple_h *tuple);
void fp_nfct_add_hash_uid(uint32_t hash, uint32_t index);
void fp_nfct_del_hash_uid(uint32_t hash, uint32_t index);
#ifdef CONFIG_MCORE_NF_CT_CPEID
void fp_nfct_add_hash_cpeid(uint32_t hash, uint32_t index);
void fp_nfct_del_hash_cpeid(uint32_t hash, uint32_t index);
void fp_nf_dump_nfct_bycpeid(uint32_t cpeid, uint32_t count, int summary);
#endif

int fp_nf_update_bypass(uint8_t);
void fp_nf_invalidate_cache(void);
int fp_nf_set_conntrack_nat(uint8_t enable, uint16_t nf_vr);
void fp_nf_update_nftable_stats(const fp_nftable_t *cur_table,
				const fp_nftable_t *next_table);
void fp_nf_relocate_tables(uint8_t table, uint16_t nf_vr, int delta);

static inline uint32_t fp_nf_first_ruleid(const fp_nftable_t *table)
{
	return table->fpnftable_hook_entry[0];
}

static inline uint32_t fp_nf_last_ruleid(const fp_nftable_t *table)
{
	return table->fpnftable_hook_entry[0] + table->fpnftable_rules_count - 1;
}

#define FP_NF_DUMP_NFTABLE_MODE_SHORT       0
#define FP_NF_DUMP_NFTABLE_MODE_VERBOSE     1
#define FP_NF_DUMP_NFTABLE_MODE_NONZERO     2
int fp_nf_dump_nftable(uint8_t table, uint16_t nf_vr, int mode);
int fp_nf_print_summary(uint8_t table, uint16_t nf_vr);
void fp_nf_dump_nfct(uint32_t, int);

#ifdef CONFIG_MCORE_NETFILTER_IPV6
int fp_nf6_update_bypass(uint8_t);
#endif
#endif /* __FP_NETFILTER_H__ */
