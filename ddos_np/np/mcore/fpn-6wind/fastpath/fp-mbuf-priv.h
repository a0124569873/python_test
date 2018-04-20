/*
 * Copyright(c) 2007 6WIND
 *
 * mbuf extra data for FPN application
 */
#ifndef __FP_MBUF_PRIV_H__
#define __FP_MBUF_PRIV_H__

#if defined(CONFIG_MCORE_ARCH_XLP)
  #define __ipsec_aligned__ ____cacheline_aligned
#else
  #define __ipsec_aligned__
#endif
#define M_OUT_AUTH_MAX_SIZE    64 /* with this size MD5,SHA1,SHA256,SHA384 and SHA512 supported */
#define M_SAVE_AUTH_MAX_SIZE   32 /* with this size MD5,SHA1,SHA256,SHA384 and SHA512 supported */
#define M_IV_MAX_SIZE          16 /* max IV size */


/*
 * M_TAG_HASH_ORDER is rder of the hashtable for MTAG in
 * mbuf_priv. The maximum number of buckets in the hashtable is 2 ^
 * order. The maximum number of mtags in one packet is
 * 2 ^ M_TAG_HASH_ORDER + M_TAG_EXTRA_COUNT.
 *
 * M_TAG_EXTRA_COUNT is the number of additionnal MTAGS besides the
 * ones stored in hashtable. See in fp-mbuf-mtags.h and fp-mbuf-priv.h
 * for details.
 *
 * The total number of rooms to store mtags is M_TAG_TABLE_SIZE. Note
 * that some features like filtering or splicing require mtag to work
 * correctly.
 */
#ifdef CONFIG_MCORE_M_TAG
#  ifdef CONFIG_MCORE_M_TAG_HASH_ORDER
#    define M_TAG_HASH_ORDER CONFIG_MCORE_M_TAG_HASH_ORDER
#  else
#    define M_TAG_HASH_ORDER 1
#  endif
#  ifdef CONFIG_MCORE_M_TAG_EXTRA_COUNT
#    define M_TAG_EXTRA_COUNT CONFIG_MCORE_M_TAG_EXTRA_COUNT
#  else
#    define M_TAG_EXTRA_COUNT 2
#  endif
#  define M_TAG_HASH_SIZE  (1<<M_TAG_HASH_ORDER)
#  define M_TAG_HASH_MASK  (M_TAG_HASH_SIZE-1)
#  define M_TAG_TABLE_SIZE (M_TAG_HASH_SIZE + M_TAG_EXTRA_COUNT)
#else
#  define M_TAG_TABLE_SIZE  0
#endif


/* structure defining a mtag */
struct m_tag {
	int16_t  id;        /* ID of the mtag (-1 of not present) */
	int16_t  idx_next;  /* index of the next mtag with same hash */
	uint32_t val;       /* value of the mtag */
};

struct m_ipsec_state {
	char         out_auth[M_OUT_AUTH_MAX_SIZE] __ipsec_aligned__ ; /* ah/esp input/output */
	char         save_auth[M_SAVE_AUTH_MAX_SIZE]; /* ah input */
	char         iv[M_IV_MAX_SIZE]; /* IV copy for GCM */

	uint32_t ipv6_flow; /* IPv6 version, traffic class, flow label */
	uint16_t ip_off;
	uint8_t  ip_ttl;
	uint8_t  ip_tos;
	uint8_t  ah_nxt;
	uint8_t  flags;
#define M_PRIV_OOPLACE_ICV  0x1
};

struct fp_mbuf_priv_s {
	uint32_t ifuid;

	uint16_t flags;
#define M_LOCAL_OUT     0x0001    /* packet source is host */
#define M_IPSEC_BYPASS  0x0002    /* decrypted or encrypted packet */
#define M_TOS           0x0004    /* TOS field is valid */
#define M_ASYNC         0x0008    /* packet processed asynchronously */
#define M_LOCAL_F       0x0010    /* allow to fragment this packet locally */
#define M_F_REASS       0x0020    /* reassembly was forced on this packet */
#define M_IPSEC_SP_OK   0x0040    /* inbound policy has been checked */
#define M_IPSEC_OUT     0x0080    /* encrypted packet */
#define M_NFNAT_DST     0x0100    /* NAT has modified destination */

#ifdef CONFIG_MCORE_VRF
	uint16_t vrfid;
#elif !defined(CONFIG_MCORE_NETFILTER)
	uint16_t pad0;
#endif

#ifdef CONFIG_MCORE_NETFILTER
#define  FP_NF_CT_MBUF_UNKNOWN         0
#define  FP_NF_CT_MBUF_ESTABLISHED     1
#define  FP_NF_CT_MBUF_OTHER           2
	uint8_t		fp_nfct_established;
	uint8_t		fp_nfct_dir;
#if defined(CONFIG_MCORE_EBTABLES)
#define FP_BRNF_NOTHING                0x01
#define FP_BRNF_BRIDGED                0x02
	uint8_t		fp_phys_mask;
	uint8_t		pad0;
#endif
	union {
		struct fp_nfct_entry  *v4;
		struct fp_nf6ct_entry *v6;
	} fp_nfct;
#endif

	int8_t  m_tag_count; /* <= 0 if no tag */
	uint8_t  exc_type;
	uint16_t exc_proto;

	uint8_t  exc_class;
	uint8_t  tos;                 /* Inherited DSCP/ECN for encapsulation */
	uint16_t max_frag_size;    /* size of the longest received fragment */

	struct {
		uint32_t start_offset; /* start offset of this fragment */
		uint32_t end_offset;   /* end offset of this fragment */
	} reass;

	struct {
		uint32_t in_link; /* recored lacp in link */
	} lacp;

	struct m_tag	m_tag[M_TAG_TABLE_SIZE];

	/* --------------------------------
	 * all fields after 'end_of_copy' are not copied when the packet is
	 * copied using m_dup(), m_clone(), ...
	 * -------------------------------- */
	struct { } end_of_copy;

#if defined(CONFIG_MCORE_FPN_CRYPTO_ASYNC) && (defined(CONFIG_MCORE_IPSEC) || defined(CONFIG_MCORE_IPSEC_IPV6))
	struct {
		struct m_ipsec_state m_ipsec_buf;
		void *sa;  /* ah/esp input, ah/esp output */
		uint32_t     seq;
		uint32_t     back; /* backup of packet data overwritten during encryption/decryption */
		void *esp; /* esp header */
	} ipsec;
#endif
} __attribute__((__may_alias__));
typedef struct fp_mbuf_priv_s fp_mbuf_priv_t;

#define m_priv(m) mtopriv(m, fp_mbuf_priv_t *)
#define m2ifnet(m) (__fp_ifuid2ifnet(m_priv(m)->ifuid))

#include "fp-mbuf-mtag.h"

#ifdef CONFIG_MCORE_VRF
#define m2vrfid(m) (m_priv(m)->vrfid)
#define m2linkvrfid(m) (m_priv(m)->linkvrfid)
#define set_mvrfid(m,v) m2vrfid(m) = (v)
#else
#define m2vrfid(m) 0
#define m2linkvrfid(m) 0
#define set_mvrfid(m,v) do { } while (0)
#endif

#ifdef FPN_HAS_HW_RESET
#define fp_reset_hw_flags(m) fpn_mbuf_hw_reset((m))
#else
#define fp_reset_hw_flags(m) do { } while (0)
#endif

#endif /* __FP_MBUF_PRIV_H__ */
