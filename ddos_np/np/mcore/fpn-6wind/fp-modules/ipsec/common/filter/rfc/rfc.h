/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __RFC_H__
#define __RFC_H__

#ifdef CONFIG_MCORE_IPSEC_TRIE_MAXRULES
#define MAXRULES (CONFIG_MCORE_IPSEC_TRIE_MAXRULES)
#else
#define MAXRULES 10000
#endif
#define MAXDIMENSIONS 5
#define MAXCHUNKS 7
#define FILTERSIZE 18

#if (RFC_PHASE != 4) && (RFC_PHASE != 3)
#error RFC_PHASE is 3 or 4
#endif

#include "dheap.h"
#include "fblock.h"

#include "filter.h"

#ifdef PRINT_MATCH
#include <stdio.h>
#endif

struct eq {
  int numrules;
  int first_rule_id;
  int *rulelist;
};

struct fp_filter_range {
  uint32_t low;
  uint32_t high;
};

struct pc_rule{
  uint32_t filtId;
  uint32_t cost;
  struct fp_filter_range field[MAXDIMENSIONS];
};

struct trie_rfc {
	int p0_table[7][65536];                  //phase 0 chunk tables
	int *p1_table[4];               //phase 1 chunk tables
	int *p2_table[2];               //phase 2 chunk tables
	int *p3_table;                  //phase 3 chunk tables
	struct eq p0_eq[7][2*MAXRULES];          //phase 0 chunk equivalence class
	struct eq p1_eq[4][2*MAXRULES];          //phase 1 chunk equivalence class
	struct eq p2_eq[2][2*MAXRULES];          //phase 2 chunk equivalence class
	struct eq p3_eq[2*MAXRULES];             //phase 3 chunk equivalence class
	int p0_neq[7];                           //phase 0 number of chunk equivalence classes
	int p1_neq[4];                           //phase 1 number of chunk equivalence classes
	int p2_neq[2];                           //phase 2 number of chunk equivalence classes
	int p3_neq;                              //phase 3 number of chunk equivalence classes
	struct pc_rule rule[MAXRULES];
	int numrules;
	struct fblock fb;
	struct dheap dheap;
} __fpn_cache_aligned;

#define RFC_5BIT_PROTO_INVALID 31
#define RFC_5BIT_PROTO_UNKNOWN 30
#define RFC_5BIT_PROTO_MAX RFC_5BIT_PROTO_UNKNOWN

FPN_DECLARE_SHARED(uint8_t, rfc_protocomptab[256]);

/* return a unique value between 0 and RFC_5BIT_PROTO_UNKNOWN-1 for known
   protocols, RFC_5BIT_PROTO_UNKNOWN otherwise */
static inline uint8_t rfc_proto_compress(uint8_t proto)
{
	return rfc_protocomptab[proto];
}

/* build the VR+proto (network order) field based on:
 * vrfid (host order) and compressed protocol */
static inline uint16_t rfc_make_vrproto(uint16_t vrfid, uint8_t proto)
{
	return htons((vrfid<<5)|proto);
}

static inline int rfc_lookup(void *ctx,
		      uint32_t src,
		      uint32_t dst,
		      uint8_t proto,
		      uint16_t sport,
		      uint16_t dport,
		      uint16_t vrfid,
		      uint32_t *index)
{
  struct trie_rfc *t = (struct trie_rfc *)ctx;
  unsigned a, b, c, d, e, f, g;
      //phase 0
      a = t->p0_table[0][ntohl(src) & 0xFFFF];
      b = t->p0_table[1][(ntohl(src) >> 16) & 0xFFFF];
      c = t->p0_table[2][ntohl(dst) & 0xFFFF];
      d = t->p0_table[3][(ntohl(dst) >> 16) & 0xFFFF];
      e = t->p0_table[4][rfc_make_vrproto(vrfid, rfc_proto_compress(proto))];
      f = t->p0_table[5][ntohs(sport)];
      g = t->p0_table[6][ntohs(dport)];

      //phase 1
      a = t->p1_table[0][a*t->p0_neq[1]+b];
      c = t->p1_table[1][c*t->p0_neq[3]+d];
      e = t->p1_table[2][e*t->p0_neq[5]*t->p0_neq[6]+f*t->p0_neq[6]+g];


#if RFC_PHASE == 4
        //phase 2
        a = t->p2_table[0][a*t->p1_neq[1]+c];

        //phase 3
        a = t->p3_table[e*t->p2_neq[0]+a];

        if(likely(t->p3_eq[a].numrules == 1)) {
		*index = t->p3_eq[a].first_rule_id;
		return 0;
	}

        if(t->p3_eq[a].numrules == 0) {
		return -1;
	}
        else {
#ifdef PRINT_MATCH
		int j;
		printf("numrules=%d: ", t->p3_eq[a].numrules);
		for (j = 0; j < t->p3_eq[a].numrules; j++)
			printf(" %d", t->p3_eq[a].rulelist[j]);
		printf("\n");	
#endif
		*index = t->p3_eq[a].first_rule_id;
		return 0;
	}

#else /* RFC PHASE 3 */
        //phase 2
        a = t->p2_table[0][a*t->p1_neq[1]*t->p1_neq[2]+c*t->p1_neq[2]+e];

        if (likely(t->p2_eq[0][a].numrules == 1)) {
		*index = t->rule[t->p2_eq[0][a].rulelist[0]].filtId;
		return 0;
	}

        if(t->p2_eq[0][a].numrules == 0)
		return -1;
        else  {
#ifdef PRINT_MATCH
		int j;
		printf("numrules=%d: ", t->p2_eq[0][a].numrules);
		for (j = 0; j < t->p2_eq[0][a].numrules; j++)
			printf(" %d", t->p2_eq[0][a].rulelist[j]);
		printf("\n");	
#endif
		*index = t->rule[t->p2_eq[0][a].rulelist[0]].filtId;
		return 0;
	}
#endif
}

void *rfc_init(void *memstart, uint32_t memsize);
int rfc_update(struct FILTER *f, void *user_ctx);
int rfc_final(void *user_ctx);

#endif
