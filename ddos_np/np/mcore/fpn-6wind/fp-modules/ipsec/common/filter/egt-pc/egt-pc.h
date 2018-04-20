/*
 * Copyright(c) 2007 6WIND
 */
/*****************************************************************************
 *
 *	EGT-PC (Extended Grid of Tries with Path Compression)
 *
 *	Author:	Sumeet Singh
 *
 *	Last Update: Dec 08, 2002
 *
 *	
 *	This source code is part of the Packet Classification Repository (PCR)
 *	at http://www.ial.ucsd.edu/
 *
 *	If you use this code we will apprecaite it if you cite the
 *	Packet Classification Repository in your publication.
 *
 *	If you would like to contribute paper publications, or
 *	source code to the PCR please email
 *	Sumeet Singh at susingh@cs.ucsd.edu
 *
 * **************************************************************************/
#ifndef _EGTPC_H_
#define _EGTPC_H_

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#define EGT_NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#include "pool.h"

/* To use compressed trie EGT-PC, define EGT_PC.
XXX: EGT-PC lookup is broken -JMG.
#define EGT_PC 1
*/

struct TRIESUBNODE {
	uint32_t cost;
	uint32_t filtId;
	uint16_t port[2];
	uint16_t portmask[2];
	uint16_t vrfid;
	uint8_t  protPref; /* 255 means any */
	uint8_t  pad;
	struct TRIESUBNODE* next;
#if 0 /* not used -JMG. */
	struct TRIESUBNODE* nextI[3];
#endif
}; /* 6 */

typedef struct TRIESUBNODE TrieSubNode;
typedef struct TRIESUBNODE* PTrieSubNode;

struct TRIENODE {
	struct TRIENODE *zero;
	struct TRIENODE *one;
	struct TRIENODE *dest;
	struct TRIENODE *parent;
	//struct TRIENODE *jump;
	struct TRIESUBNODE* pdimList;
#if 0 /* not used -JMG. */
	struct TRIESUBNODE* pdimListI[3];
#endif
	uint8_t  level;
	uint8_t pad[3];
}; /* 9 */

typedef struct TRIENODE TrieNode;
typedef struct TRIENODE* PTrieNode;

#define MAX_MATCH_RESULTS	100
struct trie_result {
	PTrieSubNode SEARCH_RESULTS[MAX_MATCH_RESULTS];
	uint32_t nSearchResults;
};
typedef struct trie_result trie_result_t;

#define EGTPC_NOTFOUND 0xFFFFFFFF /* max rule id */
#ifdef EGT_PC
struct TRIENODEC{
	uint32_t zmask;
	uint32_t omask;
	uint8_t  zmaskLen;
	uint8_t  omaskLen;
	uint8_t  level;
	uint8_t  pad;
	struct TRIENODEC *zero;
	struct TRIENODEC *one;
	struct TRIENODEC *dest;
	struct TRIENODEC *parent;
	//struct TRIENODEC *jump; // not used
	struct TRIENODEC *fail;
	struct TRIESUBNODE* pdimList;
#if 0 /* not used -JMG. */
	struct TRIESUBNODE* pdimListI[3];
#endif
}; /* 11 */

typedef struct TRIENODEC TrieNodeC;
typedef struct TRIENODEC* PTrieNodeC;
#endif

struct trie_ctx {
#ifdef EGT_PC
	TrieNodeC *rootC;
#endif
	PTrieNode trieroot;
	struct pool pool[3];
};

typedef struct trie_ctx * TCTX;

static uint32_t MASKS[] = { 0x00000000, 0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000 };

#define BitX(A,X)       ( ((A)&MASKS[(X%32)])?1:0)
#define MSBBitX(A,X)    ( ((A)&MASKS[(32-(X))])?1:0)

//#define DEBUG 1
//#define DEBUG_SEARCH 1
#ifdef DEBUG
#define TRACE_EGT(x...) do { fpn_printf(x); } while (0)
#else
#define TRACE_EGT(x...) {}
#endif

#ifdef DEBUG_SEARCH
#define TRACE_EGT_SEARCH(x...) fpn_printf(x)
#else
#define TRACE_EGT_SEARCH(x...)
#endif

#ifdef DEBUG_SEARCH
void WriteTrieSubNode(PTrieSubNode ptsubnode);
#endif
/* Search Functions for EGT */

static inline void SearchSourceTrie(PTrieNode ptnode, __attribute ((unused)) uint32_t dest, uint32_t source, trie_result_t *res)
{
	int i;
	PTrieSubNode tpsubnode;

	if (!ptnode)
		return;

	for (i=ptnode->level; (ptnode); i=ptnode->level) {
		FPN_TRACK();
		if(ptnode && ptnode->pdimList) {
			tpsubnode=ptnode->pdimList;
			while(tpsubnode) {
				FPN_TRACK();
#ifdef DEBUG_SEARCH
				TRACE_EGT("F");
				WriteTrieSubNode(tpsubnode);
#endif
				if (res->nSearchResults == (MAX_MATCH_RESULTS - 1))
					return;
				res->SEARCH_RESULTS[res->nSearchResults] = tpsubnode;
				res->nSearchResults++;
				tpsubnode=tpsubnode->next;
			}
		}

#ifdef DEBUG_SEARCH
		/*
		   if (i>31) fpn_printf("i>31: %d  ",i);
		   {
		   fpn_printf("  >> ");
		   if (ptnode->one && ptnode->one->pdimList) WriteTrieSubNode(ptnode->one->pdimList);
		   if (ptnode->zero && ptnode->zero->pdimList) WriteTrieSubNode(ptnode->zero->pdimList);
		   fpn_printf("  (%d)<< ",MSBBitX(source,i));

		   }
		 */
#endif

		if (MSBBitX(source,i)) {
			TRACE_EGT("1");
			if (ptnode->one) 
				ptnode = ptnode->one;
			else { 
				TRACE_EGT("SORRY");
				break;
			}
		} else {
			TRACE_EGT("0");
			if (ptnode->zero) 
				ptnode = ptnode->zero;
			else	{
				TRACE_EGT("SORRY"); 
				break;
			}
		}

		if (!ptnode) {
			TRACE_EGT(" >>%d<<END\n",i);
			break;
		}
	}
}

static inline void SearchTrie(PTrieNode ptnode,uint32_t dest, uint32_t source, trie_result_t *res)
{
	int i;
	int notdone = 1;
	PTrieNode 	lastGoodNode=ptnode->dest;

	TRACE_EGT("\nD: 0x%x  S: 0x%x L: 0x%p\n",dest,source,lastGoodNode);

	for (i=0; (notdone && (i<32)); i++) {
		FPN_TRACK();

		if (!(ptnode)) {
			TRACE_EGT("SORRY!");
			SearchSourceTrie(lastGoodNode, dest, source, res);
			notdone=0; 
			break;
		}

		if (ptnode->dest)
			lastGoodNode = ptnode->dest;

		if (MSBBitX(dest,i)) {
			TRACE_EGT("1");
			if (ptnode->one)
				ptnode = ptnode->one;
			else {
				TRACE_EGT("SORRY!");
				SearchSourceTrie(lastGoodNode, dest,source, res);
				notdone=0; break;
			}
		} else {
			TRACE_EGT("0");
			if (ptnode->zero)
				ptnode = ptnode->zero;
			else {
				TRACE_EGT("SORRY!");
				SearchSourceTrie(lastGoodNode, dest,source, res);
				notdone=0; break;
			}
		}
	}

	if (ptnode->dest)
		lastGoodNode = ptnode->dest;
	TRACE_EGT("D");

	if (notdone)
		SearchSourceTrie(lastGoodNode, dest, source, res);
	else
		TRACE_EGT("already done\n");
}

#ifdef EGT_PC

/* Search Functions for EGT-WPC */
static inline void SearchSourceTrieC(PTrieNodeC ptnode, uint32_t dest, uint32_t source, trie_result_t *res)
{
	int j,k;
	int done = 1;
	int found = 1;
	int prefixLen=32;
	uint32_t prefix = source;

	PTrieSubNode tpsubnode;

	PTrieNodeC	cN = ptnode;

	(void)dest;
	// if (ptnode) 	fpn_printf("valid"); else fpn_printf("problem");
	if (!ptnode)
		return ;

	for(j=0;(cN);j++)
	{

		if (cN->pdimList)
		{
			TRACE_EGT_SEARCH("LIST");
			// traverse through the list
			tpsubnode=cN->pdimList;
			while(tpsubnode)
			{
				TRACE_EGT_SEARCH("F");
#ifdef DEBUG_SEARCH
				WriteTrieSubNode(tpsubnode);
#endif
				if (res->nSearchResults == MAX_MATCH_RESULTS)
					return;
				res->SEARCH_RESULTS[res->nSearchResults] = tpsubnode;
				res->nSearchResults++;
				tpsubnode=tpsubnode->next;
			}

		}

		if (MSBBitX(prefix,j))
		{
			// make sure there is 1 pointer, else return lastFound
			if (cN->one)
			{
				if (cN->omaskLen > prefixLen)
				{
					// FOLLOW THE FAIL POINTER
					cN = cN->fail;
					// done = 0;
					continue;
				}
				else
				{
					found = 1;
					for(k=0;((k<cN->omaskLen) && found);k++)
					{
						if (MSBBitX(prefix,(j+k)) == MSBBitX(cN->omask,k))
							continue;
						// compare the bits k (for CN) and (j+k) for mask
						// if any bits dont match found = 0;
						found = 0;
					}

					if (found)
					{
						// lastFound = cN->one;
						cN = cN->one;
						TRACE_EGT_SEARCH("one\n");
					}
					else
					{
						TRACE_EGT_SEARCH("fail\n");
						cN = cN->fail;
						done=0;
					}
					if (cN) j=cN->level-1;
				}
			}
			else
			{
				// FOLLOW FAIL POINTER
				if (cN) cN = cN->fail;
				// done=0;
			}
		}
		else
		{
			if (cN->zero)
			{
				if (cN->zmaskLen > prefixLen)
				{
					// FOLLOW THE FAIL POINTER
					cN = cN->fail;
					// done = 0;
					continue;
				}
				else
				{
					found = 1;
					for(k=0;((k<cN->zmaskLen) && found);k++)
					{
						if (MSBBitX(prefix,(j+k)) == MSBBitX(cN->zmask,k))
							continue;
						// compare the bits k (for CN) and (j+k) for mask
						// if any bits dont match found = 0;
						found = 0;
					}

					if (found)
					{
						// lastFound = cN->zero;
						cN = cN->zero;
					}
					else
					{
						cN = cN->fail;
						done=0;
					}
					if (cN) j=cN->level-1;
				}
			}
			else
			{
				// FOLLOW FAIL POINTER
				cN = cN->fail;
				// done=0;
			}
		}
	}

}

static inline void SearchTrieC(PTrieNodeC ptnode,uint32_t dest, uint32_t source, trie_result_t *res)
{
	int j,k;
	int done = 1;
	int found = 1;
	int prefixLen=32;
	uint32_t prefix = dest;

	PTrieNodeC 	lastFound=ptnode->dest;
	PTrieNodeC	cN = ptnode;

	TRACE_EGT_SEARCH("SF: %x %x\n",dest, source);
	// TRACE_EGT_SEARCH("%d 0x%x  0x%x 0x%x\n",MSBBitX(prefix,j),cN->zero,cN->one,cN->dest);

	for(j=0;((j<prefixLen) && done && cN);j++)
	{
		TRACE_EGT_SEARCH(".");
		if (cN->dest)
			lastFound=cN->dest;

		if (MSBBitX(prefix,j))
		{
			TRACE_EGT_SEARCH("1");
			// make sure there is 1 pointer, else return lastFound
			if (cN->one)
			{
				if (cN->omaskLen > prefixLen)
				{
					// return current node
					done = 0;
					continue;
				}
				else
				{
					found = 1;
					for(k=0;((k<cN->omaskLen) && found);k++)
					{
						TRACE_EGT_SEARCH("'");
						if (MSBBitX(prefix,(j+k)) == MSBBitX(cN->omask,k))
							continue;
						// compare the bits k (for CN) and (j+k) for mask
						// if any bits dont match found = 0;
						found = 0;
					}

					if (found)
					{
						// lastFound = cN->one;
						cN = cN->one;
						if (cN->dest) lastFound=cN->dest;
					}
					else
					{
						done=0;
					}
					j=j+k-1;
				}
			}
			else
			{
				done=0;
			}
		}
		else
		{
			TRACE_EGT_SEARCH("0");
			// make sure there is 0 pointer, else return lastFound
			if (cN->zero)
			{
				if (cN->zmaskLen > prefixLen)
				{
					// return current node
					done = 0;
					continue;
				}
				else
				{
					found = 1;
					for(k=0;((k<cN->zmaskLen) && found);k++)
					{
						TRACE_EGT_SEARCH("'");
						if (MSBBitX(prefix,(j+k)) == MSBBitX(cN->zmask,k))
							continue;
						// compare the bits k (for CN) and (j+k) for mask
						// if any bits dont match found = 0;
						found = 0;

					}

					if (found)
					{
						// lastFound = cN->zero;
						cN = cN->zero;
						if (cN->dest) lastFound=cN->dest;
					}
					else
					{
						done=0;
					}
					j=j+k-1;
				}
			}
			else
			{
				// return lastFound || lastValid
				done=0;
			}
		}
	} // end for(j)

	if (cN && cN->pdimList)
		lastFound = cN->dest;

	SearchSourceTrieC(lastFound,dest,source, res);
}
#endif

static inline int SearchOtherDims(unsigned int sp, unsigned int dp, uint8_t pr, uint16_t vrfid, trie_result_t *res)
{
	uint32_t i=0;
	unsigned int result=0xffffffff;
	uint32_t match_id = EGTPC_NOTFOUND;
	PTrieSubNode tFilter;

	/* Select the rule with lowest cost */

	TRACE_EGT_SEARCH("SearchOtherDims:nres=%u %u %u proto %d\n", res->nSearchResults, sp, dp, pr);
	for(i = 0; i < res->nSearchResults; i++) {
		tFilter = res->SEARCH_RESULTS[i];
		TRACE_EGT_SEARCH("(%d) result=0x%x cost=%d id=%d port[0]=%u portmask[0]=0x%x port[1]=%u portmask[1]=0x%x proto=%u\n",
				i, result, tFilter->cost, tFilter->filtId, ntohs(tFilter->port[0]), tFilter->portmask[0], tFilter->port[1], tFilter->portmask[1], tFilter->protPref);

		if (tFilter->cost > result)
			continue;
		if (!((sp ^ tFilter->port[0]) & tFilter->portmask[0]) &&
		    !((dp ^ tFilter->port[1]) & tFilter->portmask[1]) &&
			((tFilter->protPref == 255) || (pr == tFilter->protPref)) &&
            (tFilter->vrfid == vrfid)) {
				result=tFilter->cost;
				match_id = tFilter->filtId;
		}
	}
	return match_id;
}

static inline int egtpc_lookup(void *ctx, uint32_t src, uint32_t dst,
		uint8_t proto,
		uint16_t sport, uint16_t dport,
		uint16_t vrfid,
		uint32_t *index)
{
	uint32_t match;
	trie_result_t result, *res;

	TRACE_EGT_SEARCH("Looking %u.%u.%u.%u -> %u.%u.%u.%u proto=%d sport=%d dport=%d (ctx=%p)\n",
			EGT_NIPQUAD(src), EGT_NIPQUAD(dst), proto, ntohs(sport), ntohs(dport), (TCTX)ctx);

	if (unlikely(ctx == 0))
		return -1;

	res = &result;
	res->nSearchResults = 0;

#ifdef EGT_PC
	// to search EGTWPC, XXX BUG
	SearchTrieC(((TCTX)ctx)->rootC, ntohl(dst), ntohl(src), res);
#else
	// to search EGT
	TRACE_EGT_SEARCH("trieroot=%p\n", ((TCTX)ctx)->trieroot);
	SearchTrie(((TCTX)ctx)->trieroot, ntohl(dst), ntohl(src), res);
#endif

#ifdef DEBUG_SEARCH
	TRACE_EGT_SEARCH("res->nSearchResults == %u: ", res->nSearchResults);
	{
		unsigned int i;
		for (i = 0; i < res->nSearchResults; i++) {
			PTrieSubNode tFilter = res->SEARCH_RESULTS[i];
			fpn_printf(" %d", tFilter->filtId);
		}
		fpn_printf("\n");
	}
#endif
	/* No match ? */
	if (unlikely(res->nSearchResults == 0))
		return -1;

	/* likely one exact match */
	if (likely(res->nSearchResults == 1)) {
		PTrieSubNode tFilter = res->SEARCH_RESULTS[0];
		*index = tFilter->filtId;
		return 0;
	}

	match = SearchOtherDims(ntohs(sport), ntohs(dport), proto, vrfid, res);
	*index = match;

	return (match == EGTPC_NOTFOUND);
}

void *egtpc_init(void *memstart, uint32_t size);
int egtpc_update(struct FILTER *user_filter, void *user_ctx);
int egtpc_final(void *user_ctx);

void egtpc_pool_left(void *user_ctx);
#endif
