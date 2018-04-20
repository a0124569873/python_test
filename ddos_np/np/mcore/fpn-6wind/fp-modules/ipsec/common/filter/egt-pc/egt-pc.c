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
#include "fpn.h"

#include "filter.h"
#include "egt-pc/egt-pc.h"

#include "pool.h"

#define POOL_TRIENODE    0
#define POOL_TRIESUBNODE 1
#ifdef EGT_PC
#define POOL_TRIENODEC   2
#endif

static PTrieSubNode  NewTrieSubNode(TCTX ctx)
{
	PTrieSubNode ptsubnode = (TrieSubNode*) pool_alloc (&ctx->pool[POOL_TRIESUBNODE]);

	if (!ptsubnode)
		return NULL;
	ptsubnode->next = NULL;

	return ptsubnode;
}

#ifdef DEBUG_SEARCH
void WriteTrieSubNode(PTrieSubNode ptsubnode)
{
	TRACE_EGT_SEARCH("<<%d>>",ptsubnode->cost);
}
#endif

#ifdef DEBUG_PRINT_FILTER
static void print_filter(struct FILTER *wF);
#endif
static void AddFilterToNode(PTrieNode ptnode, struct FILTER *pfilter, TCTX ctx)
{
	PTrieSubNode ptsubnode = NewTrieSubNode(ctx);

	if (ptsubnode == NULL)
		return;

//if (pfilter->filtId == 857 || pfilter->filtId == 909)
//	print_filter(pfilter);
	ptsubnode->protPref = pfilter->ul_proto;
	ptsubnode->port[0] = ntohs(pfilter->srcport);
	ptsubnode->portmask[0] = ntohs(pfilter->srcport_mask);
	ptsubnode->port[1] = ntohs(pfilter->dstport);
	ptsubnode->portmask[1] = ntohs(pfilter->dstport_mask);
	ptsubnode->cost = pfilter->filtId; // XXX pfilter->cost;
	ptsubnode->filtId = pfilter->filtId;
	ptsubnode->vrfid = pfilter->vrfid;
	ptsubnode->next = NULL;

	if (ptnode->pdimList != NULL)
	{
		TRACE_EGT(":");
		ptsubnode->next = ptnode->pdimList;
		ptnode->pdimList = ptsubnode;
	}
	else
	{
		ptnode->pdimList = ptsubnode;
	}
}

static PTrieNode NewTrieNode(TCTX ctx)
{
	PTrieNode ptnode = (TrieNode*) pool_alloc (&ctx->pool[POOL_TRIENODE]);
	if (!ptnode)
		return NULL;
	ptnode->zero = NULL;
	ptnode->one = NULL;
	ptnode->dest = NULL;
	ptnode->pdimList=NULL;
	ptnode->level=0;

	return ptnode;
}

#ifdef EGT_PC
static PTrieNodeC NewTrieNodeC(TCTX ctx)
{
	PTrieNodeC ptnode = (TrieNodeC*) pool_alloc (&ctx->pool[POOL_TRIENODEC]);
//PTrieNodeC ptnode = (TrieNodeC*)malloc(sizeof(TrieNodeC));
//(void)ctx;
	if (!ptnode)
		return NULL;
	ptnode->zero = NULL;
	ptnode->one = NULL;
	ptnode->dest = NULL;
	ptnode->pdimList=NULL;
	ptnode->level=0;

	return ptnode;
}
#endif

static int AddRuleToGrid(TrieNode* ptnode, struct FILTER *pfilter, TCTX ctx)
{
	uint8_t i,j;
	TrieNode* currentNode = ptnode;

	uint32_t destPref = ntohl(pfilter->dst);
	uint32_t destLen =  pfilter->dst_plen;
	uint32_t sourcePref = ntohl(pfilter->src);
	uint32_t sourceLen = pfilter->src_plen;
	uint32_t prefix = 0x0;

	TRACE_EGT(" ptnode=%p pfilter=%p ctx=%p (0x%x/%d)\n", ptnode, pfilter, ctx, destPref,destLen);

	for(i = 0; i < destLen; i++) {
		// fpn_printf("%d:",i);
		if (MSBBitX(destPref,i)) {
			// 1 right sub tree
			// fpn_printf("1 ");
			if (currentNode->one != NULL)
				currentNode = currentNode->one;
			else {
				currentNode->one = NewTrieNode(ctx);
				if (currentNode->one == NULL)
					return -1;
				currentNode->one->parent = currentNode;
				currentNode->one->level = currentNode->level + 1;
				currentNode = currentNode->one;
			}
			prefix = prefix << 1 | 0x1;

		} else {
			// 0 left sub tree
			// fpn_printf("0 ");
			if (currentNode->zero != NULL)
				currentNode = currentNode->zero;
			else {
				currentNode->zero = NewTrieNode(ctx);
				if (currentNode->zero == NULL)
					return -1;
				currentNode->zero->parent = currentNode;
				currentNode->zero->level = currentNode->level + 1;
				currentNode = currentNode->zero;

			}
			prefix = prefix << 1 | 0x0;
		}
	}

	if (currentNode->dest)
		currentNode = currentNode->dest;
	else {
		currentNode->dest = NewTrieNode(ctx);
		if (currentNode->dest == NULL)
			return -1;
		currentNode->dest->parent = currentNode;
		currentNode->dest->level = 0;
		currentNode = currentNode->dest;
	}

	TRACE_EGT(" (0x%x/%d) ",sourcePref,sourceLen);

	for(j = 0; j < sourceLen; j++) {
		if (MSBBitX(sourcePref,j)) {
			// 1 right sub tree
			TRACE_EGT("1");
			if (currentNode->one != NULL)
				currentNode = currentNode->one;
			else {
				currentNode->one = NewTrieNode(ctx);
				if (currentNode->one == NULL)
					return -1;
				currentNode->one->parent = currentNode;
				currentNode->one->level = currentNode->level + 1;
				currentNode = currentNode->one;
			}
		} else {
			// 0 left sub tree
			TRACE_EGT("0");
			if (currentNode->zero != NULL)
				currentNode = currentNode->zero;
			else {
				currentNode->zero = NewTrieNode(ctx);
				if (currentNode->zero == NULL)
					return -1;	
				currentNode->zero->parent = currentNode;
				currentNode->zero->level = currentNode->level + 1;
				currentNode = currentNode->zero;
			}
		}
	}

	// we need to put the filter off the location we are at..
	AddFilterToNode(currentNode, pfilter, ctx);

	return 0;
}

#if 0
static void AddPointerToLastNode(PTrieNode ptnode, PTrieSubNode ptsubnode)
{
	PTrieSubNode currentSubNode;

	if (!(ptnode->pdimList))
		ptnode->pdimList = ptsubnode;
	else {
		currentSubNode = ptnode->pdimList;

		while(currentSubNode->next) {
			TRACE_EGT(":");
			currentSubNode = currentSubNode->next;
		}

		currentSubNode->next=ptsubnode;
	}
}

static int AddLinkToSubNode(PTrieNode start, PTrieSubNode ptsubnode)
{
	PTrieNode currentNode = start;

	TRACE_EGT("AddLinkToSubNode %p %p\n", start, ptsubnode);

	if (!start) return 0;

	if (currentNode->pdimList) {
		TRACE_EGT("<Z>");
		AddPointerToLastNode(currentNode,ptsubnode);
		return (AddLinkToSubNode(currentNode->zero, currentNode->pdimList) + 
                AddLinkToSubNode(currentNode->one, currentNode->pdimList));
	}
	else {
		return (AddLinkToSubNode(currentNode->zero, ptsubnode) + 
                AddLinkToSubNode(currentNode->one, ptsubnode));
	}
}
#endif


#if 0
static inline uint32_t plen2mask(uint8_t plen)
{
    return plen ? (~((1<<(32-plen)) -1)) : 0;
}
#endif

static PTrieNode FindNextLongestNodeN(PTrieNode start, uint32_t prefix, int prefixLen)
{
	PTrieNode cN = start;
	PTrieNode lastFound = NULL;
	PTrieNode lastValid = NULL;
	int i;
	int l;

	 //fpn_printf("(FNL:0x%x/%d LGS:%p)\n",prefix,prefixLen,start);

	if (!start)
		return NULL;

	if (!start->dest)
		return FindNextLongestNodeN(start->parent, prefix, prefixLen);

	cN = start->dest;
	if (cN->pdimList)
		lastFound = cN;
	lastValid = cN; // FIX JMG set lastValid for prefixLen 0 case 
	l = prefixLen > 0 ? 1<<(prefixLen-1) : 0;
	for(i = 0; i <prefixLen; i++) {
		if (cN) {
			lastValid=cN;
			if (cN->pdimList)
				lastFound = cN;
		} else {
			break;
		}

		//if (MSBBitX(prefix,i)) FIX JMG: use proper mask 
		if (prefix & l) {
			TRACE_EGT("1");
			cN = cN->one;
		} else {
			TRACE_EGT("0");
			cN = cN->zero;
		}
		l = l >> 1;
	}

	TRACE_EGT("\n");

	if (cN && cN->pdimList)
		return cN;

	if (lastFound)
		return lastFound;

	if (lastValid)
		return lastValid;

	return FindNextLongestNodeN(start->parent, prefix, prefixLen);
}

#if 0
static PTrieSubNode GetSubNode(PTrieNode start, uint32_t prefix, uint32_t prefixLen)
{

	PTrieNode currentNode=NULL;
	PTrieNode lastNode=NULL;
	PTrieSubNode ptsubnode=NULL;
	uint32_t i;

	if (!start) return NULL;

	if (!(start->dest)) return (GetSubNode(start->parent, prefix,prefixLen));

	currentNode=start->dest;

	i=0;
	while(currentNode && (i<prefixLen))
	{
		lastNode=currentNode;
		if (MSBBitX(prefix,i))
		{
			currentNode = currentNode->one;
		}
		else
		{
			currentNode = currentNode->zero;
		}

		i++;
	}

	if (currentNode)
		ptsubnode = currentNode->pdimList;
	else
		ptsubnode = lastNode->pdimList;

	return ptsubnode;

}

static void AddLinksToSubNodes(PTrieNode start, PTrieNode lastGoodSource, uint32_t prefix, int prefixLen)
{
	PTrieNode currentNode;
	PTrieSubNode tsubnode;


	TRACE_EGT("L");
	if (!(start)) return;


	currentNode = start;

	if (lastGoodSource)
	{
		TRACE_EGT("GOT GOOD LAST SOURCE\n");
#ifdef DEBUG
		if (!lastGoodSource->parent)
			TRACE_EGT("BUT NO PARENT\n");
#endif
		tsubnode = GetSubNode(lastGoodSource->parent, prefix, prefixLen);
		AddPointerToLastNode(currentNode, tsubnode);
	}

	// else
	{
		if (currentNode->dest != NULL)
		{
			lastGoodSource = currentNode;
			TRACE_EGT("SET LAST GOOD SOURCE\n");
			AddLinksToSubNodes(currentNode->dest,lastGoodSource, 0x0,0);
		}


		if (currentNode->zero) AddLinksToSubNodes(currentNode->zero, lastGoodSource, ((prefix>>1))    ,prefixLen+1);
		if (currentNode->one) AddLinksToSubNodes(currentNode->one,  lastGoodSource, ((prefix>>1)|0x80000000 ) ,prefixLen+1);
	}

	TRACE_EGT("\n");
	return;
}
#endif

static void AddLinksToLongestPaths(PTrieNode start, PTrieNode lastGoodSource, uint32_t prefix, int prefixLen, int dim)
{
	PTrieNode currentNode;
	PTrieNode tnode;

	// fpn_printf("L");
	if (!(start))
		return;

	currentNode = start;

	TRACE_EGT("(H:%d:%d:%d)",prefixLen,dim,(currentNode->zero && currentNode->one));

	if (currentNode->zero) {
		TRACE_EGT("0");
		//AddLinksToLongestPaths(currentNode->zero, lastGoodSource, ((prefix>>1))    ,prefixLen+1, dim);
		//	FIX JMG: shit left 
		AddLinksToLongestPaths(currentNode->zero, lastGoodSource, ((prefix<<1))    ,prefixLen+1, dim);
	} else {
		if (dim == 1) {
			tnode = FindNextLongestNodeN(lastGoodSource->parent, prefix, prefixLen);
			currentNode->zero = tnode;
			if (currentNode->zero == currentNode)
				currentNode->zero=NULL;

#ifdef DEBUG
			{
				fpn_printf("\n[0x%x/%d]",prefix,prefixLen);
				fpn_printf("-> ");
				fpn_printf("Z > ");
				fpn_printf("(LEVEL %d:",currentNode->level);
				if (tnode) fpn_printf("%d",tnode->level);
				fpn_printf(")\n");
				if (tnode && tnode->pdimList)	fpn_printf("<<zero VP %u %p>>", tnode->pdimList->cost, currentNode->zero);
			}
#endif
		}
	}


	if (currentNode->one) {
		TRACE_EGT("1");
		//AddLinksToLongestPaths(currentNode->one,  lastGoodSource, ((prefix>>1)|0x80000000 ) ,prefixLen+1, dim);
		//	FIX JMG: shit left 
		AddLinksToLongestPaths(currentNode->one,  lastGoodSource, ((prefix<<1)|0x1 ) ,prefixLen+1, dim);
	} else {
		if (dim==1) {
			tnode = FindNextLongestNodeN(lastGoodSource->parent, prefix, prefixLen);
			currentNode->one = tnode;
			if (currentNode->one == currentNode)
				currentNode->one=NULL;
#ifdef DEBUG
			{	
				fpn_printf("\n[0x%x/%d]",prefix,prefixLen);
				fpn_printf("-> ");
				fpn_printf("0 > ");
				fpn_printf("(LEVEL %d:",currentNode->level);
				if (tnode) fpn_printf("%d",tnode->level);
				fpn_printf(")\n");
				if (tnode && tnode->pdimList)	fpn_printf("<<one VP %u>>", tnode->pdimList->cost);
			}
#endif
		}
	}

	if (currentNode->dest != NULL) {
		// lastGoodSource = currentNode;
		//TRACE_EGT("changed LGS: 0x%x P: 0x%x\nD",currentNode,currentNode->parent);
		// HEREY
		AddLinksToLongestPaths(currentNode->dest,currentNode, 0x0,0,1);
	}

	return;
}


static void InitGridOfTrie(TCTX ctx)
{
	TrieNode *newNode = (TrieNode*) pool_alloc(&ctx->pool[POOL_TRIENODE]);
	newNode->zero = NULL;
	newNode->one = NULL;
	newNode->dest = NULL;
	ctx->trieroot = newNode;
	TRACE_EGT("InitGridOfTrie: ctx=%p, root=%p\n", ctx, ctx->trieroot);
}

static void trie_add_filter(struct FILTER *filter, TCTX ctx)
{
#define TRIE_ACCEPT_ANY2ANY 1
#ifdef TRIE_ACCEPT_ANY2ANY
	AddRuleToGrid(ctx->trieroot, filter, ctx);
#else
		if (!((filter->src_plen == 0) && (filter->dst_plen == 0)))
			AddRuleToGrid(ctx->trieroot, filter, ctx);
		else {
			TRACE_EGT("SKIP: rule %u %d %d\n", filter->filtId, filter->src_plen, filter->dst_plen);
		}
#endif
}

#ifdef DEBUG_SEARCH
void WriteTrie(PTrieNode ptnode)
{
	PTrieSubNode tpsubnode;
	fpn_printf("(%d)",ptnode->level);
	if (ptnode->pdimList)
	{
		tpsubnode=ptnode->pdimList;
		while(tpsubnode)
		{
			TRACE_EGT_SEARCH("F");
			WriteTrieSubNode(tpsubnode);
			tpsubnode=tpsubnode->next;
		}
	}

	if (ptnode->zero)
	{
		WriteTrie(ptnode->zero);
		fpn_printf("0");
	}
	if (ptnode->one)
	{
		WriteTrie(ptnode->one);
		fpn_printf("1");
	}

	if (ptnode->dest)
	{
		WriteTrie(ptnode->dest);
		fpn_printf("D");
	}


	if (!(ptnode->zero && ptnode->dest && ptnode->one))
		fpn_printf("E");
}
#endif

#ifdef EGT_PC
/**********
 *
 * PATH COMPRESSION FUNCTIONS
 *
 **********/

static int CompressDestTrie(PTrieNodeC parent, PTrieNode ptnode, uint32_t cmask, uint8_t cmaskLen, int level, uint8_t branch, TCTX ctx)
{
#if 0
fpn_printf("parent=%p ptnode=%p cmask=%u/%u level=%u br=%u\n",
		parent, ptnode, cmask, cmaskLen, level, branch);
#endif
	if ((ptnode->zero && ptnode->one) || (ptnode->dest) || (cmaskLen==MAX_STRIDE) || (ptnode->pdimList))
	{
		// create new trie node
		PTrieNodeC newNode;
		newNode = NewTrieNodeC(ctx);
		if (newNode == NULL)
			return -1;

		newNode->level = level;
		newNode->pdimList = ptnode->pdimList;
		newNode->parent = parent;

		if (branch==1)
		{
			// set parent one mask / pointer
			parent->one = newNode;
			parent->omask = cmask;
			parent->omaskLen = cmaskLen;
		}
		else
		{
			parent->zero = newNode;
			parent->zmask = cmask;
			parent->zmaskLen = cmaskLen;
		}


		if (ptnode->dest)
		{
			// create a new node for ptnode->dest
			PTrieNodeC newDestNode;

			// fpn_printf("NEW D NODE\n");

			newDestNode = NewTrieNodeC(ctx);
			if (newDestNode == NULL)
				return -1;
			newNode->dest = newDestNode;
			newDestNode->parent = newNode;

			newDestNode->pdimList = ptnode->dest->pdimList;

			newDestNode->level = 1;

			// call CompressSourceTrie
			// with the newDestNode as parent
			//

			if (ptnode->dest->one) {
				if (CompressDestTrie(newDestNode, ptnode->dest->one, 0x80000000, 1, 1, 1, ctx) < 0)
					return -1;
			}
			if (ptnode->dest->zero) {
				if (CompressDestTrie(newDestNode, ptnode->dest->zero, 0x00000000, 1, 1, 0, ctx) < 0)
					return -1;
			}
		}

		// call CompressDestTrie on zero / one with new parent / mask
		if (ptnode->zero) {
			if (CompressDestTrie(newNode, ptnode->zero, 0x0, 1, level+1, 0, ctx) < 0)
				return -1;
		}

		if(ptnode->one) {
			if (CompressDestTrie(newNode, ptnode->one, 0x80000000, 1, level+1, 1, ctx) < 0)
				return -1;
		}
	} else {
		if (ptnode->zero) {
			uint32_t nmask = 0x0;
			nmask = cmask >> 1;
			nmask = nmask ^ 0x0;

			if (CompressDestTrie(parent, ptnode->zero, nmask, cmaskLen+1, level+1, branch, ctx) < 0)
				return -1;
		}
		if (ptnode->one) {
			uint32_t nmask = 0x0;
			nmask = cmask >> 1;
			nmask = nmask ^ 0x80000000;

			if (CompressDestTrie(parent, ptnode->one, nmask, cmaskLen+1, level+1, branch, ctx) < 0)
				return -1;
		}
	}
	return 0;
}

static int CreateCompressedTrie(PTrieNodeC nodeC, PTrieNode trieroot, TCTX ctx)
{
	nodeC->level=0;

	if (trieroot->zero)
		if (CompressDestTrie(nodeC, trieroot->zero, 0x0, 1, 1, 0, ctx) < 0)
			return -1;
	if (trieroot->one)
		if (CompressDestTrie(nodeC, trieroot->one, 0x80000000, 1, 1, 1, ctx) < 0)
			return -1;
	if (trieroot->dest) {
		// create a new node for ptnode->dest
		PTrieNodeC newDestNode;
		// fpn_printf("NEW D NODE\n");
		// fpn_printf(":%d:",ptnode->dest->pdimList->cost);

		newDestNode = NewTrieNodeC(ctx);
		if (newDestNode == NULL)
			return -1;
		nodeC->dest = newDestNode;

		newDestNode->pdimList = trieroot->dest->pdimList;
#if 0
		newDestNode->pdimListI[0] = trieroot->dest->pdimListI[0];
		newDestNode->pdimListI[1] = trieroot->dest->pdimListI[1];
		newDestNode->pdimListI[2] = trieroot->dest->pdimListI[2];
#endif
		newDestNode->level = 1;
		// call CompressSourceTrie
		// with the newDestNode as parent

		if (trieroot->dest->one) {
			if (CompressDestTrie(newDestNode, trieroot->dest->one,
						0x80000000, 1, 1, 1, ctx) < 0)
				return -1;
		}
		if (trieroot->dest->zero) {
			if (CompressDestTrie(newDestNode, trieroot->dest->zero,
						0x00000000, 1, 1, 0, ctx) < 0)
				return -1;
		}

	}

	return 0;
}

static PTrieNodeC FindNextLongestNodeC(PTrieNodeC start, uint32_t prefix, int prefixLen)
{
	PTrieNodeC cN = start;
	PTrieNodeC lastFound = NULL;
	PTrieNodeC lastValid = NULL;

	int j=0;
	int k=0;
	int found = 0;
	int done =1;

	if (!start)
		return NULL;


	if (!start->dest)
		return FindNextLongestNodeC(start->parent, prefix, prefixLen);

	cN = start->dest;

	if (cN->pdimList) lastFound = cN;
	lastValid = cN;

	j=0;
	done = 1;

	for(j=0;((j<prefixLen) && done);j++)
	{
		if (cN)
		{
			lastValid = cN;
			if (cN->pdimList) lastFound = cN;
		}
		else
		{
			done = 0;
			continue;
		}

		if (MSBBitX(prefix,j))
		{
			// make sure there is 1 pointer, else return lastFound
			if (cN->one)
			{
				if (cN->omaskLen > prefixLen)
				{
					done = 0;
					// return current node
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
		else
		{
			// make sure there is 0 pointer, else return lastFound
			if (cN->zero)
			{
				if (cN->zmaskLen > prefixLen)
				{
					done = 0;
					// return current node
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
		lastFound = cN;

	if (lastFound)
		return (lastFound);
	else
	{	
		if (lastValid)
			return (lastValid);
		else
			return FindNextLongestNodeC(start->parent, prefix, prefixLen);
	}

}

static void AddLinksToLongestPathsC(PTrieNodeC start, PTrieNodeC lastGoodSource, uint32_t prefix, int prefixLen, int dim)
{
	PTrieNodeC currentNode;
	PTrieNodeC tnode;

	if (!(start)) return;

	currentNode = start;

	if (currentNode->zero)
	{
		uint32_t nzp = (prefix >> currentNode->zmaskLen) ^ currentNode->zmask;
		int nzpl = prefixLen+currentNode->zmaskLen;
		AddLinksToLongestPathsC(currentNode->zero, lastGoodSource, nzp, nzpl, dim);
	}

	if(currentNode->one)
	{
		uint32_t nop = (prefix >> currentNode->omaskLen) ^ currentNode->omask;
		int nopl = prefixLen+currentNode->omaskLen;

		AddLinksToLongestPathsC(currentNode->one, lastGoodSource, nop, nopl,dim);
	}


	if (dim==1)
	{
		tnode = FindNextLongestNodeC(lastGoodSource->parent, prefix, prefixLen);
		currentNode->fail = tnode;

		if (currentNode->fail == currentNode)
			currentNode->fail = NULL;
	}

	if ((currentNode->dest != NULL) && (dim==0))
	{
		AddLinksToLongestPathsC(currentNode->dest,currentNode, 0x0, 0, 1);
	}


	return;

}

#endif


void egtpc_pool_left(void *user_ctx)
{
	struct trie_ctx *ctx;
	unsigned int x,y;
#ifdef EGT_PC
	unsigned int z;
#endif
	unsigned int sum;

	ctx = (struct trie_ctx *)user_ctx;
	x = pool_left(&ctx->pool[POOL_TRIENODE]);
	y = pool_left(&ctx->pool[POOL_TRIESUBNODE]);
	sum = x + y;
#ifdef EGT_PC
	z = pool_left(&ctx->pool[POOL_TRIENODEC]);
	sum += z;
	fpn_printf("EGTPC left pool = %u (%u,%u,%u)\n", sum, x,y,z);
#else
	fpn_printf("EGTPC left pool = %u (%u,%u)\n", sum, x,y);
#endif
}

void *egtpc_init(void *memstart, uint32_t memsize)
{
	struct trie_ctx *ctx;
	uint32_t nb;
	char *start = memstart;
	uint32_t pool_size;
	int size = memsize;

	ctx = (struct trie_ctx *)start;
	memset(start, 0, size);

	start += sizeof(*ctx);
	size -= sizeof(*ctx);

	nb = size / (10*(sizeof(struct TRIENODE) + POOL_OVERHEAD) +
#ifdef EGT_PC
			sizeof(struct TRIENODEC) + POOL_OVERHEAD +
#endif
			sizeof(struct TRIESUBNODE) + POOL_OVERHEAD);

	pool_size = pool_init(&ctx->pool[POOL_TRIENODE], sizeof(struct TRIENODE), start, nb*10);
	start += pool_size;
	size -= pool_size;

	pool_size = pool_init(&ctx->pool[POOL_TRIESUBNODE], sizeof(struct TRIESUBNODE), start, nb);
	start += pool_size;
	size -= pool_size;
#ifdef EGT_PC
	pool_size = pool_init(&ctx->pool[POOL_TRIENODEC], sizeof(struct TRIENODEC), start, nb);
	start += pool_size;
	size -= pool_size;
#endif

	/* Tell the compiler that these variables can be never read */
	(void)start;
	(void)size;

	InitGridOfTrie(ctx);

#ifdef EGT_PC
	ctx->rootC = NULL;
#endif

	TRACE_EGT("trie_init: using %u nodes\n", nb);

	TRACE_EGT("trie_init: return %p end %p start=%p size=%d\n", ctx, (char*)memstart + memsize, start, size);
	return (void *)ctx;
}

#ifdef DEBUG_PRINT_FILTER
static void print_filter(struct FILTER *wF)
{
	fpn_printf("id=%d cost=%d act=%d %u.%u.%u.%u/%d %u.%u.%u.%u/%d [%d/0x%x] [%d/0x%x] %i\n",
			wF->filtId,
			wF->cost,
			wF->action,
			EGT_NIPQUAD(wF->src), wF->src_plen,
			EGT_NIPQUAD(wF->dst), wF->dst_plen,
			ntohs(wF->srcport), ntohs(wF->srcport_mask),
			ntohs(wF->dstport), ntohs(wF->dstport_mask),
			wF->ul_proto);
}
#endif

int egtpc_update(struct FILTER *user_filter, void *user_ctx)
{
	trie_add_filter(user_filter, (TCTX)user_ctx);
	return 0;
}

int egtpc_final(void *user_ctx)
{
	TCTX ctx = (TCTX) user_ctx;
	TRACE_EGT("trie_final ctx = %p root=%p\n", ctx, ctx->trieroot);
#ifdef EGT_PC
	TrieNodeC *rootC;
#endif

#ifdef EGT_PC
	rootC = NewTrieNodeC(ctx);
#endif
	//AddSubNodeToTrieBase(ctx->trieroot);
	AddLinksToLongestPaths(ctx->trieroot, NULL, 0x0, 0, 0);

#ifdef EGT_PC
	AddLinksToLongestPathsC(rootC, NULL, 0, 0, 0);
	CreateCompressedTrie(rootC, ctx->trieroot, ctx);
	ctx->rootC = rootC;
#endif
	return 0;
}

