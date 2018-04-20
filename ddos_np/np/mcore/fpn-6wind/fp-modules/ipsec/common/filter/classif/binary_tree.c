/*
 * Copyright(c) 2007 6WIND
 * $Id: binary_tree.c,v 1.10 2009-04-08 10:32:19 gaudonville Exp $
 */
#include "fpn.h"
#include "pool.h"
#include "binary_tree.h"

/*********************************************/
/* Insert a undefined length value           */
/*********************************************/
/* Parameter:                                */
/*     char* pAddr: Value to insert
                    considered as an array of
		    bytes (must be in network order !!!)
       unsigned short sLength:
                    Length of the array in bits
       unsigned short sOffset:
                    Nb of offset bits that are
		    needed to add to get the first significant
		    bit.
		    This parameter is only relevant when
		    we pass a 32 bits length value but when
		    only the 20th last are interesting. We pass
		    an 12 offset and we only analyze the 20th bit.
		    (this avoid a copy and << operation before
		    adding a rule...)
       unsigned short sPrefix:
                    Prefix length of the rule
       SixNode* root:
                    Root node
       SixNode** pStopNode:
                    Last node used when the rule was
		    allocated (returned in order to fill the
		    m_nextRoot field...)

Example:
Meaning of sLenght, sOffset and sPrefix:
 Suppose that we would like to classify the following
value (seen as an array of bits)
  0001010001101100
     ***********
but the only value that we have to classify is underline
with stars.

Here is the value that we have to enter:

  <----sLength--->
  0001010001101100
  <-> sOffset
     <-sPrefix->

 sLength = 16
 sOffset = 3
 sPrefix = 11
*/
/*****************************************/
int insert_value(struct pool *pool_SixNode, char* pAddr, unsigned short sLength, unsigned short sOffset,
			unsigned short sPrefix, SixNode* root, SixNode** pStopNode)
{
	/* First bit to test */
	int sBit = (sLength - sOffset) - 1;

	/* First bytes to take into account (pointer offset) */
	int sAddrLength = ((sLength - sOffset) - 1)/ 8;

	/* Bit where to stop */
	int nStopBit = (sLength - sOffset) - sPrefix;

	/* Sanity check (the sum offset + prefix MUST NOT exceed total length) */
	if ((nStopBit < 0) ||
		(root == NULL) ||
		(pStopNode == NULL))
	{
		/* Prefix cannot be larger than the value length */
		/* or null pointer... */
		return -10;
	}

	/* End node == root */
	*pStopNode = root;

	/* Build the tree */
	while (sBit >= nStopBit)
	{
		FPN_TRACK();
		if  (*(pAddr + (sAddrLength - (sBit >> 3))) & (1 << (sBit & 0x7)))
		{
			if (!(*pStopNode)->m_left)
			{
				(*pStopNode)->m_left = (SixNode*)pool_alloc(pool_SixNode);

				if ((*pStopNode)->m_left == NULL)
					return -200;
			}

			*pStopNode = (*pStopNode)->m_left;
		}
		else
		{
			if (!(*pStopNode)->m_right)
			{
				(*pStopNode)->m_right = (SixNode*)pool_alloc(pool_SixNode);
				if ((*pStopNode)->m_right == NULL)
					return -200;
			}

			*pStopNode = (*pStopNode)->m_right;
		}

		sBit--;
	}

	return 0;
}

/*****************************************/
/* Delete tree branch function           */
/*****************************************/
int delete_path(struct pool *pool_SixNode, struct pool *pool_UserData,
		SixNode* start_node, funcDeleteUserdata funcDelete, SixNode **pStack)
{
	SixNode* pSaveNode;
	int nStackSize = 0;

	pStack[0] = start_node;

	while (nStackSize >= 0) {
		FPN_TRACK();
		while (pStack[nStackSize] != NULL) {
			FPN_TRACK();
			/* Check if we are on a list... */
			if ((pStack[nStackSize]->type == LIST) &&
				!FPN_SLIST_EMPTY(&pStack[nStackSize]->nextNode.m_pUserValue) &&
				(funcDelete != NULL)) {
				funcDelete(pool_UserData, &pStack[nStackSize]->nextNode.m_pUserValue);
				pStack[nStackSize]->type = NODE;
			}

			/* This is the a terminal node */
			if ((pStack[nStackSize]->m_left == NULL) &&
				(pStack[nStackSize]->m_right == NULL) &&
				(pStack[nStackSize]->nextNode.m_nextRoot == NULL)) {
				pool_free(pool_SixNode, pStack[nStackSize]);
				pStack[nStackSize] = NULL;
				break;
			}

			/* Case of left branch alone */
			if ((pStack[nStackSize]->m_left != NULL) &&
				(pStack[nStackSize]->m_right == NULL) &&
				(pStack[nStackSize]->nextNode.m_nextRoot == NULL) ) {
				pSaveNode = pStack[nStackSize];
				pStack[nStackSize] = pStack[nStackSize]->m_left;
				pool_free(pool_SixNode, pSaveNode);
			}
			else {
				/* Case of right branch alone */
				if ((pStack[nStackSize]->m_left == NULL) &&
					(pStack[nStackSize]->m_right != NULL) &&
					(pStack[nStackSize]->nextNode.m_nextRoot == NULL) ) {
					pSaveNode = pStack[nStackSize];
					pStack[nStackSize] = pStack[nStackSize]->m_right;
					pool_free(pool_SixNode, pSaveNode);
				}
				else {
					/* Case of next branch alone */
					if ((pStack[nStackSize]->m_left == NULL) &&
						(pStack[nStackSize]->m_right == NULL) &&
						(pStack[nStackSize]->nextNode.m_nextRoot != NULL) ) {
						pSaveNode = pStack[nStackSize];
						pStack[nStackSize] = pStack[nStackSize]->nextNode.m_nextRoot;
						pool_free(pool_SixNode, pSaveNode);
					}
					else {
						/* At least two values among right, left or nextRoot are valid */
						/* We have to fork... */
						if (pStack[nStackSize]->m_left != NULL) {
							if (pStack[nStackSize]->m_right != NULL) {
								/* Left and right... */
								pStack[nStackSize+1] = pStack[nStackSize]->m_right;
								pStack[nStackSize]->m_right = NULL;
								nStackSize++;
							}
							else {
								if (pStack[nStackSize]->nextNode.m_nextRoot != NULL) {
									/* Left and next root... */
									pStack[nStackSize+1] = pStack[nStackSize]->nextNode.m_nextRoot;
									pStack[nStackSize]->nextNode.m_nextRoot = NULL;
									nStackSize++;
								}
							}
						}
						else {
							/* The right link and the next_root are valid */
							pStack[nStackSize+1] = pStack[nStackSize]->nextNode.m_nextRoot;
							pStack[nStackSize]->nextNode.m_nextRoot = NULL;
							nStackSize++;
						}
					}
				}
			}
		}

		nStackSize--;
	}

	return 0;
}

#ifdef __PRINT_DEBUG__
/*****************************************/
/* Print tree function                   */
/*****************************************/
void print_tree(SixNode* node, int depth)
{
	if (node == NULL)
		return;

	/* Print the content of the current node */
	if (node->type == LIST) {
		struct UserDataPointer *pCurrent;
		fprintf(stderr, "Rules:");
		pCurrent = FPN_SLIST_FIRST(&node->nextNode.m_pUserValue);
		while (pCurrent) {
			fprintf(stderr, " %d ", pCurrent->m_filtId);
			pCurrent = FPN_SLIST_NEXT(pCurrent, m_nextPointer);
		}
		fprintf(stderr, "\n");
	}

	if (node->m_left != NULL)
	{
		fprintf(stderr, "1");
		print_tree(node->m_left, depth+1);
	}
	if (node->m_right != NULL)
	{
		fprintf(stderr, "0");
		print_tree(node->m_right, depth+1);
	}

	if ((node->type == NODE) &&
		(node->nextNode.m_nextRoot != NULL)) {
		fprintf(stderr, "Next root..\n");
		print_tree(node->nextNode.m_nextRoot, depth+1);
	}
}
#endif /* __PRINT_DEBUG__ */

/******************************************************/
/* Find the last node used by the rule and its        */
/* ancestor (if it exists)                            */
/******************************************************/
/* In values:                                         */
/* ----------                                         */
/*    SixNode* pRoot: root node where to search       */
/*    char* pValue: value to search                   */
/*    u s sLength: length of the value                */
/*    u s sOffset: offset of the value                */
/*    u s sPrefix: Prefix length of the value         */
/* Out values:                                        */
/* -----------                                        */
/*    SixNode** pLastNodeUsed: last use node          */
/*    SixNode** pPreviousNodeUsed: previous node used */
/*    SixNode** pEndNode: node where whe stop         */
/******************************************************/
/* If the whole tree is unused then:                  */
/*     pPreviousNodeUsed = NULL and                   */
/*     pLastNodeUsed = ROOT                           */
/* If the node where we stop has parent               */
/*     If there's another root node after:            */
/*       pPreviousNodeUsed = node where we stop       */
/*       pLastNodeUsed = next root                    */
/*     Otherwise:                                     */
/*       pPreviousNodeUsed = node where we stop       */
/*       pLastNodeUsed = node where we stop           */
/******************************************************/
int find_last_node_used(SixNode* pRoot,
						char* pValue,
						unsigned short sLength,
						unsigned short sOffset,
						unsigned short sPrefix,
						SixNode** pLastNodeUsed,
						SixNode** pPreviousNodeUsed,
						SixNode** pEndNode)
{
	SixNode* pCurrentNode;

	short sBit = (sLength - sOffset) - 1;
	short sValueLength = (sBit >> 3);
	int nStopBit = (sLength - sOffset) - sPrefix;

	*pLastNodeUsed = pRoot;
	*pPreviousNodeUsed = NULL;

	/* Sanity check */
	if ((pRoot == NULL) ||
		(nStopBit < 0))
	{
		/* Null pointer or prefix > length... */
		return -100;
	}

	/* Snaity check for NULL values */
	if (pValue == NULL) {
		if (sPrefix != 0) {
			/* NULL value only accepted for a 0 prefix length... */
			return -100;
		}
	}

	pCurrentNode = pRoot;

	while ((pCurrentNode != NULL) && (sBit >= nStopBit))
	{
		FPN_TRACK();
		FPN_ASSERT(pValue + (sValueLength - (sBit >> 3) ) != NULL);
		if  (*(pValue + (sValueLength - (sBit >> 3) )) & (1 << (sBit & 0x7)))
		{
			if (pCurrentNode->m_left == NULL)
			{
				/* Rule not found */
				return -50;
			}

			/* We can follow the left link */
			/* Test if this is a used node or not... */
			if ((pCurrentNode->m_right != NULL) ||
				!FPN_SLIST_EMPTY(&pCurrentNode->nextNode.m_pUserValue) ||
				(pCurrentNode->nextNode.m_nextRoot != NULL) )
			{
				*pLastNodeUsed = pCurrentNode->m_left;
				*pPreviousNodeUsed = pCurrentNode;
			}
			pCurrentNode = pCurrentNode->m_left;
		}
		else
		{
			if (pCurrentNode->m_right == NULL)
			{
				/* Rule not found */
				return -50;
			}

			/* We can follow the right link */
			/* Test if this is a used node or not... */
			if ((pCurrentNode->m_left != NULL) ||
				(pCurrentNode->nextNode.m_nextRoot != NULL) )
			{
				*pLastNodeUsed = pCurrentNode->m_right;
				*pPreviousNodeUsed = pCurrentNode;
			}
			pCurrentNode = pCurrentNode->m_right;
		}

		sBit--;
	}

	/* We stop on a branch that is still used after... */
	/* The last used node if we are not in the "last" tree */
	/* is the next root if this root exists */
	if (pCurrentNode != NULL) {
		if ((pCurrentNode->m_left != NULL) ||
			(pCurrentNode->m_right != NULL)) {
			if ((pCurrentNode->type == NODE) &&
				(pCurrentNode->nextNode.m_nextRoot != NULL)) {
				*pLastNodeUsed = pCurrentNode->nextNode.m_nextRoot;
				*pPreviousNodeUsed = pCurrentNode;
			}
			else {
				*pLastNodeUsed = pCurrentNode;
				*pPreviousNodeUsed = pCurrentNode;
			}
		}
	}

	*pEndNode = pCurrentNode;

	return 0;
}
