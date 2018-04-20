/*
 * Copyright(c) 2007 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#include "pool.h"
#include "classifier_error.h"

#include "classifier.h"


/* Delete function declaration */
static void deleteUserDataList(struct pool *pool, struct UserDataList *pList);

/**************************************/
/* Init struct used by the classifier */
/**************************************/

int initClassifier(char *memory, uint32_t memsize, unsigned int nNbFields,
		   	int* pClassifierDescription, funcCompare pFunc, funcValid pFuncValid)
{
	SixClassifier* pClassifier;
	int nTotalSize;
	unsigned int i;
	uint32_t pool_size;
	int nSixNode, nUserData;
	int size = memsize;

	pClassifier = (SixClassifier*) memory;
	memory += sizeof(SixClassifier);
	size -= sizeof(SixClassifier);
	memset(pClassifier, 0, sizeof(SixClassifier));

	/* Copy the classifier description... */
	pClassifier->m_pClassifierDescription = (int*)memory;
	memory += sizeof(int)*nNbFields;
	size -= sizeof(int)*nNbFields;

	/* Copy the fields description */
	memcpy(pClassifier->m_pClassifierDescription, pClassifierDescription, sizeof(int)*nNbFields);

	/* Update the classifier description : instead of being in bytes */
	/* it will be in bits */
	nTotalSize = 0;
	for (i = 0; i < nNbFields ; i++) {
		FPN_TRACK();
		pClassifier->m_pClassifierDescription[i] = pClassifier->m_pClassifierDescription[i] * 8;
		nTotalSize += pClassifier->m_pClassifierDescription[i];
	}

	/* Number of fields */
	pClassifier->m_nNbFields = nNbFields;

	/* Store the comparison function */
	pClassifier->m_pFunc = pFunc;

	/* Store the validation function */
	pClassifier->m_pFuncValid = pFuncValid;

	/* Context allocation */
	for (i = 0;  i < FPN_MAX_CORES; i++) {
		FPN_TRACK();
		pClassifier->m_pContext[i] = (MatchContext*)memory;
		memory += (nTotalSize * sizeof(MatchContext));
		size -= (nTotalSize * sizeof(MatchContext));
	}

	/* The max tree depth... */
	pClassifier->m_nDepth = nTotalSize;

	pClassifier->m_pStack = (SixNode **)memory;
	memory += pClassifier->m_nDepth * sizeof(SixNode *);
	size -= pClassifier->m_nDepth * sizeof(SixNode *);

	/* 1/3 for UserDataPointer, 2/3 for SixNode */
	nUserData = (size / 3) / (sizeof(struct UserDataPointer) + POOL_OVERHEAD);
	nSixNode = (2 * size / 3) / (sizeof(SixNode) + POOL_OVERHEAD);

	pool_size = pool_init(&pClassifier->m_poolSixNode, sizeof(SixNode), memory, nSixNode);
	memory += pool_size;

	pool_init(&pClassifier->m_poolUserData, sizeof(struct UserDataPointer), memory, nUserData);

	pClassifier->m_pRoot = (SixNode*)pool_alloc(&pClassifier->m_poolSixNode);

	if (pClassifier->m_pRoot == NULL)
		return -1;

	return 0;
}

/*************************************/
/* Delete all mem. allocated for the */
/* classifier                        */
/*************************************/
int deleteClassifier(SixClassifier* pClassifier)
{
	/* Sanity check */
	if (pClassifier == NULL) {
		/* Invalid value */
		return CLS_INCORRECTVALUE;
	}

	/*************************/
	/* Remove binary tree(s) */
	/*************************/

	if (pClassifier->m_pRoot != NULL) {
		memset(pClassifier->m_pStack, 0, pClassifier->m_nDepth * sizeof(SixNode *)); /* init the stack */
		delete_path(&pClassifier->m_poolSixNode, &pClassifier->m_poolUserData,
				pClassifier->m_pRoot, deleteUserDataList, pClassifier->m_pStack);
	}

	return CLS_NOERR;
}

/***********************************************/
/* Add a rule to the classifier                */
/* This operation is made in two steps         */
/* 1°) check that the rule matches with        */
/*     the field definition of the classifier  */
/* 2°) add the rule to the binary tree         */
/***********************************************/
int addRule(SixClassifier* pClassifier,
			RuleValue_t* pRuleDefinition,
			uint32_t filtId)
{
	SixNode *pStopNode,
			*pRoot;
	int		i,
			nError,
			nNbFields,
			nResult;

	/* Init */
	i = 0;
	nError = 0;
	pStopNode = NULL;

	/* Sanity check */
	if ((pClassifier == NULL) || (pRuleDefinition == NULL)) {
		/* Bad pointer ! */
		return CLS_INCORRECTVALUE;
	}

	nNbFields = pClassifier->m_nNbFields;

	/*****************************/
	/* STEP 1:                   */
	/*****************************/
	/* Check the rule definition */
	/*****************************/
	while (!nError &&
		(i < nNbFields)) {
		/* Compare the rule constraint with */
		/* the classifier definition for the field i */
		if (pRuleDefinition[i].m_nPrefixLength > pClassifier->m_pClassifierDescription[i]) {
			nError = CLS_INCOMPATIBLE_RULE_DEF;
		}

		i++;
	}

	/* Test if there was no difference between rule definition */
	/* and classifier definition */
	if (nError != 0) {
		return nError;
	}

	/******************************************/
	/* STEP 2:                                */
	/******************************************/
	/* We add the value to the binary tree... */
	/******************************************/
	i = 0;

	pRoot = pClassifier->m_pRoot;

	while (i < nNbFields) {
		nResult = insert_value(&pClassifier->m_poolSixNode, pRuleDefinition[i].m_pData,
								pClassifier->m_pClassifierDescription[i],
								0,
								pRuleDefinition[i].m_nPrefixLength,
								pRoot,
								&pStopNode);

		if (nResult != 0) {
			switch (nResult) {
			case -10: {
				return CLS_INCORRECTVALUE;
					  }
			case -200: {
				return CLS_NOMEM;
					   }
			default: {
				return CLS_INCORRECTVALUE;
					 }
			}
		}

		/* Next field...  */
		i++;

		/* If there's another field to test, we have to check whether or not */
		/* the next tree root is already allocated */
		if (i < nNbFields) {
			if (pStopNode->nextNode.m_nextRoot == NULL) {
				pStopNode->nextNode.m_nextRoot = (SixNode*)pool_alloc(&pClassifier->m_poolSixNode);

				if (pStopNode->nextNode.m_nextRoot == NULL)
					return CLS_NOMEM;
				
			}

			/* Next root */
			pRoot = pStopNode->nextNode.m_nextRoot;
		}
	}

	/* We add the rule where we stop... */
	if (pStopNode != NULL) {
		pStopNode->type = LIST;

		/* We store the rule */
		/* Two cases here: */
		/*   1°) this node is free: we have to create the list struct */
		/*       to store the rule */
		/*   2°) there's already a rule associated to this node */
		/*       so we have to insert the rule in the list */
		if (FPN_SLIST_EMPTY((&pStopNode->nextNode.m_pUserValue))) {
			struct UserDataPointer* pUserDataPointer;

			/* Allocation of the first element of the list */
			pUserDataPointer = (struct UserDataPointer*)pool_alloc(&pClassifier->m_poolUserData);

			if (pUserDataPointer == NULL)
				return CLS_NOMEM;

			pUserDataPointer->m_filtId = filtId;

			/* Insert the first element */
			FPN_SLIST_INSERT_HEAD(&pStopNode->nextNode.m_pUserValue, pUserDataPointer, m_nextPointer);

		} else {
			/* We have to insert the rule in the list ! */
			struct UserDataPointer* pCurrent, *pPrevious;
			struct UserDataPointer* pUserDataPointer;

			/* Allocation of the element of the list */
			pUserDataPointer = (struct UserDataPointer*)pool_alloc(&pClassifier->m_poolUserData);

			if (pUserDataPointer == NULL)
				return CLS_NOMEM;

			pUserDataPointer->m_filtId = filtId;

			pCurrent = FPN_SLIST_FIRST(&pStopNode->nextNode.m_pUserValue);
			pPrevious = NULL;

			if (pClassifier->m_pFunc) {
			/* We sort the list with decreasing number... the rule with the highest priority is at the */
			/* top of the list */
				while ((pCurrent != NULL) &&
					(pClassifier->m_pFunc(pUserDataPointer->m_filtId, pCurrent->m_filtId) < 0) ) {
					FPN_TRACK();
					pPrevious = pCurrent;
					pCurrent = FPN_SLIST_NEXT(pCurrent, m_nextPointer);
				}
			}

			/* Insert according to the last found position */
			if (pPrevious == NULL) {
				FPN_SLIST_INSERT_HEAD(&pStopNode->nextNode.m_pUserValue, pUserDataPointer, m_nextPointer);
			}
			else {
				FPN_SLIST_INSERT_AFTER(pPrevious, pUserDataPointer, m_nextPointer);
			}
		}
	}

	return CLS_NOERR;
}


/*************************************/
/* Delete a rule from the classifier */
/*************************************/

#ifdef __PRINT_DEBUG__
void print_classifier(SixClassifier *pClassifier) {

	print_tree(pClassifier->m_pRoot, pClassifier->m_nDepth);
}
#endif
int deleteRule(	SixClassifier* pClassifier,
				RuleValue_t* pRuleDefinition,
				uint32_t filtId)
{
	SixNode *pLastNodeUsed,
			*pLastPreviousNodeUsed,
			*pCurrentRoot,
			*pEndNode = NULL,
			*pCurrentLastNodeUsed,
			*pCurrentPreviousNodeUsed;

	unsigned int nLevel = 0;
	int nResult;

	if ((pClassifier == NULL) || (pRuleDefinition == NULL)) {
		/* Invalid pointer */
		return CLS_INCORRECTVALUE;
	}

	/* Init the last node */
	pLastNodeUsed = pClassifier->m_pRoot;
	pLastPreviousNodeUsed = pClassifier->m_pRoot;

	pCurrentRoot = pClassifier->m_pRoot;

	/* Search through all the fields */
	while (nLevel < pClassifier->m_nNbFields) {

		/* Find the last node used for the current rule...*/
		nResult = find_last_node_used(	pCurrentRoot,
										pRuleDefinition[nLevel].m_pData,
										pClassifier->m_pClassifierDescription[nLevel],
										0,
										pRuleDefinition[nLevel].m_nPrefixLength,
										&pCurrentLastNodeUsed,
										&pCurrentPreviousNodeUsed,
										&pEndNode);

		if ((nResult != 0) ||
			(pEndNode == NULL) ) {
			/* Rule not found ! */
			return CLS_RULENOTFOUND;
		}

		/* If the previous node used is not null */
		/* we found a branch in this tree that is only used by the rule */
		/* that we are deleting */
		if (pCurrentPreviousNodeUsed != NULL) {
			pLastNodeUsed = pCurrentLastNodeUsed;
			pLastPreviousNodeUsed = pCurrentPreviousNodeUsed;
		}

		/* Next root */
		if (pEndNode->type == NODE) {
			pCurrentRoot = pEndNode->nextNode.m_nextRoot;
		}

		nLevel++;
	}

	FPN_ASSERT(pEndNode != NULL);

	/* The last node MUST be a list */
	if (pEndNode->type == LIST) {
		struct UserDataPointer *pCurrentPointer;

		pCurrentPointer = FPN_SLIST_FIRST(&pEndNode->nextNode.m_pUserValue);

		if (pClassifier->m_pFunc)
			while ( (pCurrentPointer != NULL) &&
				(pClassifier->m_pFunc(pCurrentPointer->m_filtId, filtId) != 0)) {
				FPN_TRACK();
				pCurrentPointer = FPN_SLIST_NEXT(pCurrentPointer, m_nextPointer);
			}

		/* Did we find the rule ? */
		if (pCurrentPointer == NULL) {
			/* Error we did not find the rule */
		  	return CLS_RULENOTFOUND;
		}

		/* Remove the rule from the list */
		FPN_SLIST_REMOVE(&pEndNode->nextNode.m_pUserValue,
				 pCurrentPointer,
				 UserDataPointer,
				 m_nextPointer);

		/* We have remove the list element, now free it and free the user data associated... */
		pool_free(&pClassifier->m_poolUserData, pCurrentPointer);

		/* Remove the whole unused branch ? */
		if (FPN_SLIST_EMPTY(&pEndNode->nextNode.m_pUserValue)) {
			/* Special case : we will delete the whole tree... */
			if ((pLastPreviousNodeUsed == pClassifier->m_pRoot) &&
				(pLastNodeUsed == pClassifier->m_pRoot)) {
					/* The whole struct will be cleared ! */
					memset(pClassifier->m_pStack, 0, pClassifier->m_nDepth * sizeof(SixNode *)); /* init the stack */
					delete_path(&pClassifier->m_poolSixNode, &pClassifier->m_poolUserData,
								pClassifier->m_pRoot,
								deleteUserDataList,
								pClassifier->m_pStack);


					/* We have to reallocate the root node otherwise we will */
					/* have a segfault during the next addRule call */
					pClassifier->m_pRoot = (SixNode*)pool_alloc(&pClassifier->m_poolSixNode);
			}
			else {
				if (pLastPreviousNodeUsed != pLastNodeUsed) {
					/* We delete only a "branch", we only have to find the relationship */
					/* between the previous node used and the last node used... */
					if (pLastPreviousNodeUsed->m_left == pLastNodeUsed) {
						pLastPreviousNodeUsed->m_left = NULL;
					}
					else {
						if (pLastPreviousNodeUsed->m_right == pLastNodeUsed) {
								pLastPreviousNodeUsed->m_right = NULL;
						}
						else {
							if (pLastPreviousNodeUsed->nextNode.m_nextRoot == pLastNodeUsed) {
								pLastPreviousNodeUsed->nextNode.m_nextRoot = NULL;
							}
							else {
								/* No relationship between the previous and the last node */
								/* internal error ! */
								return CLS_INTERNALERROR;
							}
						}
					}
					/* delete the branch */
					memset(pClassifier->m_pStack, 0, pClassifier->m_nDepth * sizeof(SixNode *)); /* init the stack */
					delete_path(&pClassifier->m_poolSixNode, &pClassifier->m_poolUserData,
							pLastNodeUsed, deleteUserDataList, pClassifier->m_pStack);
				}
				else {
					/* There's no more list in this node... */
					/* The node type is no longer a list */
					/* This branch is nevertheless still used */
					/* So we only have to free the list head and reinit the node... */
					pEndNode->type = NODE;
					FPN_SLIST_INIT(&pEndNode->nextNode.m_pUserValue);
				}
			}
		}
	}
	else {
		/* The node where we stop wasn't a LIST node ! => error rule not found */
		return CLS_RULENOTFOUND;
	}

	return CLS_NOERR;
}

/****************************************/
/* Delete all the rules                 */
/****************************************/
/* Parameters:                          */
/*    SixClassifier* pClassifier:       */
/*       Classifier where to delete all */
/*       the rules                      */
/****************************************/
/* Goal:                                */
/*    Remove all the rules (destroy the */
/*    binary tree)                      */
/****************************************/
/* Return code:                         */
/*    CLS_INCORRECTVALUE:               */
/*      Bad pClassifier pointer         */
/*    CLS_NOMEM:                        */
/*      Memory allocation pb            */
/*    CLS_NOERR: OK                     */
/****************************************/
int resetClassifier(SixClassifier* pClassifier)
{
	/* Check the pointer... */
	if (pClassifier == NULL) {
		return CLS_INCORRECTVALUE;
	}

	/*************************/
	/* Remove binary tree(s) */
	/*************************/
	memset(pClassifier->m_pStack, 0, pClassifier->m_nDepth * sizeof(SixNode *)); /* init the stack */
	delete_path(&pClassifier->m_poolSixNode, &pClassifier->m_poolUserData,
				pClassifier->m_pRoot,
				deleteUserDataList,
				pClassifier->m_pStack);

	/*************************/
	/* Realloc the root node */
	/*************************/
	pClassifier->m_pRoot = (SixNode*)pool_alloc(&pClassifier->m_poolSixNode);

	if (pClassifier->m_pRoot == NULL)
		return CLS_NOMEM;

	return CLS_NOERR;
}

/***************************************************************************/
/* Delete function for the user_data (delete all the elements in the list) */
/***************************************************************************/
static void deleteUserDataList(struct pool *pool, struct UserDataList *pList)
{
	struct UserDataPointer *pCurrent, *pNext;

	/* Avoid memory pb... */
	if (pList == NULL) {
		return;
	}

	/* Free the elements of the list */
	pCurrent = FPN_SLIST_FIRST(pList);

	while (pCurrent != NULL) {
		FPN_TRACK();
		pNext = FPN_SLIST_NEXT(pCurrent, m_nextPointer);
		FPN_SLIST_REMOVE(pList, pCurrent, UserDataPointer, m_nextPointer);
		/* Free the list element */
		pool_free(pool, pCurrent);
		pCurrent = pNext;
	}

}

/* END OF FILE */
