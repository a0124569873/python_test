/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __CLASSIFIER_H__
#define __CLASSIFIER_H__

#include "pool.h"
/* Binary tree structure */
#include "binary_tree.h"

/* Return 0 if the two parameters are equal */
/*        > 0 if the first paramater is > than the second */
/*        < 0 if the first paramater is < than the second */
typedef int (*funcCompare) (const uint32_t, const uint32_t);

/* Return 0 (FALSE) if the data is invalid */
/*       != 0 if the data is valid */
typedef int (*funcValid) (const uint32_t);

typedef struct {
	void* m_pData;		/* Data for the rule */
	int m_nPrefixLength;	/* Prefix length in bit */
} RuleValue_t;

/* Context use to "linearize" the initial recursive function match_value */
typedef struct {
	SixNode* pNode;	/* Node where we stop */
	int   nBit;	/* Number of bits we have already read */
	int   nLevel;	/* Field number */
	int   nLength;	/* Length of the field */
} MatchContext;


/****************************/
/* CLASSIFIER DEFINITION    */
/****************************/
typedef struct {

	/* Number of fields to classify */
	unsigned int m_nNbFields;

	/* Fields description */
	int *m_pClassifierDescription;

	/* Function used to compare two user-data values */
	funcCompare m_pFunc;

        /* Function used to know whether or not a rule is valid */
        funcValid m_pFuncValid;

	/* Root of the binary tree */
	SixNode *m_pRoot;

	/* Context of matching, used to "linearize"
	 * a recursive function. One per core.
	 */
	MatchContext *m_pContext[FPN_MAX_CORES];

	/* Depth of the classifier in bits */
	int m_nDepth;
	SixNode **m_pStack;
 	struct pool m_poolSixNode;
 	struct pool m_poolUserData;
} SixClassifier;

/************************************************/
/* Function to get the "best" value in the list */
/************************************************/
static inline void get_list_value(	SixNode* pNode,
					SixClassifier* pClassifier,
					uint32_t *filtId)
{

	if ((pClassifier->m_pFuncValid == NULL) && (pClassifier->m_pFunc == NULL)) {
		*filtId = FPN_SLIST_FIRST(&pNode->nextNode.m_pUserValue)->m_filtId;
		return;
	}

	if (pClassifier->m_pFuncValid) {
		struct UserDataPointer* pData;
		/* There is a validation function... */
		
		/* Two case: either we have already a result: */
		/*        - we have to look for the first valid data that is */
		/*          better than the result already found */
		/* or we did not have a result: */
		/*        - we have to find the first valid user_data */
		if (*filtId) {
			pData = FPN_SLIST_FIRST(&pNode->nextNode.m_pUserValue);
			
			while (pData != NULL) {
				FPN_TRACK();
				if (pClassifier->m_pFuncValid(pData->m_filtId)) {
					if (pClassifier->m_pFunc(*filtId, pData->m_filtId) <= 0) {
						*filtId = pData->m_filtId;
					}
					else {
						/* We found a valid rule but its priority is inferior to */
						/* the one we already found => it is useless to continue */
						/* looking for a result because the list is ordered... */
						break;
					}
				}
				pData = FPN_SLIST_NEXT(pData, m_nextPointer);
			}
		}
		else {
			/* We have to find the first valid structure */
			pData = FPN_SLIST_FIRST(&pNode->nextNode.m_pUserValue);
			while ((pData != NULL) &&
					(pClassifier->m_pFuncValid(pData->m_filtId) == 0)) {
				FPN_TRACK();
				pData = FPN_SLIST_NEXT(pData, m_nextPointer);
			}
			
			if (pData) {
				/* Assign the result */
				*filtId = pData->m_filtId;
			}
		}
	}
	else {
		/* If we have already found a value, we have to compare it */
		/* with the value in the list */
		if (*filtId) {
			if ((pClassifier->m_pFunc(*filtId, FPN_SLIST_FIRST(&pNode->nextNode.m_pUserValue)->m_filtId) <= 0)) {
				*filtId = FPN_SLIST_FIRST(&pNode->nextNode.m_pUserValue)->m_filtId;
			}
		}
		else {
			/* This is the first found rule => it is the best one... */
			*filtId = FPN_SLIST_FIRST(&pNode->nextNode.m_pUserValue)->m_filtId;
		}
	}
}

/*****************************************/
/* Internal matching function            */
/*****************************************/
static inline void match_fields(register void** pPacket, register SixClassifier* pClassifier,
		uint32_t* filtId)
{
	/* Try to force each variable in a register */
	register int nStackSize;
	register MatchContext *pCurrentContext;
	register char* pValue;
	register SixNode* pBranchRootNode;

	/* Init */
	pCurrentContext = pClassifier->m_pContext[fpn_get_core_num()];
	nStackSize = 0;

	/* Start point of the process */
	pCurrentContext->pNode = pClassifier->m_pRoot;
	pCurrentContext->nBit = pClassifier->m_pClassifierDescription[0] - 1;
	pCurrentContext->nLength = pCurrentContext->nBit >> 3;
	pCurrentContext->nLevel = 0;

	/* While the stack is not totally empty we continue... */
	while (nStackSize >= 0) {
		FPN_TRACK();

		while (pCurrentContext->pNode != NULL) {

			FPN_TRACK();
			/********************************************************/
			/* First check : does the nLevel packet value is NULL ? */
			/********************************************************/

			/* If it is the case we have to move to the next root if it exists... */
			if (pPacket[pCurrentContext->nLevel] == NULL) {

				/* Does the current node is a LIST or a next node ? */
				if (pCurrentContext->pNode->type == NODE) {
					if (pCurrentContext->pNode->nextNode.m_nextRoot != NULL) {
						/**************************************/
						/* We jump to the next binary tree    */
						/* For this we update the current     */
						/* context:                           */
						/*    - pNode = nextRoot              */
						/*    - nBit = nextLevel classifier   */
						/*             number of bits         */
						/*    - nLength = number of byte to   */
						/*                take into account   */
						/**************************************/
						pCurrentContext->nLevel++;
						pCurrentContext->pNode = pCurrentContext->pNode->nextNode.m_nextRoot;
						pCurrentContext->nBit = pClassifier->m_pClassifierDescription[pCurrentContext->nLevel] - 1;
						pCurrentContext->nLength = (pCurrentContext->nBit) >> 3;

						/* Continue the search with the next values */
						continue;
					}
					else {
						/***********************************************************/
						/* There's no "ANY" rule in this classifier for this field */
						/* We force a pop by exiting the loop                      */
						/***********************************************************/
						break;
					}
				}
				else {
					/*****************************************************/
					/* We are on a leaf, we have to select the best rule */
					/*****************************************************/
					get_list_value(	pCurrentContext->pNode,
									pClassifier,
									filtId);
					break;
				}
			} /* END pPacket[XX] == NULL */
			else {
				/* the pPacket[XX] value is not null */

				/* Fill the pValue pointer ... */
				pValue = (char*)pPacket[pCurrentContext->nLevel];

				/******************************/
				/* Look for each bit matching */
				/******************************/
				while	(pCurrentContext->pNode &&
						(pCurrentContext->nBit >= 0)) {

					/********************************************/
					/* Did we match a branch for the next field */
					/********************************************/

					/************************/
					/* Test the node nature */
					/************************/
					/************************/
					/********************************************************/
					/* 1) If it is a list compare the rule                  */
					/* 2) If it is a root node we follow this root node by  */
					/*    storing it into the matching context (we simulate */
					/*    a recursive call                                  */
					/********************************************************/
					if (pCurrentContext->pNode->type == LIST) {
						/****************************************************************/
						/* If we are in the last tree and if we found a rule that match */
						/* during the lookup => compare it with the rule !              */
						/****************************************************************/
						get_list_value(	pCurrentContext->pNode,
										pClassifier,
										filtId);

						/* Left or right branch ? */
						if  (*(pValue + (pCurrentContext->nLength - (pCurrentContext->nBit >> 3))) & (1 << (pCurrentContext->nBit & 0x7))) {
							pCurrentContext->pNode = pCurrentContext->pNode->m_left;
						}
						else {
							pCurrentContext->pNode = pCurrentContext->pNode->m_right;
						}

						pCurrentContext->nBit--;
					}
					else {
						/**************************************************/
						/* We store the next node we want to examine and  */
						/* in the next mathcing context we will follow    */
						/* the next root node                             */
						/**************************************************/
						if (pCurrentContext->pNode->nextNode.m_nextRoot != NULL) {
							/* Instead of a recursive call with the next field and the next root */
							/* we will push the context on the stack... */

							pBranchRootNode = pCurrentContext->pNode;
							/* Left or right branch ? */
							if  (*(pValue + (pCurrentContext->nLength - (pCurrentContext->nBit >> 3))) & (1 << (pCurrentContext->nBit & 0x7))) {
								pCurrentContext->pNode = pCurrentContext->pNode->m_left;
							}
							else {
								pCurrentContext->pNode = pCurrentContext->pNode->m_right;
							}

							pCurrentContext->nBit--;

							nStackSize++;
							pCurrentContext++;
							pCurrentContext->pNode = pBranchRootNode->nextNode.m_nextRoot;
							pCurrentContext->nLevel = (pCurrentContext-1)->nLevel + 1;
							pCurrentContext->nBit = pClassifier->m_pClassifierDescription[pCurrentContext->nLevel] - 1;
							pCurrentContext->nLength = pCurrentContext->nBit >> 3;

							goto exit_while;
						}
						else {
							/* Left or right branch ? */
							if  (*(pValue + (pCurrentContext->nLength - (pCurrentContext->nBit >> 3))) & (1 << (pCurrentContext->nBit & 0x7))) {
								pCurrentContext->pNode = pCurrentContext->pNode->m_left;
							}
							else {
								pCurrentContext->pNode = pCurrentContext->pNode->m_right;
							}
							pCurrentContext->nBit--;
						}
					}

				} // END of while (pCurrentContext->pNode && (pCurrentContext->nBit >= 0))
				// End of value binary tree search

				/*************************/
				/* Analyze the end state */
				/*************************/
				if (pCurrentContext->pNode != NULL) {
					/*******************************************************************************************/
					/* Did we stop on an "endpoint" of the tree ?                                              */
					/* 2 cases: 1) we have already found a result : we have to compare it with the found rule  */
					/*          2) we don't find a result yet : we store this one                              */
					/*******************************************************************************************/
					if (pCurrentContext->pNode->type == LIST) {
						get_list_value(	pCurrentContext->pNode,
										pClassifier,
										filtId);
						break;
					}
					else {
						/* Did we stop where a nextRoot node is present ? */
						if (pCurrentContext->pNode->nextNode.m_nextRoot != NULL) {
							/* Get the next field and the next root */
							pCurrentContext->nLevel++;
							pCurrentContext->nBit = pClassifier->m_pClassifierDescription[pCurrentContext->nLevel] - 1;
							pCurrentContext->nLength = (pCurrentContext->nBit) >> 3;
							pCurrentContext->pNode = pCurrentContext->pNode->nextNode.m_nextRoot;
						}
						else {
							/* The node where we stop do not have */
							/* a next node pointer... */
							/* We do not match this branch => we have to leave it ! */
							break;
						}
					}
				}
				else {
					/* We stop on a node where no rule is store... */
					/* Stop looking in this branch... */
					break;
				}
			} /* END of test on pPacket[XX] == NULL */

			/* Exit for the branching... */
			exit_while:
				;
		} /* End of while pCurrentContext->pNode != NULL */

		/* Pop the elements on the stack */
		nStackSize--;

		/* Update the values only if */
		/* it is necessary... */
		if (nStackSize >= 0) {
			pCurrentContext--;
		}
	} // END of test on STACK_SIZE...
}
/* End of match_fields */

/*
   Structure defined in files hidden from the user...
   typedef int (*funcCompare) (const void *, const void *);
   struct RuleValue_t {
     void* pData;
     int nPrefixLength;
   };
 */

/* Allocate and initialize internal structure of a classifier */
/* The pFunc function MUST accept two parameters */
/*    pFunc(const void* A, const void* B) */
/*     A and B are two pointers to the associated value of two rules */
/*     it returns: */
/*          0 if the arguments are equal */
/*          < 0 if A < B */
/*          > 0 if A > B */
/* The pFuncValid function MUST accept one parameter */
/*     pFuncValid(const void* A) */
/*     A is a pointer to an associated value of a rule */
/*     it returns: */
/*          0 if the data is not valid */
/*          1 otherwise */
int initClassifier(char *memory, uint32_t memsize, unsigned int nNbFields,
				   int* pClassifierDescription,
				   funcCompare pFunc,
		                   funcValid pFuncValid);

/* Add the specified rule to the classifier */
int addRule(SixClassifier* pClassifier,
		    RuleValue_t* pRuleDefinition,
		    uint32_t filtId);

/* Delete the specified rule */
int deleteRule(SixClassifier* pClassifier,
		       RuleValue_t* pRuleDefinition,
		    uint32_t filtId);

/* Delete and free the internal structure of a classifier... */
int deleteClassifier(SixClassifier* pClassifier);

/* Delete all the rules */
int resetClassifier(SixClassifier* pClassifier);
#ifdef __PRINT_DEBUG__
void print_classifier(SixClassifier *pClassifier);
#endif
#endif
