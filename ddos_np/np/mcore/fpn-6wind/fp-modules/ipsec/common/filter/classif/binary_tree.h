/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __BINARY_TREE__H__
#define __BINARY_TREE__H__

/* Node type */
typedef enum
{
  NODE,
  LIST
} eNodeType;

#include "fpn-queue.h"
#include "pool.h"

struct UserDataPointer {
	FPN_SLIST_ENTRY(UserDataPointer) m_nextPointer;
	/*
	struct {
		struct UserDataPointer *sle_next;
	}*/

	uint32_t m_filtId;
};

/* Node struct */
typedef struct _Node {
  struct _Node* m_left;
  struct _Node* m_right;
  union  {
    struct _Node* m_nextRoot;
    FPN_SLIST_HEAD(UserDataList, UserDataPointer) m_pUserValue;
  } nextNode;
  eNodeType     type;
} SixNode;

/* Delete function for user data store in the binary tree */
typedef void (*funcDeleteUserdata) (struct pool *pool, struct UserDataList *);

/* Tree function */

/* Insert a value in the binary tree that begins with root */
int insert_value(struct pool *, char* pAddr,
		 unsigned short sLength,
		 unsigned short sOffset,
		 unsigned short sPrefix,
		 SixNode* root,
		 SixNode** pStopNode);

/* Delete the whole branch beginning with start node */
/* (start_node is also removed) */
int delete_path(struct pool *pool_SixNode, struct pool *pool_UserData, SixNode* start_node, funcDeleteUserdata funcDelete, SixNode **pStack);

#ifdef __PRINT_DEBUG__
#include <stdio.h>
void print_tree(SixNode* node,
		int depth);
#endif

/* Find the last node used for the value pValue in the */
/* pRoot binary tree */
int find_last_node_used(SixNode* pRoot,
			char* pValue,
			unsigned short sLength,
			unsigned short sOffset,
			unsigned short sPrefix,
			SixNode** pLastNodeUsed,
			SixNode** pPreviousNodeUsed,
			SixNode** pEndNode);

#endif
