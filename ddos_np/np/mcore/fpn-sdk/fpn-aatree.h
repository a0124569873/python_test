/*
 * Copyright (c) 2011 6WIND
 */
/*
 * Implementation of an AA tree (Arne Andersson tree) for fast insertion
 * of objects in an ordered list.
 *
 * AA trees are a form of self balanced binary tree.
 *
 * original paper from Arne Andersson:
 * http://user.it.uu.se/~arnea/abs/simp.html
 */

#ifndef __FPN_AATREE_H__
#define __FPN_AATREE_H__

struct fpn_aatree_node;
typedef struct fpn_aatree_node fpn_aatree_node_t;

struct fpn_aatree_node {
#ifdef CONFIG_MCORE_AATREE_SANITY_CHECK
	uint32_t magic;
#endif
	uint64_t priority;

	FPN_TAILQ_ENTRY(fpn_aatree_node) next;

	int level;
	fpn_aatree_node_t *child[2];
	fpn_aatree_node_t *parent;
	int dir; /* direction (left/right) as child of our parent */
};

FPN_TAILQ_HEAD(fpn_aatree_list, fpn_aatree_node);
typedef struct fpn_aatree_list fpn_aatree_list_t;

struct fpn_aatree_ctx;
typedef struct fpn_aatree_ctx fpn_aatree_ctx_t;

struct fpn_aatree_ctx {
	/* priority-ordered chained list of nodes */
	fpn_aatree_list_t list;

	/* sentinel node that hosts the tree root */
	fpn_aatree_node_t top;
};

/*
 * Initialize an AA tree context
 *
 * param ctx
 *   AA tree context to initialize
 */
#ifdef CONFIG_MCORE_AATREE_SANITY_CHECK
void fpn_aatree_node_init(fpn_aatree_node_t *node);
#else
static inline void
fpn_aatree_node_init(__attribute__((unused)) fpn_aatree_node_t *node)
{
}
#endif

/*
 * Initialize an AA tree context
 *
 * param ctx
 *   AA tree context to initialize
 */
void fpn_aatree_init(fpn_aatree_ctx_t *ctx);

/*
 * Insert an AA tree node into the tree and chained list
 *
 * after insertion, the tree is rebalanced
 *
 * param ctx
 *   AA tree context
 * param node
 *   AA tree node to insert
 */
void fpn_aatree_insert(fpn_aatree_ctx_t *ctx, fpn_aatree_node_t *node);

/*
 * Remove an AA tree node from the tree and chained list
 *
 * after removal, the tree is rebalanced
 *
 * param ctx
 *   AA tree context
 * param node
 *   AA tree node to insert
 */
void fpn_aatree_remove(fpn_aatree_ctx_t *ctx, fpn_aatree_node_t *node);

#endif /* __FPN_AATREE_H__ */
