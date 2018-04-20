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
 *
 * Various ideas harvested from the following sites:
 * http://en.wikipedia.org/wiki/AA_tree
 * http://www.eternallyconfuzzled.com
 */

/*
 * This API stores fpn_aatree_node_t objects ordered by their priority
 * field, both in a FPN_TAILQ chained list and an AA tree.
 *
 * The tree enables to find the right position in the list in a very fast
 * manner (O(log(N)). The object is inserted both in the tree and
 * in the chained list, and the tree is maintained balanced.
 * (nodes are inserted just after other nodes of priority <=)
 *
 * The ordered chained list of objects can then be browsed by the library
 * user. The chained list is also internally used by fpn_aatree_remove()
 * to find the predecessor or successor of the node being deleted.
 *
 * This implementation was originally designed to sort timers by order of
 * expiration. Therefore, the following conventions are defined in order to
 * allow the priority to wrap:
 * - the maximum priority difference between 2 nodes in the tree is supposed
 *   to always be < 2^63.
 * - node1 is before node2 if (int64_t)(node1->priority - node2->priority) < 0
 * Therefore: 0x2000 is before 0x4000 but after 0xFFFFFFFFFFFFFFF2
 *
 * If you are not confortable with the second rule, just use priority values
 * ranging from 0 to 2^63-1. Then the rule is more straighforward:
 * node1 is before node2 if node1->priority < node2->priority.
 *
 * To sort any type of structure, simply embed a fpn_aatree_node_t structure:
 *
 * struct mystruct {
 *     int field1;
 *     int field2;
 *     ...
 *     fpn_aatree_node_t aanode; <== AA tree chaining node
 * };
 *
 * fpn_aatree_node_ctx aactx;    <== AA tree context
 *
 * struct mystruct mystruct1, mystruct2, ...; <== elements to sort
 *
 *
 * To insert and sort the mystruct structures in the tree:
 * fpn_aatree_init(&aactx);
 *
 * fpn_aatree_node_init(&mystruct1.aanode);
 * mystruct1.aanode.priority = 25;
 * fpn_aatree_insert(&aactx, &mystruct1.aanode);
 *
 * fpn_aatree_node_init(&mystruct2.aanode);
 * mystruct2.aanode.priority = 42;
 * fpn_aatree_insert(&aactx, &mystruct2.aanode);
 * ...
 *
 * Then, to browse the sorted mystruct structures:
 * fpn_aatree_node_t *node;
 * struct mystruct *p;
 * FPN_TAILQ_FOREACH(node, &aactx, list) {
 *    p = fpn_containerof(node, struct mystruct, aanode);
 * }
 */
#include "fpn.h"
#include "fpn-queue.h"
#include "fpn-aatree.h"

#define FPN_AATREE_MAGIC  0xc0ffee42
#define FPN_AATREE_BADMAGIC 0xffffffff
#define FPN_AATREE_POISONED ((void*)-1)

/* sentinel node that stands for "no child" */
static FPN_DEFINE_SHARED(fpn_aatree_node_t, aatree_nil0) = {
#ifdef CONFIG_MCORE_AATREE_SANITY_CHECK
	.magic = FPN_AATREE_MAGIC,
#endif
	.child = {
		[0] = &aatree_nil0,
		[1] = &aatree_nil0
	},
	.parent = NULL,
	.level = 0,
};
static FPN_DEFINE_SHARED(fpn_aatree_node_t*, aatree_nil)= &aatree_nil0;

/* sentinel node that hosts the tree root */
#define aatree_top (&ctx->top)

/* root node of the tree */
#define aatree_root (ctx->top.child[0])

/* head of chained list */
#define aatree_list (&ctx->list)

#ifdef CONFIG_MCORE_AATREE_SANITY_CHECK
#define FPN_AATREE_ASSERT_IS_ENQUEUED(node) ({ \
	FPN_ASSERT(node->magic == FPN_AATREE_MAGIC); \
	FPN_ASSERT(node->parent != FPN_AATREE_POISONED); \
	FPN_ASSERT(node->child[0] != FPN_AATREE_POISONED); \
	FPN_ASSERT(node->child[1] != FPN_AATREE_POISONED); \
})

#define FPN_AATREE_ASSERT_IS_DEQUEUED(node) ({ \
	FPN_ASSERT(node->magic == FPN_AATREE_BADMAGIC); \
	FPN_ASSERT(node->parent == FPN_AATREE_POISONED); \
	FPN_ASSERT(node->child[0] == FPN_AATREE_POISONED); \
	FPN_ASSERT(node->child[1] == FPN_AATREE_POISONED); \
})
#define FPN_AATREE_POISON(node)  ({ \
	node->magic = FPN_AATREE_BADMAGIC; \
	node->parent = FPN_AATREE_POISONED; \
	node->child[0] = FPN_AATREE_POISONED; \
	node->child[1] = FPN_AATREE_POISONED; \
})

#else /* CONFIG_MCORE_AATREE_SANITY_CHECK */
#define FPN_AATREE_ASSERT_IS_ENQUEUED(node)
#define FPN_AATREE_ASSERT_IS_DEQUEUED(node)
#define FPN_AATREE_POISON(node)
#endif /* CONFIG_MCORE_AATREE_SANITY_CHECK */

/*
 * Initialize an AA tree node as a leaf
 *
 * param node
 *   AA tree node to initialize as a leaf
 */
static void fpn_aatree_node_init_leaf(fpn_aatree_node_t *node)
{
#ifdef CONFIG_MCORE_AATREE_SANITY_CHECK
	node->magic = FPN_AATREE_MAGIC;
#endif
	node->level = 1;
	node->child[0] = node->child[1] = aatree_nil;
	node->parent = NULL;
	node->dir = 0;
}

/*
 * Initialize an AA tree node
 *
 * param node
 *   AA tree node to initialize
 */
#ifdef CONFIG_MCORE_AATREE_SANITY_CHECK
void fpn_aatree_node_init(fpn_aatree_node_t *node)
{
	FPN_AATREE_POISON(node);
}
#endif

/*
 * Initialize an AA tree context
 *
 * param ctx
 *   AA tree context to initialize
 */
void fpn_aatree_init(fpn_aatree_ctx_t *ctx)
{
	fpn_aatree_node_init_leaf(aatree_top);

	FPN_TAILQ_INIT(aatree_list);
}

/*
 * Skew a branch of an AA tree
 *
 * skew removes left horizontal links by rotating right at the parent. 
 *
 * done in case of left horizontal link (left child level = node level)
 *
 *          d,2               b,2
 *         /   \             /   \
 *      b,2     e,1  -->  a,1     d,2
 *     /   \                     /   \
 *  a,1     c,1               c,1     e,1
 *
 * param node
 *   root node of the branch to skew (d)
 * return
 *   pointer to new branch root (b)
 */
static fpn_aatree_node_t *__fpn_aatree_skew(fpn_aatree_node_t *node)
{
	fpn_aatree_node_t *save;

	/* save old root node (d) in save */
	save = node;

	/* set new root node as left child (b) */
	node = save->child[0];
	node->parent = save->parent;
	node->dir = save->dir;

	/* set (d)'s left child as (b)'s right child */
	save->child[0] = node->child[1];
	if (save->child[0] != aatree_nil) {
		save->child[0]->parent = save;
		save->child[0]->dir = 0;
	}

	/* set (b)'s right child as (d) */
	node->child[1] = save;
	save->parent = node;
	save->dir = 1;

	/* connect (d)'s old parent to the new root node (b) */
	node->parent->child[node->dir] = node;

	return node;
}

/*
 * Skew a branch of an AA tree if needed
 */
static inline fpn_aatree_node_t *fpn_aatree_skew(fpn_aatree_node_t *node)
{
	FPN_AATREE_ASSERT_IS_ENQUEUED(node);

	if (node->level != 0 && node->level == node->child[0]->level)
		node = __fpn_aatree_skew(node);

	return node;
}

/*
 * Split a branch of an AA tree
 *
 * split removes consecutive horizontal links by rotating left and increasing
 * the level of the parent.
 * 
 *      b,2                     d,3
 *     /   \                   /   \
 *  a,1     d,2     -->     b,2     e,2
 *         /   \           /   \
 *      c,1     e,2     a,1     c,1
 *
 * param node
 *   root node of the branch to split (b)
 * return
 *   pointer to new branch root (d)
 */
static fpn_aatree_node_t *__fpn_aatree_split(fpn_aatree_node_t *node)
{
	fpn_aatree_node_t *save;

	/* save old node (b) in save */
	save = node;

	/* set new root node as (b)'s right child (d) */
	node = save->child[1];
	node->parent = save->parent;
	node->dir = save->dir;

	/* increase new root node level */
	node->level++;

	/* set (b)'s right child as (d)'s left child */
	save->child[1] = node->child[0];
	if (save->child[1] != aatree_nil) {
		save->child[1]->parent = save;
		save->child[1]->dir = 1;
	}

	/* set (d)'s left child as (b) */
	node->child[0] = save;
	save->parent = node;
	save->dir = 0;

	/* connect (b)'s old parent to the new root node (d) */
	node->parent->child[node->dir] = node;

	return node;
}

/*
 * Split a branch of an AA tree if needed
 */
static fpn_aatree_node_t *fpn_aatree_split(fpn_aatree_node_t *node)
{
	FPN_AATREE_ASSERT_IS_ENQUEUED(node);

	if (node->level != 0 &&
	    node->level == node->child[1]->child[1]->level)
		node = __fpn_aatree_split(node);

	return node;
}

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
void fpn_aatree_insert(fpn_aatree_ctx_t *ctx, fpn_aatree_node_t *node)
{
	fpn_aatree_node_t *parent = NULL;
	fpn_aatree_node_t *t;
	int dir;

	FPN_AATREE_ASSERT_IS_DEQUEUED(node);

	fpn_aatree_node_init_leaf(node);

	if (aatree_root == aatree_nil) {
		aatree_root = node;
		node->parent = aatree_top;
		FPN_TAILQ_INSERT_TAIL(aatree_list, node, next);
		return;
	}

	t = aatree_root;

	/* find the leaf where the new node should be stored */
	while (t != aatree_nil) {
		/*
		 * node < t  => left branch
		 * node >= t => right branch
		 */
		parent = t;
		dir = (((int64_t)(node->priority - t->priority)) >= 0);
		t = t->child[dir];
	}

	/* found a leaf of the tree. *parent* is the parent of our node */
	node->parent = parent;
	node->dir = dir;

	parent->child[dir] = node;

	if (dir)
		FPN_TAILQ_INSERT_AFTER(aatree_list, parent, node, next);
	else
		FPN_TAILQ_INSERT_BEFORE(parent, node, next);

	/* now rebalance the tree from the leaf parent up to the root */
	t = parent;

	while (t != aatree_top) {
		t = fpn_aatree_skew(t);
		t = fpn_aatree_split(t);
		t = t->parent;
	}
}

/*
 * Check whether an AA tree node is a leaf
 *
 * param node
 *   AA tree node
 * result
 *   boolean (0: node is a leaf, 1: node is not a leaf)
 */
static inline int is_leaf(fpn_aatree_node_t *node)
{
	return (node->child[0] == aatree_nil && node->child[1] == aatree_nil);
}

/*
 * Decrease the level of an AA tree node (if needed)
 *
 * called after a node was deleted
 *
 * param node
 *   AA tree node
 * result
 *   boolean (0: node is a leaf, 1: node is not a leaf)
 */
static void fpn_aatree_decrease_level(fpn_aatree_node_t *node)
{
	int should_be;

	/* should_be: min(left->level, right->level) + 1 */
	should_be = node->child[0]->level > node->child[1]->level ?
		node->child[1]->level + 1 : node->child[0]->level + 1;

	if (should_be < node->level) {
		node->level = should_be;
		if (should_be < node->child[1]->level)
			node->child[1]->level = should_be;
	}
}

/*
 * Find the successor of an AA tree node
 *
 * param node
 *   AA tree node
 * return
 *   successor AA tree node
 */
static inline fpn_aatree_node_t *successor(fpn_aatree_node_t *node)
{
	fpn_aatree_node_t *t = FPN_TAILQ_NEXT(node, next);

	FPN_AATREE_ASSERT_IS_ENQUEUED(node);
	FPN_ASSERT(is_leaf(t));

	return t;
}

/*
 * Find the predecessor of an AA tree node
 *
 * param node
 *   AA tree node
 * return
 *   predecessor AA tree node
 */
static inline fpn_aatree_node_t *predecessor(fpn_aatree_node_t *node)
{
	fpn_aatree_node_t *t = FPN_TAILQ_PREV(node, fpn_aatree_list, next);

	FPN_AATREE_ASSERT_IS_ENQUEUED(node);
	FPN_ASSERT(is_leaf(t));

	return t;
}

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
void fpn_aatree_remove(fpn_aatree_ctx_t *ctx, fpn_aatree_node_t *node)
{
	fpn_aatree_node_t *t;
	fpn_aatree_node_t *parent;
	fpn_aatree_node_t *substitute;
	int dir;

	FPN_AATREE_ASSERT_IS_ENQUEUED(node);

	if (is_leaf(node)) {
		if (node == aatree_root) {
			aatree_root = aatree_nil;
			/* remove node from linked list */
			FPN_TAILQ_REMOVE(aatree_list, node, next);
			FPN_AATREE_POISON(node);
			return;
		}
		parent = node->parent;
		dir = node->dir;
		/* unlink leaf from its parent */
		parent->child[dir] = aatree_nil;
	} else if (node->child[0] == aatree_nil) {
		substitute = successor(node);
		/* save parent of substitute */
		parent = substitute->parent;
		dir = substitute->dir;
		/* replace node by substitute */
		substitute->parent = node->parent;
		substitute->dir = node->dir;
		substitute->level = node->level;
		if (parent == node) {
			/* successor is the node's right son */
			parent = substitute;
		} else {
			/* - unlink substitute leaf from its parent */
			parent->child[dir] = aatree_nil;
			/* - adopt node's right child */
			substitute->child[1] = node->child[1];
			substitute->child[1]->parent = substitute;
		}
		/* link new parent to substitute */
		substitute->parent->child[substitute->dir] = substitute;
	} else {
		substitute = predecessor(node);
		/* save parent of substitute */
		parent = substitute->parent;
		dir = substitute->dir;
		/* replace node by substitute */
		substitute->parent = node->parent;
		substitute->dir = node->dir;
		substitute->level = node->level;
		if (parent == node)  {
			/* predecessor is the node's right son */
			parent = substitute;
		} else {
			/* - unlink substitute leaf from its parent */
			parent->child[dir] = aatree_nil;
			/* - adopt node's left child */
			substitute->child[0] = node->child[0];
			substitute->child[0]->parent = substitute;
		}
		/* - adopt node's right child */
		substitute->child[1] = node->child[1];
		if (substitute->child[1] != aatree_nil)
			substitute->child[1]->parent = substitute;
		/* link new parent to substitute */
		substitute->parent->child[substitute->dir] = substitute;
	}

	/* remove node from linked list */
	FPN_TAILQ_REMOVE(aatree_list, node, next);

	FPN_AATREE_POISON(node);

	/* rebalance tree from parent */
	t = parent;

	while (t != aatree_top) {
		fpn_aatree_decrease_level(t);
		t = fpn_aatree_skew(t);
		(void)fpn_aatree_skew(t->child[1]);
		(void)fpn_aatree_skew(t->child[1]->child[1]);
		t = fpn_aatree_split(t);
		(void)fpn_aatree_split(t->child[1]);
		t = t->parent;
	}
}

