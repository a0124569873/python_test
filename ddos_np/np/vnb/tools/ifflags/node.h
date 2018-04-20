/*
 * Copyright 2009 6WIND S.A.
 */

#ifndef _IFFLAGS_NODE_H_
#define _IFFLAGS_NODE_H_

struct dev_node;
struct bind_node{
	LIST_ENTRY(bind_node)	next;
	struct dev_node		*ptr;
};

LIST_HEAD(bind_list, bind_node);

struct dev_node {
	LIST_ENTRY(dev_node)	h_next;		/* hashtable bucket list */
	char			name[IFNAMSIZ];
	int			bindnum;	/* number node in bind_list */
	struct bind_list 	bindings;
#define	RUNNING	0x01
	int			status;
};

#define HASHTABLE_ORDER 10
#define HASHTABLE_SIZE  (1<<HASHTABLE_ORDER)
#define HASHTABLE_MASK  (HASHTABLE_ORDER-1)
LIST_HEAD(dev_list, dev_node);

int hash_table_init(void);
struct dev_node *create_root(const char *ifname);
int del_root(const char *ifname);
int cli_addbinding(const char *root, const char *leaf);
int cli_delbinding(const char *root, const char *leaf);

void ifflags_nl_cb(const struct libif_iface *iface, uint16_t notif_flags, void *arg);
/********************************
 *  function for dump the entry
 *******************************/
struct dev_node *device_root_findbyname(const char *ifname);
struct dev_node *device_leaf_findbyname(const char *ifname);

#endif /* _IFFLAGS_NODE_H_ */

