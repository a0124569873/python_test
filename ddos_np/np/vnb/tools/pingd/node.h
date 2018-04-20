/*
 * Copyright 2007 6WIND S.A.
 */

#ifndef _NODE_H_
#define _NODE_H_

extern struct node *node_create(char *name, char *ftlname, char *ifname,
		uint32_t ouraddr, uint32_t peeraddr, uint32_t brdaddr);
extern void node_destroy(struct node *entry);
extern void node_destroy_all(void);
extern int node_connect(struct node *entry);
extern int node_set_carriertimer(struct node *entry);
extern int node_set_pingtimer(struct node *entry);
extern struct node *node_findbyname(char *name);
extern struct node *node_findbyaddr(uint32_t ouradddr, uint32_t peeraddr);
extern int node_setcarrier(struct node *entry);

#endif /* _NODE_H_ */
