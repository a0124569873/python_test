/*
 * Copyright 2009-2013 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <event.h>
#include <time.h>
#include <sys/queue.h>
#include <linux/types.h>
#include <libconsole.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include  <linux/version.h>
#include <netlink/msg.h>

#include "libif.h"
#include "ifflags.h"
#include "node.h"

#define IFFLAGS_LOGLEVEL LOG_WARNING
#define IFFLAGS_LOG(level, args...) do {			\
		if (level <= IFFLAGS_LOGLEVEL)		\
			syslog(level, args);			\
	} while(0)

struct dev_list root_bucket[HASHTABLE_SIZE];
struct dev_list leaf_bucket[HASHTABLE_SIZE];

#ifndef USE_VRF_NETNS
extern struct nl_sock *ifflags_nlsock;
#endif

/************************
 *  internal function
 ************************/

/* Superfast hash Copyright 2004-2008 by Paul Hsieh */
#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif
static uint32_t sfhash(const char *data, int len)
{
	uint32_t hash = len, tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Mainface_list loop */
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp    = (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (uint16_t);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
	case 3: hash += get16bits (data);
		hash ^= hash << 16;
		hash ^= data[sizeof (uint16_t)] << 18;
		hash += hash >> 11;
		break;
	case 2: hash += get16bits (data);
		hash ^= hash << 11;
		hash += hash >> 17;
		break;
	case 1: hash += *data;
		hash ^= hash << 10;
		hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

static uint32_t dev_hash(const char *ifname)
{
	uint32_t h;
	h = sfhash(ifname, strlen(ifname));
	return h & HASHTABLE_MASK;
}

/* assume device does not exist */
static struct dev_node *new_device(struct dev_list *hash_head, const char *ifname)
{
	struct dev_node *device;
	uint32_t h;
	struct dev_list *devlist;

	IFFLAGS_LOG(LOG_DEBUG, "%s(%s)", __FUNCTION__, ifname);

	device = malloc(sizeof(*device));
	if (device == NULL) {
		IFFLAGS_LOG(LOG_ERR, "%s() not enough memory", __FUNCTION__);
		return NULL;
	}
	memset(device, 0, sizeof(*device));
	snprintf(device->name, IFNAMSIZ, "%s", ifname);
	LIST_INIT(&device->bindings);
	h = dev_hash(ifname);
	devlist = &hash_head[h];
	LIST_INSERT_HEAD(devlist, device, h_next);
	return device;
}

static struct dev_node *find_device(struct dev_list *hash_head, const char *ifname)
{
	struct dev_node *device;
	uint32_t h;
	struct dev_list *devlist;

	h = dev_hash(ifname);
	devlist = &hash_head[h];

	LIST_FOREACH(device, devlist, h_next) {
		if (!strncmp(ifname, device->name, IFNAMSIZ))
			return device;
	}
	return NULL;
}

/* bind to device object
 * return: 0 : binding success
 *        -1 : binding error
 *         1 : already be binded before
 */
static int add_binding(struct dev_node *from, struct dev_node *to)
{
	struct bind_node *bindnode = NULL;
	struct bind_list *bindlist;

	if ((from == NULL) || (to == NULL))
		return -1;

	bindlist = &from->bindings;
	LIST_FOREACH(bindnode, bindlist, next) {
		if (bindnode->ptr == to) {
			IFFLAGS_LOG(LOG_INFO, "the bindings from %s to %s is already exist", from->name, to->name);
			return 1;
		}
	}

	bindnode = malloc(sizeof(*bindnode));
	if (bindnode == NULL) {
		IFFLAGS_LOG(LOG_ERR, "%s() not enough memory", __FUNCTION__);
		return -1;
	}
	memset(bindnode, 0, sizeof(*bindnode));
	bindnode->ptr = to;
	LIST_INSERT_HEAD(bindlist, bindnode, next);
	from->bindnum++;
	return 0;
}

/* unbind the two devices, don't destroy the device object. */
static int del_binding(struct dev_node *from, struct dev_node *to)
{
	struct bind_node *bindnode = NULL;
	struct bind_list *bindlist;

	if ((from == NULL) || (to == NULL))
		return -1;
	bindlist = &from->bindings;
	LIST_FOREACH(bindnode, bindlist, next) {
		if (bindnode->ptr == to)
			break;
	}
	if(bindnode != NULL) {
		LIST_REMOVE(bindnode, next);
		free(bindnode);
		from->bindnum--;
	}
	return 0;
}

static struct dev_node *create_leaf(const char *ifname)
{
	struct dev_node *device;

	device = find_device(leaf_bucket, ifname);
	if(device)
		return device;

	device = new_device(leaf_bucket, ifname);
	if(device) {
		struct libif_iface *iface;

	/* ask libif, set the RUNNING status of this device,
	 * for the device is not exist in kernel, the status is NO RUNNING. */
		iface = libif_iface_lookup_allvr(ifname);
		if (iface) {
			IFFLAGS_LOG(LOG_INFO, "libif_iface_lookup_allvr(%s) returned %p flags=%d\n",
				ifname, iface, iface->flags);
			if(iface->flags & IFF_RUNNING)
				device->status |= RUNNING;
		} else
			IFFLAGS_LOG(LOG_INFO,"libif_iface_lookup_allvr(%s) returned NULL\n", ifname);

	}
	return device;
}

static int del_leaf_binding(struct dev_node *leaf, struct dev_node *root)
{
	int ret;

	/* do the normal unbind */
	ret = del_binding(leaf, root);
	/* if leaf->bindnum is zero, remove the leaf node. */
	if(leaf->bindnum == 0) {
		LIST_REMOVE(leaf, h_next);
		free(leaf);
	}
	return ret;
}

/* delete the device object from the hash table,
 * before destroy the node, we need unbind the bind list first. */
static int del_device(struct dev_node *entry)
{
	struct bind_node *bindnode, *nextnode;
	struct bind_list *bindlist;

	if (entry == NULL)
		return -1;

	bindlist = &entry->bindings;
	LIST_FOREACH(bindnode, bindlist, next) {
		del_leaf_binding(bindnode->ptr, entry);
	}
	for (bindnode = LIST_FIRST(bindlist); bindnode != NULL;
			bindnode = nextnode) {
		nextnode = LIST_NEXT(bindnode, next);
		del_binding(entry, bindnode->ptr);
	}
	LIST_REMOVE(entry, h_next);
	free(entry);
	return 0;
}

static int setflags(char *dev_name, int flags)
{
	uint8_t operstate = IF_OPER_UP;
	int change_operstate = 0;
	struct nl_sock *nlsock = NULL;
	struct nl_msg *msg = NULL;
	struct ifinfomsg r;
	struct libif_iface *iface = libif_iface_lookup_allvr(dev_name);
	int err = -1;

	if (!iface)
		return -1;

	memset(&r, 0, sizeof(r));
	r.ifi_family = AF_UNSPEC;
	r.ifi_index = iface->ifindex;
	if (flags > 0) {
		r.ifi_flags = flags;
		r.ifi_change = flags;
	} else {
		r.ifi_flags = 0;
		r.ifi_change = -flags;
	}

	/* the RUNNING flag is not taken in account by the kernel, so we
	 * prefer using the operstate attribute */
	if (flags > 0 && (flags & IFF_RUNNING)) {
		change_operstate = 1;
		operstate = IF_OPER_UP;
	}
	else if (flags < 0 && ((-flags) & IFF_RUNNING)) {
		change_operstate = 1;
		operstate = IF_OPER_DORMANT;
	}

#ifdef USE_VRF_NETNS
	nlsock = get_nl_sock (iface);
	if (nlsock == NULL)
		return -1;
#else
	nlsock = ifflags_nlsock;
#endif

	msg = nlmsg_alloc_simple(RTM_SETLINK, NLM_F_REQUEST);
	if (!msg)
		goto nla_put_failure;

	if (nlmsg_append(msg, &r, sizeof(r), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (change_operstate)
		NLA_PUT_U8(msg, IFLA_OPERSTATE, operstate);

	if ((err = nl_send_sync(nlsock, msg)) < 0) {
		IFFLAGS_LOG(LOG_ERR, "%s(device %s, %s flags %04x): failed\n",
				__FUNCTION__, dev_name,
				flags > 0 ? "set" : "unset",
				flags > 0 ? flags : -flags);
	}

	msg = NULL;

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static void increase(struct dev_node *dev_node)
{
	if(++dev_node->status == 1) {
		if (setflags(dev_node->name, +IFF_RUNNING) < 0)
				IFFLAGS_LOG(LOG_ERR, "setflags() failed: %s\n", __FUNCTION__);
	}
	return;
}

static void decrease(struct dev_node *dev_node)
{
	if(--dev_node->status == 0) {
		if (setflags(dev_node->name, -IFF_RUNNING) < 0)
			IFFLAGS_LOG(LOG_ERR, "setflags() failed: %s\n", __FUNCTION__);
	}
	return;
}

/************************
 *  public function
 ************************/
int hash_table_init(void)
{
	int i;
	for (i=0; i<HASHTABLE_SIZE; i++)
		LIST_INIT(&root_bucket[i]);
	for (i=0; i<HASHTABLE_SIZE; i++)
		LIST_INIT(&leaf_bucket[i]);
	return 0;
}

struct dev_node *create_root(const char *ifname)
{
	struct dev_node *device;

	device = find_device(root_bucket, ifname);
	if(device) {
		IFFLAGS_LOG(LOG_INFO, "the root node %s is already exist", ifname);
		return device;
	}

	device = new_device(root_bucket, ifname);

	return device;
}

/* destroy the root device object */
int del_root(const char *ifname)
{
	struct dev_node *device;

	device = find_device(root_bucket, ifname);
	if(!device)
		return -1;

	return del_device(device);
}

int cli_addbinding(const char *root, const char *leaf)
{
	struct dev_node *root_dev, *leaf_dev;
	int duplicate;

	root_dev = find_device(root_bucket, root);
	if(!root_dev) {
		IFFLAGS_LOG(LOG_ERR, "the root node %s is not exist", root);
		return -1;
	}

	leaf_dev = create_leaf(leaf);
	if(!leaf_dev) {
		IFFLAGS_LOG(LOG_ERR, "the leaf node %s is not exist, can create failed", leaf);
		return -1;
	}

	duplicate = add_binding(root_dev, leaf_dev);
	if (duplicate < 0) {
		IFFLAGS_LOG(LOG_ERR, "(%s) binding from root to leaf failed", __FUNCTION__);
		return -1;
	}
	if(add_binding(leaf_dev, root_dev) < 0) {
		IFFLAGS_LOG(LOG_ERR, "(%s) binding from leaf to root failed", __FUNCTION__);
		return -1;
	}

	/*
	 * Root binding was already present, this is a config error, don't reject
	 * but don't mess with internal state either
	 */
	if (duplicate)
		return 0;

	/*
	 * When adding a new binding, count the operative leaf
	 * This will trigger (if need be) the activation of RUNNING flag
	 */
	if (leaf_dev->status & RUNNING)
		increase(root_dev);
	else if (root_dev->bindnum == 1) {
		/*
		 * In case of first binding with a non-operative lower link
		 * be sure to enforce the removal of RUNING flag
		 */
		if (setflags(root_dev->name, -IFF_RUNNING) < 0)
			IFFLAGS_LOG(LOG_ERR, "setflags() failed: %s\n", __FUNCTION__);
	}

	return 0;
}

int cli_delbinding(const char *root, const char *leaf)
{
	struct dev_node *root_dev, *leaf_dev;
	int bindings;

	root_dev = find_device(root_bucket, root);
	if(!root_dev) {
		IFFLAGS_LOG(LOG_ERR, "(%s) the root node %s is not exist", __FUNCTION__, root);
		return -1;
	}

	leaf_dev = find_device(leaf_bucket, leaf);
	if(!leaf_dev) {
		IFFLAGS_LOG(LOG_ERR, "(%s) the leaf node %s is not exist", __FUNCTION__, leaf);
		return -1;
	}

	bindings = del_binding(root_dev, leaf_dev);
	if(bindings < 0) {
		IFFLAGS_LOG(LOG_ERR, "(%s) unbinding from root to leaf failed", __FUNCTION__);
		return -1;
	}
	/*record the status of leaf, because maybe it will be released by del_leaf_binding*/
	bindings = leaf_dev->status & RUNNING ? 1 : 0;
	if(del_leaf_binding(leaf_dev, root_dev) < 0) {
		IFFLAGS_LOG(LOG_ERR, "(%s) unbinding from leaf to root failed", __FUNCTION__);
		return -1;
	}

	if (bindings)
		decrease(root_dev);
	return 0;
}
/********************************
 *  function for dump the entry
 *******************************/
struct dev_node *device_root_findbyname(const char *ifname)
{
	return find_device(root_bucket, ifname);
}

struct dev_node *device_leaf_findbyname(const char *ifname)
{
	return find_device(leaf_bucket, ifname);
}
/*
 * interface change notification
 * find the leaf node by name, if the leaf->status is NOT same to the new status,
 * we will update the all the root link list in current leaf node.
 */
void
ifflags_nl_cb(const struct libif_iface *iface, uint16_t notif_flags, void *arg)
{
	if (notif_flags & LIBIF_F_CREATE) {
		struct dev_node *root_dev;

		root_dev = find_device(root_bucket, iface->name);
		/*
		 * If a root node appears after being configured, it means
		 * that the netdevice had no chance to have its RUNNING
		 * flag configured according to lower link(s) status
		 */
		if (root_dev) {
			int err;

			err = setflags(root_dev->name,
			         root_dev->status ? +IFF_RUNNING: -IFF_RUNNING);
			if (err < 0)
				IFFLAGS_LOG(LOG_ERR, "setflags() failed: %s\n",
				      __FUNCTION__);
		}
	}

	if (notif_flags & LIBIF_F_UPDATE) {
		struct dev_node *leaf;
		struct bind_node *bindnode;
		struct bind_list *bindlist;
		int newstatus = 0;

		leaf = find_device(leaf_bucket, iface->name);
		if(leaf == NULL)
			return;
		if(iface->flags & IFF_RUNNING)
			newstatus |= RUNNING;
		if(leaf->status == newstatus)
			return;

		leaf->status = newstatus;
		bindlist = &leaf->bindings;
		LIST_FOREACH(bindnode, bindlist, next) {
			struct dev_node *root = bindnode->ptr;
			if (newstatus & RUNNING)
				increase(root);
			else
				decrease(root);
		}
	}
}

