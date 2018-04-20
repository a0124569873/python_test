/**
 * Kernel tables module
 *
 * This module allow creation of 8 bytes tables, for correspondence
 * between VLAN / MPLS and nfmark.
 */

/*-
   * Copyright (c) <2011>, 6WIND
   * All rights reserved.
   */

#include <linux/module.h>
#include <linux/version.h>
#include <net/genetlink.h>

#include <ktables_config.h>
#include "ktables.h"

MODULE_AUTHOR("AL");
MODULE_DESCRIPTION("Kernel tables module for Linux");

#define MODULE_NAME	"Ktables"

struct global_s {
	struct genl_family	family;
	struct genl_multicast_group	grp[1];
	struct genl_ops		ops[KT_CMD_MAX];
	uint32_t		dump_i;
	uint8_t	table[CONFIG_KTABLES_MAX_TABLES][KT_TABLE_SIZE];
};

static int kt_ops_do_set(struct sk_buff *skb, struct genl_info *info);
static int kt_ops_do_get(struct sk_buff *skb, struct genl_info *info);
static int kt_ops_dump(struct sk_buff *skb, struct netlink_callback *cb);
static void kt_notify(struct genl_multicast_group *grp, int i);


static int debug;
static struct global_s	glob = {
	.family.id	= GENL_ID_GENERATE,
	.family.name	= KT_NL_FAMILY_NAME,
	.family.version	= 1,
	.family.maxattr	= KT_ATTR_MAX,

	.grp[0].name	= KT_NL_GRP_NAME,

	.ops[KT_CMD_MAP_SET].cmd	= KT_CMD_MAP_SET,
	.ops[KT_CMD_MAP_SET].flags	= 0,
	.ops[KT_CMD_MAP_SET].policy	= NULL,
	.ops[KT_CMD_MAP_SET].doit	= &kt_ops_do_set,
	.ops[KT_CMD_MAP_SET].dumpit	= NULL,
	.ops[KT_CMD_MAP_SET].done	= NULL,

	.ops[KT_CMD_MAP_GET].cmd	= KT_CMD_MAP_GET,
	.ops[KT_CMD_MAP_GET].flags	= 0,
	.ops[KT_CMD_MAP_GET].policy	= NULL,
	.ops[KT_CMD_MAP_GET].doit	= &kt_ops_do_get,
	.ops[KT_CMD_MAP_GET].dumpit	= NULL,
	.ops[KT_CMD_MAP_GET].done	= NULL,

	.ops[KT_CMD_MAP_DUMP].cmd	= KT_CMD_MAP_DUMP,
	.ops[KT_CMD_MAP_DUMP].flags	= 0,
	.ops[KT_CMD_MAP_DUMP].policy	= NULL,
	.ops[KT_CMD_MAP_DUMP].doit	= NULL,
	.ops[KT_CMD_MAP_DUMP].dumpit	= &kt_ops_dump,
	.ops[KT_CMD_MAP_DUMP].done	= NULL,
};

/**
 * Get a pointer to an entry in the table
 *
 * @param table
 *   The table number ( < CONFIG_KTABLES_MAX_TABLES)
 * @param idx
 *   The looked for index in table (must be < to KT_TABLE_SIZE)
 * @return
 *   A pointer to the corresponding table entry on success, NULL otherwise
 */
uint8_t const *
kt_get_table_elmt_ptr(uint32_t table, uint8_t idx)
{

	if (likely(table < CONFIG_KTABLES_MAX_TABLES && idx < KT_TABLE_SIZE))
		return &glob.table[table][idx];
	else
		return NULL;
}
EXPORT_SYMBOL(kt_get_table_elmt_ptr);

/**
 * Get a pointer to a table
 *
 * @param table
 *   The table number ( < CONFIG_KTABLES_MAX_TABLES)
 * @return
 *   A pointer to the corresponding table on success, NULL otherwise
 */
uint8_t const *
kt_get_table_ptr(uint32_t table)
{

	if (likely(table < CONFIG_KTABLES_MAX_TABLES))
		return glob.table[table];
	else
		return NULL;
}
EXPORT_SYMBOL(kt_get_table_ptr);

/**
 * Get the value of an entry in a table
 *
 * @param table
 *   The table number ( < CONFIG_KTABLES_MAX_TABLES)
 * @param idx
 *   The table index of the value to get (must be < to KT_TABLE_SIZE)
 *   When Egress, it corresponds to the nfmark(+mask) value
 *   When Ingress, it corresponds to the priority set in the VLAN or
 *   MPLS header
 * @return
 *   The corresponding value on success, -1 otherwise.
 */
int
kt_get(uint32_t table, uint8_t idx)
{
	uint8_t const	*data;

	data = kt_get_table_elmt_ptr(table, idx);
	if (unlikely(data == NULL))
		return -1;

	return *data;
}
EXPORT_SYMBOL(kt_get);

/**
 * Return the number of existing tables
 */
uint32_t
kt_get_max_table(void)
{
	return CONFIG_KTABLES_MAX_TABLES;
}
EXPORT_SYMBOL(kt_get_max_table);

/**
 * Set the value of one entry in a table
 *
 * @param table
 *   The table number ( < CONFIG_KTABLES_MAX_TABLES)
 * @param idx
 *   The table index that is to be set (must be < to KT_TABLE_SIZE)
 *   When Egress, it corresponds to the nfmark(+mask) value
 *   When Ingress, it corresponds to the priority set in the VLAN or
 *   MPLS header
 * @param value
 *   The value to set (must be inferior to NFMARK_MASK)
 * @return
 *   0 on success, an error code otherwise
 */
int
kt_set_table(uint32_t table, uint8_t idx, uint8_t value)
{
	if (likely(table < CONFIG_KTABLES_MAX_TABLES && idx < KT_TABLE_SIZE))
		glob.table[table][idx] = value;
	else
		return -1;

	/* Notify group */
	kt_notify(glob.grp, table);

	return 0;
}
EXPORT_SYMBOL(kt_set_table);

/**
 * Send an already prepared sk_buff
 *
 * @param skb
 *   A pointer to the corresponding sk_buff
 * @param info
 *   A pointer to the genl_info passed to the calling callback
 * @return
 *   0 on success, an error code otherwise
 * @note
 *   Due to the use of the genk_info struct, this function is designed
 *   for doit callback
 */
static int
kt_send_reply(struct sk_buff *skb, struct genl_info *info)
{
	struct genlmsghdr *genlhdr = nlmsg_data(nlmsg_hdr(skb));
	void *reply = genlmsg_data(genlhdr);
	int rc;

	rc = genlmsg_end(skb, reply);
	if (rc < 0) {
		nlmsg_free(skb);
		return rc;
	}

	return genlmsg_reply(skb, info);
}

/**
 * Prepare a sk_buff for a doit callback
 *
 * @param info
 *   A pointer to the genl_info passed to the calling callback
 * @param cmd
 *   The coresponding command (KT_CMD_MAP_GET for example)
 * @param skb
 *   A pointer to a pointer to the corresponding sk_buff
 * @param size
 *   size of data to be put (later) in this sk_buff
 * @return
 *   0 on success, an error code otherwise
 */
static int
kt_prepare_reply(struct genl_info *info, uint8_t cmd,
			 struct sk_buff **skbp,	size_t size)
{
	struct sk_buff *skb;
	void *reply;

	/*
	 * If new attributes are added, please revisit this allocation
	 */
	skb = genlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	reply = genlmsg_put_reply(skb, info, &glob.family, 0, cmd);
	if (reply == NULL) {
		nlmsg_free(skb);
		return -EINVAL;
	}

	*skbp = skb;
	return 0;
}

/**
 * debugging function, prints all potential attributes from genl_info
 *
 * @param info
 *   A pointer to the corresponding genl_info struct
 * @return
 *   N/A
 */
static void
kt_check_attr(struct genl_info *info)
{
	int i;

	for (i = 0; i <= KT_ATTR_MAX; i++)
		printk(KERN_INFO "%d %p\n", i, info->attrs[i]);
}

/**
 * Notify using multicast group
 *
 * @param grp
 *   A pointer to the group to send the msg to
 * @param i
 *   Tne index of the table to send
 * @return
 *   N/A
 */
static void
kt_notify(struct genl_multicast_group *grp, int i)
{
	int		ret;
	struct sk_buff	*skb;
	void		*hdr;
	struct attr_table_s	attr_t;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return;

	hdr = genlmsg_put(skb, 0, 0, &glob.family, 0, KT_CMD_MAP_DUMP);
	if (hdr == NULL) {
		nlmsg_free(skb);
		return;
	}

	attr_t.table = i;
	memcpy(attr_t.table_value, glob.table[i], KT_TABLE_SIZE);
	if (nla_put(skb, KT_TYPE_ONE_TABLE, sizeof(attr_t), &attr_t)) {
		nlmsg_free(skb);
		return;
	}
	if (genlmsg_end(skb, hdr) < 0) {
		nlmsg_free(skb);
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	ret = genlmsg_multicast(skb, 0, grp->id, GFP_KERNEL);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genlmsg_multicast_allns(skb, 0, grp->id, GFP_KERNEL);
#else
	ret = genlmsg_multicast_allns(&glob.family, skb, 0, 0, GFP_KERNEL);
#endif
	if (ret && ret != -ESRCH)
		printk(KERN_INFO "%s: Error notifying group (%d)\n",
			MODULE_NAME, ret);
}

/**
 * Update tables
 *
 * @param attr
 *   a pointer to an attribute struct (attr_byte_s or attr_table_s)
 * @param type
 *   the attribute type (KT_ATTR_SET_ONE_BYTE for example)
 * @return
 *   0 on success, an error code otherwise
 */
static int
kt_update_table(void *attr, int type)
{
	struct attr_byte_s	*attr_b;
	struct attr_table_s	*attr_t;

	switch (type) {
	case KT_ATTR_SET_ONE_BYTE:
		attr_b = attr;
		if (debug)
			printk(KERN_INFO "table=%u, value=%02x, idx=%u\n",
				attr_b->table, attr_b->value, attr_b->idx);
		if (attr_b->table < CONFIG_KTABLES_MAX_TABLES &&
		    attr_b->idx < KT_TABLE_SIZE) {
			glob.table[attr_b->table][attr_b->idx] = attr_b->value;
			kt_notify(glob.grp, attr_b->table);
			return 0;
		} else
			return -EINVAL;
	case KT_ATTR_SET_ONE_TABLE:
		attr_t = attr;
		if (attr_t->table < CONFIG_KTABLES_MAX_TABLES) {
			memcpy(glob.table[attr_t->table], attr_t->table_value, KT_TABLE_SIZE);
			kt_notify(glob.grp, attr_t->table);
			return 0;
		} else
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
}

/**
 * doit Callback for KT_CMD_MAP_SET
 *
 * @param skb
 *   A pointer to the corresponding sk_buff
 * @param info
 *   A pointer to the genl_info
 * @return
 *   0 on success, an error code otherwise
 */
static int
kt_ops_do_set(struct sk_buff *skb, struct genl_info *info)
{
	int		ret;
	int		ret_type;
	int		attr_type;
	struct sk_buff	*rep_skb;
	struct nlattr	*na;
	struct attr_byte_s	attr_b;
	struct attr_table_s	attr_t;
	void		*attr;
	int		attr_len;

	if (debug) {
		printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
		kt_check_attr(info);
	}

	for (attr_type = 1; attr_type <= KT_ATTR_MAX; attr_type++) {
		na = info->attrs[attr_type];
		if (na != NULL)
			break;

	}
	if (na == NULL)
		return -EINVAL;

	switch (attr_type) {
	case KT_ATTR_SET_ONE_BYTE:
		attr = &attr_b;
		attr_len = sizeof(attr_b);
		ret_type = KT_TYPE_ONE_BYTE_SET;
		break;
	case KT_ATTR_SET_ONE_TABLE:
		attr = &attr_t;
		attr_len = sizeof(attr_t);
		ret_type = KT_TYPE_ONE_TABLE;
		break;
	default:
		return -EINVAL;
	}
	nla_memcpy(attr, na, attr_len);

	/* Update tables now */
	ret = kt_update_table(attr, attr_type);
	if (ret)
		return ret;

	ret = kt_prepare_reply(info, KT_CMD_MAP_GET, &rep_skb, attr_len);
	if (ret < 0)
		return ret;
	ret = nla_put(rep_skb, ret_type, attr_len, attr);
	if (ret) {
		nlmsg_free(rep_skb);
		return ret;
	}

	return kt_send_reply(rep_skb, info);
}

/**
 * doit Callback for KT_CMD_MAP_GET
 *
 * @param skb
 *   A pointer to the corresponding sk_buff
 * @param info
 *   A pointer to the genl_info
 * @return
 *   0 on success, an error code otherwise
 */
static int
kt_ops_do_get(struct sk_buff *skb, struct genl_info *info)
{
	int		ret;
	uint32_t	table;
	struct sk_buff	*rep_skb;
	size_t		size;
	struct nlattr	*na;
	struct attr_table_s	ans;

	na = info->attrs[KT_ATTR_GET_ONE_TABLE];
	if (debug) {
		printk(KERN_INFO "%s:%d na=%p\n", __func__, __LINE__, na);
		kt_check_attr(info);
	}
	if (na == NULL)
		return -EINVAL;
	table = nla_get_u32(na);

	size = sizeof(ans);
	ret = kt_prepare_reply(info, KT_CMD_MAP_GET, &rep_skb, size);
	if (ret < 0)
		return ret;
	ans.table = table;
	memcpy(ans.table_value, glob.table[table], KT_TABLE_SIZE);
	ret = nla_put(rep_skb, KT_TYPE_ONE_TABLE, size, &ans);
	if (ret) {
		nlmsg_free(rep_skb);
		return ret;
	}

	return kt_send_reply(rep_skb, info);
}

/**
 * Send a dump message for one table
 *
 * @param skb
 *   A pointer to a pre allocated sk_buff
 * @param cb
 *   A pointer to a netlink_callback struct
 * @param i
 *   The table index
 */
static int
kt_dump_one(struct sk_buff *skb, struct netlink_callback *cb, int i)
{
	void	*hdr;
	struct attr_table_s	attr_t;

	hdr = genlmsg_put(skb,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
			  NETLINK_CB(cb->skb).pid,
#else
			  NETLINK_CB(cb->skb).portid,
#endif
		       cb->nlh->nlmsg_seq,
		       &glob.family, NLM_F_MULTI, KT_CMD_MAP_DUMP);
	if (hdr == NULL)
		return -EMSGSIZE;

	attr_t.table = i;
	memcpy(attr_t.table_value, glob.table[i], KT_TABLE_SIZE);
	if (nla_put(skb, KT_TYPE_ONE_TABLE, sizeof(attr_t), &attr_t)) {
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
	}

	return genlmsg_end(skb, hdr);
}

/**
 * dumpit Callback for KT_CMD_MAP_DUMP
 *
 * @param skb
 *   A pointer to the corresponding sk_buff
 * @param cb
 *   A pointer to the netlink_callback
 * @return
 *   length of the sk_buff if data are to be sent,
 *   0 if nothing left to send or
 *   a negative error code on error
 * @note
 *   This callback has a specific behaviour. It is called again and again,
 *   as long as it return a positive value.
 */
static int
kt_ops_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int	ret;

	if (debug)
		printk(KERN_INFO "%s (%3d)\n", __func__, glob.dump_i);

	if (glob.dump_i < CONFIG_KTABLES_MAX_TABLES) {
		ret = kt_dump_one(skb, cb, glob.dump_i);
		glob.dump_i++;
		if (ret > 0)
			return skb->len;
		else
			return ret;
	} else {
		glob.dump_i = 0;
		return 0;
	}
}

/**
 * Register a new generic netlink familly and its associated operations
 *
 * @return
 *   0 on success, an error code otherwise
 */
static int
kt_netlink_open(void)
{
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genl_register_family_with_ops(&glob.family, glob.ops,
					    ARRAY_SIZE(glob.ops));
#else
	ret = genl_register_family_with_ops_groups(&glob.family, glob.ops,
						   glob.grp);
#endif
	return ret;
}

/**
 * Unregister family
 */
static void
kt_unregister_family(void)
{
	int ret;

	/* Unregister family */
	ret = genl_unregister_family(&glob.family);
	if (debug && ret) {
		printk(KERN_ERR "%s: Could not unregister family (%d)\n",
			__func__, ret);
	}
}

/**
 * Module initialization function
 */
static int __init
kt_init(void)
{
	int ret;

	memset(glob.table, 0, sizeof(glob.table));
	glob.dump_i = 0;

	if ((ret = kt_netlink_open()) < 0)
		return ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	ret = genl_register_mc_group(&glob.family, glob.grp);
	if (ret) {
		printk(KERN_CRIT "Module %s: group error (%d)\n",
				MODULE_NAME, ret);
		kt_unregister_family();
		return ret;
	}
#endif

	if (debug)
		printk(KERN_INFO "Module %s initialized\n", MODULE_NAME);

	return 0;
}

/**
 * Module exit function
 */
static void __exit
kt_exit(void)
{
	/*
	 * Unregister of multicast group and operations is automatically
	 * done when unregistering family
	 */
	kt_unregister_family();

	if (debug)
		printk(KERN_INFO "Module %s exit\n", MODULE_NAME);
}

module_init(kt_init);
module_exit(kt_exit);

module_param(debug, int, S_IWUSR);
MODULE_PARM_DESC(debug, "non null (int) to set debug mode on");

MODULE_LICENSE("6WIND");

