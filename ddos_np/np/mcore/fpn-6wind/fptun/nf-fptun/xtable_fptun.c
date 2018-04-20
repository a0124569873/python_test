/*
 * Copyright (C) 2013 6WIND
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/netns/generic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("Xtables fptun");

#ifndef CONFIG_MCORE_RFPVI
struct net_device *fpn0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
static struct nf_hook_ops *fptun_ops __read_mostly;
static struct nf_hook_ops *fptun6_ops __read_mostly;
#endif
static int fptun_net_id;
struct fptun_table {
	struct xt_table *ipv4;
	struct xt_table *ipv6;
};

#define FPTUN_VALID_HOOKS (1 << NF_INET_POST_ROUTING)

static const struct xt_table packet_fptun = {
	.name		= "fptun",
	.valid_hooks	= FPTUN_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_IPV4,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	.priority	= NF_IP_PRI_LAST,	/* should be called after conntrack engine */
#endif
};

static const struct xt_table packet_fptun6 = {
	.name		= "fptun",
	.valid_hooks	= FPTUN_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_IPV6,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	.priority	= NF_IP6_PRI_LAST,	/* should be called after conntrack engine */
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
static const struct
{
	struct ipt_replace repl;
	struct ipt_standard entries[1];
	struct ipt_error term;
} initial_table __net_initdata = {
	.repl = {
		.name = "fptun",
		.valid_hooks = FPTUN_VALID_HOOKS,
		.num_entries = 2,
		.size = sizeof(struct ipt_standard) + sizeof(struct ipt_error),
		.hook_entry = {
			[NF_INET_POST_ROUTING]  = 0,
		},
		.underflow = {
			[NF_INET_POST_ROUTING]  = 0,
		},
	},
	.entries = {
		IPT_STANDARD_INIT(NF_ACCEPT),	/* POST_ROUTING */
	},
	.term = IPT_ERROR_INIT,			/* ERROR */
};

static const struct
{
	struct ip6t_replace repl;
	struct ip6t_standard entries[1];
	struct ip6t_error term;
} initial_table6 __net_initdata = {
	.repl = {
		.name = "fptun",
		.valid_hooks = FPTUN_VALID_HOOKS,
		.num_entries = 2,
		.size = sizeof(struct ip6t_standard) + sizeof(struct ip6t_error),
		.hook_entry = {
			[NF_INET_POST_ROUTING]  = 0,
		},
		.underflow = {
			[NF_INET_POST_ROUTING]  = 0,
		},
	},
	.entries = {
		IP6T_STANDARD_INIT(NF_ACCEPT),	/* POST_ROUTING */
	},
	.term = IP6T_ERROR_INIT,		/* ERROR */
};
#endif

#undef USE_HOOK_OPS
#ifdef RHEL_RELEASE
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0)
        #define USE_HOOK_OPS
    #endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
    #define USE_HOOK_OPS
#endif

static unsigned int
iptable_fptun_hook(
#ifdef USE_HOOK_OPS
		   const struct nf_hook_ops *ops,
#else
		   unsigned int hook,
#endif
		   struct sk_buff *skb,
		   const struct net_device *in,
		   const struct net_device *out,
		   int (*okfn)(struct sk_buff *))
{
	struct fptun_table *table = net_generic(dev_net(out), fptun_net_id);

	/* POSTROUTING */
	return ipt_do_table(skb,
#ifdef USE_HOOK_OPS
			    ops->hooknum,
#else
			    hook,
#endif
			    in, out, table->ipv4);
}

static unsigned int
ip6table_fptun6_hook(
#ifdef USE_HOOK_OPS
		   const struct nf_hook_ops *ops,
#else
		   unsigned int hook,
#endif
		    struct sk_buff *skb,
		    const struct net_device *in,
		    const struct net_device *out,
		    int (*okfn)(struct sk_buff *))
{
	struct fptun_table *table = net_generic(dev_net(out), fptun_net_id);

	/* POSTROUTING */
	return ip6t_do_table(skb,
#ifdef USE_HOOK_OPS
			     ops->hooknum,
#else
			     hook,
#endif
			     in, out, table->ipv6);
}

static int __net_init iptable_fptun_net_init(struct net *net)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	struct fptun_table *table = net_generic(net, fptun_net_id);
#else
	struct fptun_table *table;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	struct ipt_replace *repl;
	struct ip6t_replace *repl6;
#endif
	int err = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	table = kmalloc(sizeof(struct fptun_table), GFP_KERNEL);
	if (table == NULL) {
		err = -ENOMEM;
		goto out;
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	repl = ipt_alloc_initial_table(&packet_fptun);
	if (repl == NULL)
		return -ENOMEM;
	table->ipv4 = ipt_register_table(net, &packet_fptun, repl);
	kfree(repl);
#else
	table->ipv4 = ipt_register_table(net, &packet_fptun, &initial_table.repl);
#endif
	if (IS_ERR(table->ipv4)) {
		err = PTR_ERR(table->ipv4);
		goto out_kfree;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	repl6 = ip6t_alloc_initial_table(&packet_fptun6);
	if (repl6 == NULL) {
		ipt_unregister_table(net, table->ipv4);
		return -ENOMEM;
	}
	table->ipv6 = ip6t_register_table(net, &packet_fptun6, repl6);
	kfree(repl6);
#else
	table->ipv6 = ip6t_register_table(net, &packet_fptun6, &initial_table6.repl);
#endif
	if (IS_ERR(table->ipv6)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
		ipt_unregister_table(net, table->ipv4);
#endif
		err = PTR_ERR(table->ipv6);
		goto out_kfree;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	err = net_assign_generic(net, fptun_net_id, table);
	if (err < 0)
		goto out_kfree;
#endif

out:
	return err;

out_kfree:
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	kfree(table);
#endif
	goto out;
}

static void __net_exit iptable_fptun_net_exit(struct net *net)
{
	struct fptun_table *table = net_generic(net, fptun_net_id);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	ipt_unregister_table(net, table->ipv4);
	ip6t_unregister_table(net, table->ipv6);
#else
	ipt_unregister_table(table->ipv4);
	ip6t_unregister_table(table->ipv6);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	kfree(table);
#endif
}

static struct pernet_operations iptable_fptun_net_ops = {
	.init = iptable_fptun_net_init,
	.exit = iptable_fptun_net_exit,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	.id   = &fptun_net_id,
	.size = sizeof(struct fptun_table),
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
static struct nf_hook_ops fptun_ops[] __read_mostly = {
	{
		.hook           = iptable_fptun_hook,
		.owner          = THIS_MODULE,
		.pf             = NFPROTO_IPV4,
		.hooknum        = NF_INET_POST_ROUTING,
		.priority       = NF_IP_PRI_LAST,	/* should be called after conntrack engine */
	},
};
static struct nf_hook_ops fptun6_ops[] __read_mostly = {
	{
		.hook           = ip6table_fptun6_hook,
		.owner          = THIS_MODULE,
		.pf             = NFPROTO_IPV6,
		.hooknum        = NF_INET_POST_ROUTING,
		.priority       = NF_IP6_PRI_LAST,	/* should be called after conntrack engine */
	},
};
#endif

extern struct xt_target xt_ipsecout_target[2];
static int __init iptable_fptun_init(void)
{
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	ret = register_pernet_subsys(&iptable_fptun_net_ops);
#else
	ret = register_pernet_gen_subsys(&fptun_net_id, &iptable_fptun_net_ops);
#endif
	if (ret < 0)
		return ret;

	/* Register hooks */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	fptun_ops = xt_hook_link(&packet_fptun, iptable_fptun_hook);
	if (IS_ERR(fptun_ops)) {
		ret = PTR_ERR(fptun_ops);
		goto cleanup_table;
	}
	fptun6_ops = xt_hook_link(&packet_fptun6, ip6table_fptun6_hook);
	if (IS_ERR(fptun6_ops)) {
		ret = PTR_ERR(fptun6_ops);
		goto cleanup_hook;
	}
#else
	ret = nf_register_hooks(fptun_ops, ARRAY_SIZE(fptun_ops));
	if (ret < 0)
		goto cleanup_table;
	ret = nf_register_hooks(fptun6_ops, ARRAY_SIZE(fptun6_ops));
	if (ret < 0)
		goto cleanup_hook;
#endif

	ret = xt_register_targets(xt_ipsecout_target,
				  ARRAY_SIZE(xt_ipsecout_target));
	if (ret < 0)
		goto cleanup_hook6;

#ifndef CONFIG_MCORE_RFPVI
	/* Assume local blade (co-localized mode) */
	fpn0 = dev_get_by_name(&init_net, "fpn0");
	if (fpn0 == NULL) {
		printk(KERN_ALERT "%s: unable to get fpn0\n", __FUNCTION__);
		ret = -ENODEV;
		goto cleanup_targets;
	}
#endif

	return ret;

#ifndef CONFIG_MCORE_RFPVI
cleanup_targets:
	xt_unregister_targets(xt_ipsecout_target, ARRAY_SIZE(xt_ipsecout_target));
#endif
cleanup_hook6:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	xt_hook_unlink(&packet_fptun6, fptun6_ops);
#else
	nf_unregister_hooks(fptun6_ops, ARRAY_SIZE(fptun6_ops));
#endif
cleanup_hook:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	xt_hook_unlink(&packet_fptun, fptun_ops);
#else
	nf_unregister_hooks(fptun_ops, ARRAY_SIZE(fptun_ops));
#endif
cleanup_table:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	unregister_pernet_subsys(&iptable_fptun_net_ops);
#else
	unregister_pernet_gen_subsys(fptun_net_id, &iptable_fptun_net_ops);
#endif
	return ret;
}

static void __exit iptable_fptun_fini(void)
{
#ifndef CONFIG_MCORE_RFPVI
	dev_put(fpn0);
#endif
	xt_unregister_targets(xt_ipsecout_target, ARRAY_SIZE(xt_ipsecout_target));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	xt_hook_unlink(&packet_fptun6, fptun6_ops);
	xt_hook_unlink(&packet_fptun, fptun_ops);
#else
	nf_unregister_hooks(fptun6_ops, ARRAY_SIZE(fptun6_ops));
	nf_unregister_hooks(fptun_ops, ARRAY_SIZE(fptun_ops));
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	unregister_pernet_subsys(&iptable_fptun_net_ops);
#else
	unregister_pernet_gen_subsys(fptun_net_id, &iptable_fptun_net_ops);
#endif
}

module_init(iptable_fptun_init);
module_exit(iptable_fptun_fini);
