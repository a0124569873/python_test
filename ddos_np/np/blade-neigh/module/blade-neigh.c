/*
 * Copyright (C) 2013 6WIND, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* 6WIND_GPL */

#ifndef CONFIG_SYSCTL
#error "this module needs CONFIG_SYSCTL"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>

#include <net/netevent.h>
#include <net/neighbour.h>

static struct timer_list inactive_active_timer;
static uint8_t inactive_active_transition = 0;

#undef DEBUG
#ifdef DEBUG
#define debug(fmt, ...)					\
do {							\
	printk("%s: "fmt, __func__, ##__VA_ARGS__);	\
} while (0)
#else
#define debug(fmt, ...)					\
do { } while (0)
#endif

/* SYSCTL */
static struct ctl_table_header *blade_neigh_sysctl_header;
static unsigned int blade_neigh_sysctl_active = 1;
/*
 * timeout after which we will restart deleting entries
 * after a inactive -> active transition.
 * 30 seconds is arbitrary
 */
static unsigned int blade_neigh_sysctl_gracetime = 30;

static int proc_blade_neigh_active(struct ctl_table *ctl, int write,
				   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int *valp = ctl->data;
	int old_active = *valp;
	int err = 0;

	if ((err = proc_dointvec(ctl, write, buffer, lenp, ppos)) < 0)
		return err;

	if (write) {
		if ((*valp != 0) && (*valp != 1)) {
			debug("invalid value for active field\n");
			err = -EINVAL;
			goto out;
		}
		if (old_active && !blade_neigh_sysctl_active) {
			debug("active => inactive: do nothing\n");
			/* active => inactive transition */
		} else if (!old_active && blade_neigh_sysctl_active) {
			/* inactive -> active transition */
			debug("inactive => active: wait for %d\n", blade_neigh_sysctl_gracetime);
			inactive_active_transition = 1;
			mod_timer(&inactive_active_timer, jiffies + blade_neigh_sysctl_gracetime * HZ);
		}
		old_active = blade_neigh_sysctl_active;
	}
out:
	return err;
}


/* Contents of /proc/sys/blade_neigh directory  */
struct ctl_table blade_neigh_sysctl_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "active",
		.data           =       &blade_neigh_sysctl_active,
		.maxlen         =       sizeof(unsigned int),
		.mode           =       0644,
		.proc_handler   =       &proc_blade_neigh_active,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "gracetime",
		.data           =       &blade_neigh_sysctl_gracetime,
		.maxlen         =       sizeof(unsigned int),
		.mode           =       0644,
		.proc_handler   =       &proc_dointvec,
	},
	/* XXX: add procfs for interface list */
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

/* Define /proc/sys/blade_neigh directory  */
struct ctl_table blade_neigh_sysctl_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name	=	CTL_UNNUMBERED,
#endif
		.procname       =       "blade-neigh",
		.mode           =       0555,
		.child          =       blade_neigh_sysctl_table,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
		.procname       =       NULL,
	}
};

#ifdef DEBUG
char *print_nud_state(__u8 state)
{
	switch (state) {
	case NUD_NONE:
		return "none";
	case NUD_INCOMPLETE:
		return "incomplete";
	case NUD_REACHABLE:
		return "reachable";
	case NUD_STALE:
		return "stale";
	case NUD_DELAY:
		return "delay";
	case NUD_PROBE:
		return "probe";
	case NUD_FAILED:
		return "failed";
	case NUD_NOARP:
		return "noarp";
	case NUD_PERMANENT:
		return "permanent";
	default:
		return "unknown";
	}
}
#endif

static int blade_neigh_netevent(struct notifier_block *self, unsigned long event,
				void *ctx)
{
	struct neighbour *neigh = ctx;

	/* system is active, don't do anything */
	if (blade_neigh_sysctl_active && !inactive_active_transition)
		return 0;

	if (neigh->ops->family != AF_INET &&
	    neigh->ops->family != AF_INET6)
		return 0;

	if (event == NETEVENT_NEIGH_UPDATE) {
		/*
		 * Prevent neighbour state machine to put entries
		 * outside reachable.
		 */
		if (neigh->nud_state == NUD_DELAY ||
		    neigh->nud_state == NUD_STALE ||
		    neigh->nud_state == NUD_PROBE) {
			neigh_hold(neigh);
			neigh_update(neigh, neigh->ha, NUD_REACHABLE, 0);
			neigh_release(neigh);
			debug("%pM => reachable\n", neigh->ha);
		} else
			debug("%pM => %s\n", neigh->ha, print_nud_state(neigh->nud_state));

	}

	return 0;
}

static struct notifier_block blade_neigh_nb = {
	.notifier_call = blade_neigh_netevent
};

static void blade_neigh_timeout(unsigned long foo)
{
	inactive_active_transition = 0;
	debug("inactive => active: restarting neighbour deletion\n");
}

int __init blade_neigh_init(void)
{
	int ret;

	printk("blade_neigh: init\n");

	/* register sysfs */
	blade_neigh_sysctl_header = register_sysctl_table(blade_neigh_sysctl_root_table);
	if (blade_neigh_sysctl_header == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	register_netevent_notifier(&blade_neigh_nb);

	setup_timer(&inactive_active_timer, blade_neigh_timeout, 0);

	return 0;

fail:
	printk("%s: init failed\n", __func__);

	return ret;
}

static void __exit blade_neigh_exit(void)
{
	printk("%s: exit\n", __func__);

	unregister_sysctl_table(blade_neigh_sysctl_header);
	unregister_netevent_notifier(&blade_neigh_nb);
}

module_init(blade_neigh_init);
module_exit(blade_neigh_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("6WIND");
