/*
 * Copyright 2009-2013 6WIND S.A.
 */

#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <asm/uaccess.h>
#include <netgraph/vnblinux.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
/* for init_net */
#include <net/net_namespace.h>

#ifdef CONFIG_PROC_FS

static struct proc_dir_entry *vnb_dir;

#ifdef CONFIG_VNB_NETLINK_NOTIFY
static int vnb_read_seqnum(struct seq_file *m, void *v)

{
	return seq_printf(m, "%u\n", vnb_seqnum);
}

static int vnb_open_seqnum(struct inode *inode, struct file *file)
{
	return single_open(file, vnb_read_seqnum, NULL);
}

static ssize_t vnb_write_seqnum(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	unsigned long value;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	char buf[64];
	int err;

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, buffer, count))
		return -EFAULT;

	buf[count] = 0;

	err = strict_strtoul(buf, 10, &value);
	if (err < 0)
		return err;
#else
	int err = kstrtoul_from_user(buffer, count, 0, &value);

	if (err)
		return err;
#endif

	spin_lock_bh(&vnb_seqnum_lock);
	vnb_seqnum = value;
	spin_unlock_bh(&vnb_seqnum_lock);

	return (count);
}

static const struct file_operations vnb_seqnum_fops = {
	.owner = THIS_MODULE,
	.open = vnb_open_seqnum,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = vnb_write_seqnum,
};
#endif

#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
uint32_t unregister_bulksize = 1024;
EXPORT_SYMBOL(unregister_bulksize);

static int vnb_read_unregister_bulksize(struct seq_file *m, void *v)

{
	return seq_printf(m, "%u\n", unregister_bulksize);
}

static int vnb_open_unregister_bulksize(struct inode *inode, struct file *file)
{
	return single_open(file, vnb_read_unregister_bulksize, NULL);
}

static ssize_t vnb_write_unregister_bulksize(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	unsigned long value;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	char buf[64];
	int err;

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, buffer, count))
		return -EFAULT;

	buf[count] = 0;

	err = strict_strtoul(buf, 10, &value);
	if (err < 0)
		return err;
#else
	int err = kstrtoul_from_user(buffer, count, 0, &value);

	if (err)
		return err;
#endif

	unregister_bulksize = value;

	return (count);
}

static const struct file_operations vnb_unregister_bulksize_fops = {
	.owner = THIS_MODULE,
	.open = vnb_open_unregister_bulksize,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = vnb_write_unregister_bulksize,
};
#endif

static int vnb_read_graph_infos(struct seq_file *m, void *v)
{
	u16 ns;

	for (ns = 0; ns < VNB_MAX_NS; ns++)
		seq_printf(m, "Total Nodes in activity (ns %u): %u\n", ns, per_ns(gNumNodes, ns));

#if VNB_DEBUG
	seq_printf(m, "Total Pointers in activity: %u\n", vnb_atomic_read(&gNumPtrs));
	seq_printf(m, "Total Pointers in Free list: %u\n", vnb_atomic_read(&gFreeNumPtrs));
#endif
#ifdef CONFIG_VNB_EXCEPTION_HANDLER
	seq_printf(m, "Invalid nodes in ng_recv_exception(): %u\n", vnb_atomic_read(&gNumDstNodeErrs));
	seq_printf(m, "Invalid hooks in ng_recv_exception(): %u\n", vnb_atomic_read(&gNumDstHookErrs));
#endif

	return 0;
}

static int vnb_open_graph_infos(struct inode *inode, struct file *file)
{
	return single_open(file, vnb_read_graph_infos, NULL);
}

static const struct file_operations vnb_graph_infos_fops = {
	.owner = THIS_MODULE,
	.open = vnb_open_graph_infos,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int vnb_init_proc(void)
{
#ifdef CONFIG_VNB_NETLINK_NOTIFY
	static struct proc_dir_entry *vnb_seqnum_proc;
#endif
#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
	static struct proc_dir_entry *vnb_unregister_bulksize_proc;
#endif
	static struct proc_dir_entry *vnb_graph_infos_proc;

	vnb_dir = proc_mkdir("vnb", init_net.proc_net);
	if (!vnb_dir)
		return EIO;

#ifdef CONFIG_VNB_NETLINK_NOTIFY
	vnb_seqnum_proc = proc_create("nl_vnb_next_seqnum",
				      S_IFREG | S_IRUGO | S_IWUSR,
				      vnb_dir, &vnb_seqnum_fops);
	if (!vnb_seqnum_proc) {
		remove_proc_entry("vnb", init_net.proc_net);
		return EIO;
	}
#endif
#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
	vnb_unregister_bulksize_proc = proc_create("unregister_bulksize",
				      S_IFREG | S_IRUGO | S_IWUSR,
				      vnb_dir, &vnb_unregister_bulksize_fops);
	if (!vnb_unregister_bulksize_proc) {
		remove_proc_entry("vnb", init_net.proc_net);
		return EIO;
	}
#endif
	vnb_graph_infos_proc = proc_create("vnb_graph_infos", 0, vnb_dir,
					   &vnb_graph_infos_fops);
	if (!vnb_graph_infos_proc)
		return EIO;

	return 0;
}

int vnb_remove_proc(void)
{
	if (vnb_dir) {
#ifdef CONFIG_VNB_NETLINK_NOTIFY
		remove_proc_entry("nl_vnb_next_seqnum", vnb_dir);
#endif
#ifdef ASYNCHRONOUS_NETDEV_REMOVAL
		remove_proc_entry("unregister_bulksize", vnb_dir);
#endif
		remove_proc_entry("vnb_graph_infos", vnb_dir);
		remove_proc_entry("vnb", init_net.proc_net);
	}

	return 0;
}
#endif
