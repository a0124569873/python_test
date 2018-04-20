/*
 * Copyright (C) 2012 6WIND, All rights reserved.
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

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/uaccess.h>        /* copy_*_user */
#include <linux/ctype.h>
#include <linux/moduleparam.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "shmem/fpn-shmem.h"

#define FPN_SHMEM_NAME "fpn_shmem: "
#define ZONE_NAME_SIZE 32

#define LIST_BUF_SIZE 32000

#ifndef CONFIG_SYSCTL
#error CONFIG_SYSCTL is required
#endif

static struct ctl_table_header *fpn_shmem_sysctl_header;

static int shm_major = 0;
static int shm_max   = 256;
static int shm_node  = -1;
module_param(shm_major, int, S_IRUGO);
module_param(shm_max, int, S_IRUGO);
module_param(shm_node, int, S_IRUGO);

/* protect the access to shm list */
static struct mutex list_mutex;

/* protect the access to minor-number pool */
static struct mutex minor_mutex;

/* bitfield of minor numbers */
static uint8_t * used_minor;

struct shm_dev {
	uint8_t *data;            /* device data */
	size_t size;              /* maximum of data stored here */
	struct semaphore sem;     /* mutual exclusion semaphore */
	struct cdev *cdev;        /* Char device structure */
	int vmas;                 /* active mappings */
};

/*
 * struct fpn_shmem for a fpn_shmem zone.
 */
struct fpn_shmem {
	struct list_head fpn_shmem_list;
	char name[ZONE_NAME_SIZE];
	struct shm_dev device;
	uint8_t major;
	uint8_t minor;
};
static LIST_HEAD(fpn_shmem_zones);

static int  fpn_shmem_register_dev(struct shm_dev *dev, size_t size, uint8_t minor);
static void fpn_shmem_unregister_dev(struct shm_dev *dev);

/* allocate a new minor number */
static int get_unused_minor(void)
{
	int i;

	mutex_lock(&minor_mutex);
	for (i = 0; i < shm_max ; i++) {
		if ((used_minor[i>>3] & (1 << (i&7))) == 0) {
			used_minor[i>>3] |= (1 << (i&7));
			mutex_unlock(&minor_mutex);
			return i;
		}
	}
	mutex_unlock(&minor_mutex);
	return -1;
}

/* free a minor number */
static void release_minor(int i)
{
	if (i >= shm_max) {
		printk(KERN_ERR FPN_SHMEM_NAME
		       "%s(): invalid minor %d\n", __func__, i);
		return;
	}

	mutex_lock(&minor_mutex);
	used_minor[i>>3] &= ~(1 << (i&7));
	mutex_unlock(&minor_mutex);
}


/*
 * === Commands format in /proc/fpn_shmem ===
 *
 * There are 2 files: /proc/fpn_shmem/add_shm and /proc/fpn_shmem/del_shm that
 * can be used to manage the shared memories zones.
 *
 * Example:
 *   fp_shared shm_order=14
 *
 * === Attribute list of commands in add_shm ===
 *
 * shm_name (required): the name of the shared zone
 *
 * shm_order (required if shm_size is not present): the size of the
 * shared zone, where 2^shm_order is the number of allocated pages.
 *
 * shm_size (required if shm_order is not present): the size of the
 * shared zone. Minimum size is 1 page.
 *
 * Note that other methods exist to reserve memory, and that the example
 * above should work on any system.
 */

#define FPN_SHMEM_PARAM_ORDER  0
#define FPN_SHMEM_PARAM_SIZE   1
#define FPN_SHMEM_PARAM_ADDR   2
#define FPN_SHMEM_PARAM_MAX    3

struct fpn_shmem_param {
	int type;
	const char *keyword;
	int has_arg;
};

static const struct fpn_shmem_param fpn_shmem_param_tab[] = {
	{ FPN_SHMEM_PARAM_ORDER, "shm_order", 1 },
	{ FPN_SHMEM_PARAM_SIZE,  "shm_size", 1 },
	{ FPN_SHMEM_PARAM_ADDR,  "shm_addr",  1 },
	{ -1,   NULL,   -1 },
};

#define FPN_SHMEM_ADD_USAGE(name) \
	printk(KERN_INFO FPN_SHMEM_NAME \
	       "%s: usage: SHM_NAME shm_order=ORDER|shm_size=SIZE_BYTES [shm_addr=ADDR]\n", (name))

/*
 * check if string is of the form "keyword=val"
 * if yes, return a pointer to val
 * else return NULL;
 */
static const char *find_val(const char *string, const char *keyword)
{
	while ((*string) && (*string == *keyword)) {
		string++; keyword++;
	}
	if ((*keyword == 0) && (*string == '='))
		return (string + 1);

	return NULL;
}

static int fpn_shmem_parse_params(char *line, const char *tab[])
{
	char *stringp;
	char *token;
	const char *val;
	char *name;

	stringp = line;

	memset(tab, 0, FPN_SHMEM_PARAM_MAX * sizeof(const char*));

	/* bypass name */
	name = strsep(&stringp, " \t");

	while (stringp) {
		const struct fpn_shmem_param *p;

		/* ignore white space */
		while (isspace(*stringp))
			stringp++;

		token = strsep(&stringp, " \t");

		val = NULL;

		for (p=fpn_shmem_param_tab; p->type != -1; p++) {
			if (p->has_arg == 0) {
				if (strcmp(token, p->keyword) == 0) {
					val = token;
					break;
				}
			} else {
				if ((val = find_val(token, p->keyword))) {
					break;
				}
			}
		}

		if (val)
			tab[p->type] = val;
		else {
			printk(KERN_NOTICE FPN_SHMEM_NAME "%s: invalid argument %s\n", __FUNCTION__, token);
			FPN_SHMEM_ADD_USAGE(name);
			return -1;
		}
	}

	return 0;
}


/*
 * fpn_shmem_find: look for a fpn_shmem zone thanks to its name.
 * Returns NULL if not found, else returns pointer to the struct fpn_shmem.
 * list_lock must be held
 */
static struct fpn_shmem *fpn_shmem_find(const char *name)
{
	struct list_head *fpn_shmem_idx;
	struct fpn_shmem *fpn_shmem = NULL;

	BUG_ON(!mutex_is_locked(&list_mutex));

	list_for_each(fpn_shmem_idx, &fpn_shmem_zones) {
		fpn_shmem = list_entry(fpn_shmem_idx, struct fpn_shmem, fpn_shmem_list);
		if (strcmp(fpn_shmem->name, name) == 0)
			return fpn_shmem;
	}
	return NULL;
}

/*
 * fpn_shmem_mmap: look for a fpn_shmem zone thanks to its name.
 * Returns NULL if not found, else returns pointer to the memory.
 */
void *fpn_shmem_mmap(const char *name,
					 void *vaddr __attribute__((unused)),
					 size_t size)
{
	struct fpn_shmem *fpn_shmem;

	mutex_lock(&list_mutex);
	fpn_shmem = fpn_shmem_find(name);
	if (fpn_shmem == NULL) {
		mutex_unlock(&list_mutex);
		return NULL;
	}
	mutex_unlock(&list_mutex);

	return fpn_shmem->device.data;
}
EXPORT_SYMBOL(fpn_shmem_mmap);

/*
 * fpn_shmem_add: allocate a memory with @name of @size bytes
 * Returns 0 on success, else returns a negative value
 */
int fpn_shmem_add(const char *name, size_t size)
{
	struct fpn_shmem *fpn_shmem = NULL;
	int minor;
	int err;

	/* find a free minor number */
	minor = get_unused_minor();
	if (minor == -1) {
		printk(KERN_ERR FPN_SHMEM_NAME "cannot register a new minor\n");
		return -ENOMEM;
	}

	/* allocate memory and register char device */
	fpn_shmem = (struct fpn_shmem *)kzalloc(sizeof(struct fpn_shmem), GFP_KERNEL);
	if (!fpn_shmem) {
		release_minor(minor);
		printk(KERN_ERR FPN_SHMEM_NAME "could not allocate new SHM "
		       "structure for %s (size 0x%zu)\n",
		       name, size);
		return -ENOMEM;
	}

	snprintf(fpn_shmem->name, ZONE_NAME_SIZE, "%s", name);
	fpn_shmem->major = shm_major;
	fpn_shmem->minor = minor;
	err = fpn_shmem_register_dev(&fpn_shmem->device, size, minor);
	if (err < 0) {
		kfree(fpn_shmem);
		release_minor(minor);
		printk(KERN_ERR FPN_SHMEM_NAME "failed to register\n");
		return err;
	}

	mutex_lock(&list_mutex);
	if (fpn_shmem_find(fpn_shmem->name)) {
		mutex_unlock(&list_mutex);
		fpn_shmem_unregister_dev(&fpn_shmem->device);
		kfree(fpn_shmem);
		release_minor(minor);
		return -EEXIST;
	}

	list_add(&fpn_shmem->fpn_shmem_list, &fpn_shmem_zones);
	mutex_unlock(&list_mutex);

	return 0;
}
EXPORT_SYMBOL(fpn_shmem_add);

/*
 * fpn_shmem_init_one: add a shm interface
 * Returns 0 on success, else returns a negative value
 */
static int fpn_shmem_init_one(char *name)
{
	const char *tab[FPN_SHMEM_PARAM_MAX];
	int err=0;
	size_t size=0;
	char *end;

	if (fpn_shmem_parse_params(name, tab)) {
		err = -EINVAL;
		printk(KERN_ERR FPN_SHMEM_NAME "%s: cannot parse params\n", name);
		return err;
	}

	if (tab[FPN_SHMEM_PARAM_ORDER] == NULL && tab[FPN_SHMEM_PARAM_SIZE] == NULL) {
		printk(KERN_ERR FPN_SHMEM_NAME "%s: size is missing\n", name);
		FPN_SHMEM_ADD_USAGE(name);
		err = -EINVAL;
		return err;
	}
	if (tab[FPN_SHMEM_PARAM_ORDER] && tab[FPN_SHMEM_PARAM_SIZE]) {
		printk(KERN_ERR FPN_SHMEM_NAME
		       "%s: size and order are exclusive\n", name);
		FPN_SHMEM_ADD_USAGE(name);
		err = -EINVAL;
		return err;
	}
	if (tab[FPN_SHMEM_PARAM_ORDER])
		size = 1UL << (PAGE_SHIFT +
			       simple_strtoul(tab[FPN_SHMEM_PARAM_ORDER],
					      &end, 0));
	else
		size = simple_strtoul(tab[FPN_SHMEM_PARAM_SIZE], &end, 0);
	if (*end != 0 || size <= 0) {
		err = -EINVAL;
		printk(KERN_ERR FPN_SHMEM_NAME "%s: invalid size\n", name);
		return err;
	}

	err = fpn_shmem_add(name, size);
	if (err != 0) {
		/* up to the caller to emit a warning */
		return err;
	}

	return 0;
}

static void fpn_shmem_free_one(struct fpn_shmem *fpn_shmem)
{
	fpn_shmem_unregister_dev(&fpn_shmem->device);
	release_minor(fpn_shmem->minor);
	kfree(fpn_shmem);
}

/*
 * fpn_shmem_del: remove shm with @name
 * Returns 0 on success, else returns a positive value if not found
 *                                 or a negative value in case of error
 */
int fpn_shmem_del(const char *name)
{
	struct fpn_shmem *fpn_shmem;

	mutex_lock(&list_mutex);
	fpn_shmem = fpn_shmem_find(name);
	if (fpn_shmem == NULL) {
		mutex_unlock(&list_mutex);
		return 1;
	}

	list_del(&fpn_shmem->fpn_shmem_list);
	mutex_unlock(&list_mutex);
	fpn_shmem_free_one(fpn_shmem);

	return 0;
}
EXPORT_SYMBOL(fpn_shmem_del);

/*
 * Handler when /proc/sys/fpn_shmem/add_shm is written. Add the shm zone in
 * the system. Returns 0 on success, else returns a negative value.
 */
static
int fpn_shmem_sysctl_add_zone(struct ctl_table *ctl, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err;
	struct ctl_table ctl_copy;
	char buf[512];

	memcpy(&ctl_copy, ctl, sizeof(ctl_copy));
	ctl_copy.data = buf;
	ctl_copy.maxlen = sizeof(buf);

	if ((err = proc_dostring(&ctl_copy, write, buffer, lenp, ppos)) < 0)
		return err;

	/* add shm zone and empty /proc/fpn_shmem/add_shm */
	if (write)
		err = fpn_shmem_init_one(buf);

	return err;
}

/*
 * Handler when /proc/sys/fpn_shmem/del_shm is written. Delete the shm zone
 * from the system. Returns 0 on success, else returns a negative
 * value.
 */
static
int fpn_shmem_sysctl_del_zone(struct ctl_table *ctl, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char name[ZONE_NAME_SIZE];
	int err;
	struct ctl_table ctl_copy;
	char buf[512];

	memcpy(&ctl_copy, ctl, sizeof(ctl_copy));
	ctl_copy.data = buf;
	ctl_copy.maxlen = sizeof(buf);

	if ((err = proc_dostring(&ctl_copy, write, buffer, lenp, ppos)) < 0)
		return err;

	if (write) {
		snprintf(name, sizeof(name), "%s", buf);
		if (fpn_shmem_del(name) != 0) {
			printk(KERN_NOTICE FPN_SHMEM_NAME "shm zone not found: %s\n", name);
			err = -ENODEV;
		}
		return err;
	}

	return 0;
}

/*
 * Handler when /proc/sys/fpn_shmem/list_shm is read.
 */
static
int fpn_shmem_sysctl_list_zone(struct ctl_table *ctl, int write,
			    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct list_head *fpn_shmem_idx;
	struct fpn_shmem *fpn_shmem;
	int err, n;
	int len=0;
	struct ctl_table ctl_copy;
	char * buf;

	if (write)
		return -EPERM;

	buf = vmalloc(LIST_BUF_SIZE);
	if (buf == NULL)
		return -ENOMEM;

	n = snprintf(buf, LIST_BUF_SIZE, "name size major minor\n--------------");
	if (n < 0) {
		vfree(buf);
		return -EINVAL;
	}

	mutex_lock(&list_mutex);
	list_for_each(fpn_shmem_idx, &fpn_shmem_zones) {
		len += n;
		if (len >= LIST_BUF_SIZE) {
			printk(KERN_DEBUG FPN_SHMEM_NAME "shm list is truncated (%d>=%d)\n",
			       len, LIST_BUF_SIZE);
			break;
		}
		fpn_shmem = list_entry(fpn_shmem_idx, struct fpn_shmem, fpn_shmem_list);
		n = snprintf(&buf[len], LIST_BUF_SIZE-len,
			     "\n%s 0x%zX %u %u", fpn_shmem->name,
			     fpn_shmem->device.size, fpn_shmem->major, fpn_shmem->minor);
		if (n < 0) {
			mutex_unlock(&list_mutex);
			vfree(buf);
			return -EINVAL;
		}
	}
	mutex_unlock(&list_mutex);

	memcpy(&ctl_copy, ctl, sizeof(ctl_copy));
	ctl_copy.data = buf;
	ctl_copy.maxlen = LIST_BUF_SIZE;

	if ((err = proc_dostring(&ctl_copy, write, buffer, lenp, ppos)) < 0) {
		vfree(buf);
		return err;
	}

	vfree(buf);
	return 0;
}

/*
 * Contents of /proc/sys/fpn_shmem directory
 */
struct ctl_table fpn_shmem_sysctl_zone_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       CTL_UNNUMBERED,
#endif
		.procname       =       "add_shm",
		.mode           =       0644,
		.proc_handler   =       &fpn_shmem_sysctl_add_zone,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       CTL_UNNUMBERED,
#endif
		.procname       =       "del_shm",
		.mode           =       0644,
		.proc_handler   =       &fpn_shmem_sysctl_del_zone,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       CTL_UNNUMBERED,
#endif
		.procname       =       "list_shm",
		.mode           =       0444,
		.proc_handler   =       &fpn_shmem_sysctl_list_zone,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
	}
};

/*
 * Define /proc/sys/fpn_shmem directory
 */
struct ctl_table fpn_shmem_sysctl_root_table[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       CTL_UNNUMBERED,
#endif
		.procname       =       "fpn_shmem",
		.mode           =       0555,
		.child          =       fpn_shmem_sysctl_zone_table,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		.ctl_name       =       0,      /* sentinel */
#endif
	}
};

/*
 * this code applies for shared memories using char devices
 * operations includes read/write/mmap
 */
static int shm_open(struct inode *inode, struct file *filp)
{
	struct list_head *fpn_shmem_idx;
	struct fpn_shmem *fpn_shmem;
	struct shm_dev *dev = NULL; /* device information */
	mutex_lock(&list_mutex);
	list_for_each(fpn_shmem_idx, &fpn_shmem_zones) {
		fpn_shmem = list_entry(fpn_shmem_idx, struct fpn_shmem, fpn_shmem_list);
		if (inode->i_cdev->dev == MKDEV(fpn_shmem->major, fpn_shmem->minor))
			dev = &fpn_shmem->device;
	}
	mutex_unlock(&list_mutex);

	if (dev == NULL)
		return -ENXIO;

	filp->private_data = dev; /* for other methods */
	/* now trim to 0 the length of the device if open was write-only */
	if ( (filp->f_flags & O_ACCMODE) == O_WRONLY) {
		if (down_interruptible(&dev->sem))
				return -ERESTARTSYS;
		filp->f_pos = 0;
		up(&dev->sem);
	}

	return 0;
}

static int shm_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t shm_read(struct file *filp, char __user *buf, size_t count,
		loff_t *f_pos)
{
	struct shm_dev *dev = filp->private_data;
	ssize_t retval = 0;

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	if (*f_pos >= dev->size)
		goto out;
	if (*f_pos + count > dev->size)
		count = dev->size - *f_pos;

	if (copy_to_user(buf, dev->data + *f_pos, count)) {
		retval = -EFAULT;
		goto out;
	}

	*f_pos += count;
	retval = count;
out:
	up(&dev->sem);
	return retval;
}

static ssize_t shm_write(struct file *filp, const char __user *buf, size_t count,
		loff_t *f_pos)
{
	struct shm_dev *dev = filp->private_data;
	ssize_t retval = 0;

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	if (*f_pos >= dev->size)
		goto out;
	if (*f_pos + count > dev->size)
		count = dev->size - *f_pos;

	if (copy_from_user(dev->data + *f_pos, buf, count)) {
		retval = -EFAULT;
		goto out;
	}

	*f_pos += count;
	retval = count;
out:
	up(&dev->sem);
	return retval;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
static int shm_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
#else
static long shm_ioctl(struct file *filp,
		unsigned int cmd, unsigned long arg)
#endif
{
	return -EINVAL;
}

static loff_t shm_llseek(struct file *filp, loff_t off, int whence)
{
	struct shm_dev *dev = filp->private_data;
	loff_t newpos;

	switch(whence) {
	  case 0: /* SEEK_SET */
			newpos = off;
			break;

	  case 1: /* SEEK_CUR */
			newpos = filp->f_pos + off;
			break;

	  case 2: /* SEEK_END */
			newpos = dev->size + off;
			break;

	  default: /* can't happen */
			return -EINVAL;
	}
	if (newpos < 0 || newpos > dev->size)
		return -EINVAL;
	filp->f_pos = newpos;
	return newpos;
}

/*
 * open and close: just keep track of how many times the device is
 * mapped, to avoid releasing it.
 */
static void shm_vma_open(struct vm_area_struct *vma)
{
        struct shm_dev *dev = vma->vm_private_data;
        dev->vmas++;
}

static void shm_vma_close(struct vm_area_struct *vma)
{
        struct shm_dev *dev = vma->vm_private_data;
        dev->vmas--;
}

static int shm_vma_access(struct vm_area_struct *vma, unsigned long addr,
			  void *buf, int len, int write)
{
        struct shm_dev *dev = vma->vm_private_data;
        int offset = (addr) - vma->vm_start;

        if (write)
                memcpy(dev->data + offset, buf, len);
        else
                memcpy(buf, dev->data + offset, len);

        return len;
}

/* mm/mem.c special_mapping_fault() */
static int shm_vma_fault(struct vm_area_struct *vma,
		struct vm_fault *vmf)
{
	struct shm_dev *dev = vma->vm_private_data;
	unsigned long offset;
	struct page *page;
	void *pageptr;

	offset = vmf->pgoff << PAGE_SHIFT;
	if (offset >= dev->size)
		return VM_FAULT_SIGBUS;

	pageptr = dev->data + offset;
	page = vmalloc_to_page(pageptr);

	if (!page)
		return VM_FAULT_NOPAGE;

	get_page(page);
	vmf->page = page;
	return 0;
}

struct vm_operations_struct shm_vm_ops = {
	.open =     shm_vma_open,
	.close =    shm_vma_close,
	.access =   shm_vma_access,
	.fault = shm_vma_fault,
};

static int shm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	/* don't do anything here: "nopage" or "fault"  will set up page table entries */
	vma->vm_ops = &shm_vm_ops;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	vma->vm_flags |= VM_RESERVED;
#else
	vma->vm_flags |= VM_IO | VM_DONTEXPAND;
#endif
	vma->vm_private_data = filp->private_data;
	shm_vma_open(vma);
	return 0;
}

static const struct file_operations shm_fops = {
	.owner   = THIS_MODULE,
	.llseek  = shm_llseek,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	.ioctl   = shm_ioctl,
#else
	.unlocked_ioctl = shm_ioctl,
#endif
	.open    = shm_open,
	.read    = shm_read,
	.write   = shm_write,
	.release = shm_release,
	.mmap    = shm_mmap,
};

/* register a new shm device and returns its device number */
static int fpn_shmem_register_dev(struct shm_dev *dev, size_t size, uint8_t minor)
{
	int err, devno = MKDEV(shm_major, minor);

	memset(dev, 0, sizeof(struct shm_dev));
	sema_init(&dev->sem, 1);
	dev->cdev = cdev_alloc();
	if (dev->cdev == NULL) {
		printk(KERN_ERR "shm: can not allocate device");
		return -1;
	}
	dev->cdev->owner = THIS_MODULE;
	dev->cdev->ops   = &shm_fops;
	err = cdev_add(dev->cdev, devno, 1);
	/* Fail gracefully if need be */
	if (err) {
		printk(KERN_ERR "shm: error %d while registering shared memory", err);
		return -1;
	}

	dev->size = (size & PAGE_MASK) + PAGE_SIZE;
	if ((shm_node != -1) && (node_online(shm_node))) {
		/* force allocation of shared memory on selected node */
		printk(KERN_INFO "shm: allocating %zum on node %d\n", size >> 20, shm_node);
		dev->data = vmalloc_node(dev->size, shm_node);
	} else {
		dev->data = vmalloc(dev->size);
	}
	if (dev->data == NULL) {
		cdev_del(dev->cdev);
		printk(KERN_ERR "shm: error while allocating shared memory");
		return -1;
	}
	memset (dev->data, 0, dev->size);
	return devno;
}

/* unregister previoulsy registered allocated shm device */
static void fpn_shmem_unregister_dev(struct shm_dev *dev)
{
	cdev_del(dev->cdev);
	if (dev->data)
		vfree(dev->data);
}

/*
 * Module init/exit
 */
static void __exit fpn_shmem_exit(void)
{
	struct fpn_shmem *fpn_shmem;

	/* unregister sysctls */
	unregister_sysctl_table(fpn_shmem_sysctl_header);

	while (1) {

		mutex_lock(&list_mutex);
		if (list_empty(&fpn_shmem_zones)) {
			mutex_unlock(&list_mutex);
			break;
		}

		fpn_shmem = list_first_entry(&fpn_shmem_zones, struct fpn_shmem,
					     fpn_shmem_list);

		list_del(&fpn_shmem->fpn_shmem_list);
		mutex_unlock(&list_mutex);

		fpn_shmem_free_one(fpn_shmem);
	}

	/* unregister char device */
	unregister_chrdev_region(MKDEV (shm_major, 0), shm_max);

	/* Free memory */
	if (used_minor != NULL) vfree(used_minor);
}

static int __init fpn_shmem_init(void)
{
	int result;
	dev_t dev = 0;

	mutex_init(&list_mutex);
	mutex_init(&minor_mutex);

	/* alloc major of char device */
	if (shm_major) {
		dev = MKDEV(shm_major, 0);
		result = register_chrdev_region(dev, shm_max, "shm");
	} else {
		result = alloc_chrdev_region(&dev, 0, shm_max, "shm");
		shm_major = MAJOR(dev);
	}

	if (result < 0) {
		printk(KERN_ERR "fpn_shmem: can't get major %d\n", shm_major);
		return -1;
	}

	if (shm_max < 0) {
		printk(KERN_ERR "fpn_shmem: invalid device number %d\n", shm_max);
		return -1;
	}

	/* Dynamically allocate used_minor */
	used_minor = vmalloc((shm_max + 7) / 8);
	if (used_minor == NULL) {
		printk(KERN_ERR "fpn_shmem: can not allocate memory for used minor\n");
		return -1;
	}

	/* Clear memory */
	memset(used_minor, 0, (shm_max + 7) / 8);

	/* register sysctls */
	fpn_shmem_sysctl_header = register_sysctl_table(fpn_shmem_sysctl_root_table);
	printk(KERN_INFO FPN_SHMEM_NAME "fpn_shmem module initialized %p\n", fpn_shmem_sysctl_header);
	return 0;
}

module_init(fpn_shmem_init);
module_exit(fpn_shmem_exit);

MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("fpn-sdk shmem module");
MODULE_LICENSE("GPL");
