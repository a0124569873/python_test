/* 
 * linux/drivers/net/vnic.c 
 * 
 * A simple VPN driver, just like TUN/TAP. 
 * 
 * Author: -------- Liu, <rssn@163.com> 
 * Date:   2010-3-1 
 * ( Please DO NOT remove these messages while redistributing. ) 
 * 
 * This source code is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License 
 * version 2 as published by the Free Software Foundation. 
 * 
 */  
  
#include <linux/kernel.h>  
#include <linux/module.h>  
#include <linux/slab.h>  
#include <linux/fs.h>  
#include <linux/poll.h>  
#include <linux/netdevice.h>  
#include <linux/etherdevice.h>  
#include <linux/if.h>  
#include <linux/if_arp.h>  
#include <linux/sched.h>  
  
struct vnic  
{  
    spinlock_t              lock;  
    struct net_device_stats stats;  
    struct sk_buff_head     readq;  
    wait_queue_head_t       rwait;  
    struct net_device      *dev;  
    unsigned int            flags;  
    #define VNIC_FLAG_IP_LAYER 0x00008000  
};  
  
/* --------------------- Network device part --------------------- */  
  
static int vnic_start_xmit(struct sk_buff *skb, struct net_device *dev)  
{  
    struct vnic *vnic = (struct vnic *)netdev_priv(dev);  
      
#ifdef VNIC_DEBUG  
    printk(KERN_INFO "%s[%d]: skb->len: %d\n", __FILE__, __LINE__, skb->len);  
#endif  
    if(skb_queue_len(&vnic->readq) >= dev->tx_queue_len)  
    {  
        vnic->stats.tx_fifo_errors++;  
        vnic->stats.tx_dropped++;  
        kfree_skb(skb);  
#ifdef VNIC_DEBUG  
        printk("%s[%d] qlen: %d, tx_queue_len: %d\n", __FILE__, __LINE__,  
            (int)skb_queue_len(&vnic->readq), (int)dev->tx_queue_len);  
#endif  
        return 0;  
    }  
    netif_stop_queue(dev);  
    spin_lock(&vnic->lock);  
    /* Add current `sk_buff` packet to the char device's read queue */  
    skb_queue_tail(&vnic->readq, skb);  
    dev->trans_start = jiffies;  
    spin_unlock(&vnic->lock);  
    /* Notify and wake up the reader process */  
    netif_wake_queue(dev);  
    wake_up_interruptible(&vnic->rwait);  
    return 0;  
}  
  
static int vnic_open(struct net_device *dev)  
{  
    netif_start_queue(dev);  
    return 0;  
}  
  
static int vnic_stop(struct net_device *dev)  
{  
    netif_stop_queue(dev);  
    return 0;  
}  
  
static int vnic_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)  
{  
    return 0;  
}  
  
static struct net_device_stats *vnic_stats(struct net_device *dev)  
{  
    struct vnic *vnic = netdev_priv(dev);  
    return &vnic->stats;  
}  
  
static void vnic_tx_timeout(struct net_device *dev)  
{  
    printk(KERN_WARNING "%s: Transmission timed out.\n", dev->name);  
    netif_wake_queue(dev);  
}  
  
static int vnic_set_mac_address(struct net_device *dev, void *addr)  
{  
    return 0;  
}  
  
static int vnic_change_mtu(struct net_device *dev, int mtu)  
{  
    if(mtu < 68 || mtu + dev->hard_header_len > 65535 - 20 - 8)  
        return -EINVAL;  
    dev->mtu = mtu;  
    return 0;  
}  
  
#ifdef HAVE_NET_DEVICE_OPS  
static const struct net_device_ops vnic_netdev_ops =  
{  
    .ndo_open               = vnic_open,  
    .ndo_stop               = vnic_stop,  
    .ndo_do_ioctl           = vnic_ioctl,  
    .ndo_get_stats          = vnic_stats,  
    .ndo_start_xmit         = vnic_start_xmit,  
    .ndo_set_mac_address    = vnic_set_mac_address,  
    .ndo_tx_timeout         = vnic_tx_timeout,  
    .ndo_change_mtu         = vnic_change_mtu,  
};  
#endif /* HAVE_NET_DEVICE_OPS */  
  
static void vnic_setup(struct net_device *dev)  
{  
    struct vnic *vnic = (struct vnic *)netdev_priv(dev);  
      
    /* Setup the operation handlers */  
#ifdef HAVE_NET_DEVICE_OPS  
    dev->netdev_ops      = &vnic_netdev_ops;  
#else  
    dev->open            = vnic_open;  
    dev->stop            = vnic_stop;  
    dev->do_ioctl        = vnic_ioctl;  
    dev->get_stats       = vnic_stats;  
    dev->hard_start_xmit = vnic_start_xmit;  
    dev->tx_timeout      = vnic_tx_timeout;  
    dev->set_mac_address = vnic_set_mac_address;  
    dev->change_mtu      = vnic_change_mtu;  
#endif  
    dev->watchdog_timeo  = 3 * HZ;  
      
    /* Set options for P-t-P/Ethernet device */  
    if(vnic->flags & VNIC_FLAG_IP_LAYER)  
    {  
        dev->mtu             = 1500;  
        dev->hard_header_len = 0;  
        dev->addr_len        = 0;  
        dev->type            = ARPHRD_NONE;  
        dev->flags           = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;  
        dev->tx_queue_len    = 100;  
    }  
    else  
    {  
        ether_setup(dev);  
        random_ether_addr(dev->dev_addr);  
        dev->tx_queue_len    = 100;  
    }  
  
}  
  
  
/* --------------------- Character device part ------------------- */  
  
static ssize_t vnic_chr_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)  
{  
    struct vnic *vnic = (struct vnic *)file->private_data;  
    DECLARE_WAITQUEUE(wait, current);  
    struct sk_buff *skb;  
    ssize_t len = -1;  
    unsigned long ret;  
      
    add_wait_queue(&vnic->rwait, &wait);  
    for(;;)  
    {  
        set_current_state(TASK_INTERRUPTIBLE);  
        /* Read packets from queue */  
        if((skb = skb_dequeue(&vnic->readq)))  
        {  
            len = skb->len;  
            ret = copy_to_user(data, skb->data, len);  
            vnic->stats.tx_packets++;  
            vnic->stats.tx_bytes += len;  
            //printk("---- READ: %d ----\n", len);  
              
            /* Wake up transmit queue and free packet */  
            netif_wake_queue(vnic->dev);  
            dev_kfree_skb(skb);  
            break;  
        }  
        //  
        if(file->f_flags & O_NONBLOCK)  
        {  
            len = -EAGAIN;  
            break;  
        }  
        if(signal_pending(current))  
        {  
            len = -ERESTARTSYS;  
            break;  
        }  
        /* Nothing to do, let it sleep */  
        schedule();  
    }  
      
    set_current_state(TASK_RUNNING);  
    remove_wait_queue(&vnic->rwait, &wait);  
      
    return len;  
}  
  
static ssize_t vnic_chr_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)  
{  
    struct vnic *vnic = (struct vnic *)file->private_data;  
    struct sk_buff *skb;  
    unsigned long ret;  
      
    if(count < 0)  
        return -EINVAL;  
    if(count == 0)  
        return 0;  
      
    /* Allocate buffer for received frame data */  
    if((skb = dev_alloc_skb(count + 4)) == NULL)  
    {  
        vnic->stats.rx_errors++;  
        return -EINVAL;  
    }  
    /* Fill `sk_buff` with frame data */  
    skb->dev = vnic->dev;  
    skb_reserve(skb, 2);  
    ret = copy_from_user(skb_put(skb, count), data, count);  
    if(vnic->flags & VNIC_FLAG_IP_LAYER)  
    {  
        switch(skb->data[0] & 0xf0)  
        {  
        case 0x40:  
            skb->protocol = htons(ETH_P_IP);  
            break;  
        case 0x60:  
            skb->protocol = htons(ETH_P_IPV6);  
            break;  
        default:  
            vnic->stats.rx_dropped++;  
            kfree_skb(skb);  
            return -EINVAL;  
        }  
    }  
    else  
    {  
        skb->protocol = eth_type_trans(skb, vnic->dev);  
    }  
    /* Notify the higher level with it... */  
    netif_rx(skb);  
    /* Update statistics */  
    vnic->dev->last_rx = jiffies;  
    vnic->stats.rx_packets++;  
    vnic->stats.rx_bytes += count;  
      
    return count;  
}  
  
static int vnic_chr_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)  
{  
    return 0;  
}  
  
static unsigned int vnic_chr_poll(struct file *file, poll_table *wait)  
{  
    struct vnic *vnic = (struct vnic *)file->private_data;  
    unsigned int mask = POLLOUT | POLLWRNORM;  
    //printk(">>---  ");  
    poll_wait(file, &vnic->rwait, wait);  
    //printk("---<<\n");  
    if(skb_queue_len(&vnic->readq) > 0)  
        mask |= POLLIN | POLLRDNORM;  
  
    return mask;  
}  
  
static int vnic_chr_open(struct inode *inode, struct file *file)  
{  
    struct vnic *vnic = NULL;  
    struct net_device *dev;  
      
    /* Allocate a private device structure */  
    dev = alloc_netdev(sizeof(struct vnic), "vnic%d", vnic_setup);  
    if(dev==NULL)  
    {  
        printk(KERN_ERR "%s[%d] alloc_netdev() error.\n", __FILE__, __LINE__);  
        return -1;  
    }  
    /* Set private data */  
    vnic = (struct vnic *)netdev_priv(dev);  
    memset(vnic, 0x0, sizeof(struct vnic));  
    file->private_data = (void *)vnic;  
    vnic->dev = dev;  
#ifdef VNIC_IP_LAYER  
    vnic->flags |= VNIC_FLAG_IP_LAYER;  
#endif  
    /* Register device to kernel */  
    if(register_netdev(dev) != 0)  
    {  
        free_netdev(dev);  
        printk(KERN_ERR "%s[%d] register_netdev() error.\n", __FILE__, __LINE__);  
        return -1;  
    }  
    spin_lock_init(&vnic->lock);  
    /* Initialize read q & wait q */  
    skb_queue_head_init(&vnic->readq);  
    init_waitqueue_head(&vnic->rwait);  
      
    return 0;  
}  
  
static int vnic_chr_release(struct inode *inode, struct file *file)  
{  
    struct vnic *vnic = (struct vnic *)file->private_data;  
    /* Clear read queue */  
    skb_queue_purge(&vnic->readq);  
    /* Unregister netdevice and release used private data */  
    unregister_netdev(vnic->dev);  
    free_netdev(vnic->dev); vnic->dev = NULL;  
      
    return 0;  
}  
  
/* Character device part::: */  
static const struct file_operations vnic_fops =   
{  
    .owner   = THIS_MODULE,  
    .ioctl   = vnic_chr_ioctl,  
    .read    = vnic_chr_read,  
    .write   = vnic_chr_write,  
    .open    = vnic_chr_open,  
    .poll    = vnic_chr_poll,  
    .release = vnic_chr_release,  
};  
  
  
  
#define MODULE_NAME   "vnic"  
#define DEVICE_NAME   "vnic"  
#define DEVICE_MAJOR  200  
#define DEVICE_MINOR  0  
  
static struct class *vnic_class = NULL;  
  
int  __init vnic_module_init(void)  
{  
    if(register_chrdev(DEVICE_MAJOR, DEVICE_NAME, &vnic_fops) < 0)  
    {  
        printk(KERN_ERR "%s[%d] register_chrdev() error.\n", __FILE__, __LINE__);  
        return -1;  
    }  
    /* Create dirs and files under /sys */  
    if((vnic_class = class_create(THIS_MODULE, MODULE_NAME)) == NULL)  
    {  
        printk(KERN_ERR "%s[%d] class_create() error.\n", __FILE__, __LINE__);  
        unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);  
        return -1;  
    }  
    if(device_create(vnic_class, NULL, MKDEV(DEVICE_MAJOR, DEVICE_MINOR),  
        "%s", DEVICE_NAME) == NULL)  
    {  
        printk(KERN_ERR "%s[%d] device_create() error.\n", __FILE__, __LINE__);  
        class_destroy(vnic_class);  
        vnic_class = NULL;  
        unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);  
        return -1;  
    }  
    //  
    printk(KERN_INFO "Just-VPN driver, v0.9, -------- Liu <rssn@163.com>\n");  
    //  
    return 0;  
}  
  
void __exit vnic_module_exit(void)  
{  
    device_destroy(vnic_class, MKDEV(DEVICE_MAJOR, DEVICE_MINOR));  
    class_destroy(vnic_class);  
    unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);  
}  
  
module_init(vnic_module_init);  
module_exit(vnic_module_exit);  
  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("-------- Liu <rssn@163.com>");  
MODULE_DESCRIPTION("Just-VPN Network driver, v0.9");  