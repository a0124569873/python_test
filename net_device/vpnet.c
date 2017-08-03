#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_arp.h>
//#define VPNET_DEBUG
//#define VPNET_IP_LAYER
typedef struct vpnet
{
    spinlock_t lock;
    struct net_device_stats stats;
    struct sk_buff_head readq;
    wait_queue_head_t rwait;
    struct net_device *dev;
    unsigned int flags;
#define VPNET_FLAG_IP_LAYER 0x00008000
} vpnet_t;
/* --- Declarations start --- */
static ssize_t vpnet_chr_read(struct file *file, char __user *data, size_t count, loff_t *f_pos);
static ssize_t vpnet_chr_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos);
static int vpnet_chr_open(struct inode *inode, struct file *file);
static int vpnet_chr_release(struct inode *inode, struct file *file);
static int vpnet_chr_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
static int vpnet_start_xmit(struct sk_buff *skb, struct net_device *dev);
static int vpnet_open(struct net_device *dev);
static int vpnet_stop(struct net_device *dev);
static int vpnet_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
static unsigned int vpnet_chr_poll(struct file *file, poll_table *wait);
static struct net_device_stats *vpnet_stats(struct net_device *dev);
static void vpnet_tx_timeout(struct net_device *dev);
static int vpnet_set_mac_address(struct net_device *dev, void *addr);
static int vpnet_change_mtu(struct net_device *dev, int mtu);
static int vpnet_init(struct net_device *dev);
static void vpnet_setup(struct net_device *dev);
/* --- Declarations end --- */
/* Character device part::: */
static const struct file_operations vpnet_fops =
    {
        .owner = THIS_MODULE,
        .ioctl = vpnet_chr_ioctl,
        .read = vpnet_chr_read,
        .write = vpnet_chr_write,
        .open = vpnet_chr_open,
        .poll = vpnet_chr_poll,
        .release = vpnet_chr_release,
};
static ssize_t vpnet_chr_read(struct file *file, char __user *data, size_t count, loff_t *f_pos)
{
    vpnet_t *vpnet = (vpnet_t *)file->private_data;
    DECLARE_WAITQUEUE(wait, current);
    struct sk_buff *skb;
    ssize_t len = -1;
    unsigned long ret;

    add_wait_queue(&vpnet->rwait, &wait);
    for (;;)
    {
        set_current_state(TASK_INTERRUPTIBLE);
        if (file->f_flags & O_NONBLOCK)
        {
            len = -EAGAIN;
            break;
        }
        /* Read packets from queue */
        if ((skb = skb_dequeue(&vpnet->readq)))
        {
            len = skb->len;
            ret = copy_to_user(data, skb->data, len);
            vpnet->stats.tx_packets++;
            vpnet->stats.tx_bytes += len;
#ifdef VPNET_DEBUG
            printk("---- READ: %d ----/n", len);
#endif
            /* Wake up transmit queue and free packet */
            netif_wake_queue(vpnet->dev);
            dev_kfree_skb(skb);
            break;
        }
        //
        if (signal_pending(current))
        {
            len = -ERESTARTSYS;
            break;
        }
        /* Nothing to do, let it sleep */
        schedule();
    }

    set_current_state(TASK_RUNNING);
    remove_wait_queue(&vpnet->rwait, &wait);
    return len;
}
static ssize_t vpnet_chr_write(struct file *file, const char __user *data, size_t count, loff_t *f_pos)
{
    vpnet_t *vpnet = (vpnet_t *)file->private_data;
    struct sk_buff *skb;
    unsigned long ret;

    if (count < 0)
        return -EINVAL;
    if (count == 0)
        return 0;

    /* Allocate buffer for received frame data */
    if ((skb = dev_alloc_skb(count + 4)) == NULL)
    {
        vpnet->stats.rx_errors++;
        return -EINVAL;
    }
    /* Fill `sk_buff` with frame data */
    skb->dev = vpnet->dev;
    skb_reserve(skb, 2);
    ret = copy_from_user(skb_put(skb, count), data, count);
    if (vpnet->flags & VPNET_FLAG_IP_LAYER)
    {
        switch (skb->data[0] & 0xf0)
        {
        case 0x40:
            skb->protocol = htons(ETH_P_IP);
            break;
        case 0x60:
            skb->protocol = htons(ETH_P_IPV6);
            break;
        default:
            vpnet->stats.rx_dropped++;
            kfree_skb(skb);
            return -EINVAL;
        }
    }
    else
    {
        skb->protocol = eth_type_trans(skb, vpnet->dev);
    }
    /* Notify the higher level with it... */
    netif_rx(skb);
    /* Update statistics */
    vpnet->dev->last_rx = jiffies;
    vpnet->stats.rx_packets++;
    vpnet->stats.rx_bytes += count;

    return count;
}
static int vpnet_chr_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
    return 0;
}
static unsigned int vpnet_chr_poll(struct file *file, poll_table *wait)
{
    vpnet_t *vpnet = (vpnet_t *)file->private_data;
    unsigned int mask = POLLOUT | POLLWRNORM;
    //printk(">>---  ");
    poll_wait(file, &vpnet->rwait, wait);
    //printk("---<</n");
    if (skb_queue_len(&vpnet->readq) > 0)
        mask |= POLLIN | POLLRDNORM;
    return mask;
}
static int vpnet_chr_open(struct inode *inode, struct file *file)
{
    vpnet_t *vpnet = NULL;
    struct net_device *dev;

    /* Allocate a private device structure */
    dev = alloc_netdev(sizeof(vpnet_t), "vpnet%d", vpnet_setup);
    if (dev == NULL)
    {
        printk(KERN_ERR "%s[%d] alloc_netdev() error./n", __FILE__, __LINE__);
        return -1;
    }
    dev->init = vpnet_init;
    /* Set private data */
    vpnet = (vpnet_t *)netdev_priv(dev);
    memset(vpnet, 0x0, sizeof(vpnet_t));
    file->private_data = (void *)vpnet;
    vpnet->dev = dev;
#ifdef VPNET_IP_LAYER
    vpnet->flags |= VPNET_FLAG_IP_LAYER;
#endif
    /* Register device to kernel */
    if (register_netdev(dev) != 0)
    {
        free_netdev(dev);
        printk(KERN_ERR "%s[%d] register_netdev() error./n", __FILE__, __LINE__);
        return -1;
    }
    spin_lock_init(&vpnet->lock);
    /* Initialize read q & wait q */
    skb_queue_head_init(&vpnet->readq);
    init_waitqueue_head(&vpnet->rwait);

    return 0;
}
static int vpnet_chr_release(struct inode *inode, struct file *file)
{
    vpnet_t *vpnet = (vpnet_t *)file->private_data;
    /* Clear read queue */
    skb_queue_purge(&vpnet->readq);
    /* Unregister netdevice and release used private data */
    unregister_netdev(vpnet->dev);
    free_netdev(vpnet->dev);
    vpnet->dev = NULL;

    return 0;
}
/* Network device part::: */
static int vpnet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    vpnet_t *vpnet = (vpnet_t *)netdev_priv(dev);

#ifdef VPNET_DEBUG
    printk(KERN_INFO "%s[%d]: skb->len: %d/n", __FILE__, __LINE__, skb->len);
#endif
    if (skb_queue_len(&vpnet->readq) >= dev->tx_queue_len)
    {
        vpnet->stats.tx_fifo_errors++;
        vpnet->stats.tx_dropped++;
        kfree_skb(skb);
#ifdef VPNET_DEBUG
        printk("%s[%d] qlen: %d, tx_queue_len: %d/n", __FILE__, __LINE__,
               (int)skb_queue_len(&vpnet->readq), (int)dev->tx_queue_len);
#endif
        return 0;
    }
    netif_stop_queue(dev);
    spin_lock(&vpnet->lock);
    /* Add current `sk_buff` packet to the char device's read queue */
    skb_queue_tail(&vpnet->readq, skb);
    dev->trans_start = jiffies;
    spin_unlock(&vpnet->lock);
    /* Notify and wake up the reader process */
    netif_wake_queue(dev);
    wake_up_interruptible(&vpnet->rwait);
    return 0;
}
static int vpnet_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}
static int vpnet_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}
static int vpnet_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    return 0;
}
static struct net_device_stats *vpnet_stats(struct net_device *dev)
{
    vpnet_t *vpnet = netdev_priv(dev);
    return &vpnet->stats;
}
static void vpnet_tx_timeout(struct net_device *dev)
{
    netif_wake_queue(dev);
}
static int vpnet_set_mac_address(struct net_device *dev, void *addr)
{
    return 0;
}
static int vpnet_change_mtu(struct net_device *dev, int mtu)
{
    if (mtu < 68 || mtu + dev->hard_header_len > 65535 - 20 - 8)
        return -EINVAL;
    dev->mtu = mtu;
    return 0;
}
static int vpnet_init(struct net_device *dev)
{
    vpnet_t *vpnet = (vpnet_t *)netdev_priv(dev);
    /* Set options for P-t-P/Ethernet device */
    if (vpnet->flags & VPNET_FLAG_IP_LAYER)
    {
        dev->mtu = 1500;
        dev->hard_header_len = 0;
        dev->addr_len = 0;
        dev->type = ARPHRD_NONE;
        dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
        dev->tx_queue_len = 100;
    }
    else
    {
        ether_setup(dev);
        random_ether_addr(dev->dev_addr);
        dev->tx_queue_len = 100;
    }

    return 0;
}
static void vpnet_setup(struct net_device *dev)
{
    /* Setup the operation handlers */
    dev->open = vpnet_open;
    dev->stop = vpnet_stop;
    dev->do_ioctl = vpnet_ioctl;
    dev->get_stats = vpnet_stats;
    dev->hard_start_xmit = vpnet_start_xmit;
    dev->tx_timeout = vpnet_tx_timeout;
    dev->set_mac_address = vpnet_set_mac_address;
    dev->watchdog_timeo = 3 * HZ;
    dev->change_mtu = vpnet_change_mtu;
}
#define MODULE_NAME "vpnet"
#define DEVICE_NAME "vpnet"
#define DEVICE_MAJOR 200
#define DEVICE_MINOR 0
static struct class *vpnet_class = NULL;
int __init vpnet_module_init(void)
{
    if (register_chrdev(DEVICE_MAJOR, DEVICE_NAME, &vpnet_fops) < 0)
    {
        printk(KERN_ERR "%s[%d] register_chrdev() error./n", __FILE__, __LINE__);
        return -1;
    }
    /* Create dirs and files under /sys */
    if ((vpnet_class = class_create(THIS_MODULE, MODULE_NAME)) == NULL)
    {
        printk(KERN_ERR "%s[%d] class_create() error./n", __FILE__, __LINE__);
        unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);
        return -1;
    }
    if (device_create(vpnet_class, NULL, MKDEV(DEVICE_MAJOR, DEVICE_MINOR),
                      "%s", DEVICE_NAME) == NULL)
    {
        printk(KERN_ERR "%s[%d] device_create() error./n", __FILE__, __LINE__);
        class_destroy(vpnet_class);
        vpnet_class = NULL;
        unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);
        return -1;
    }
    //
    printk(KERN_INFO "Just-VPN driver, v0.9, Jianying Liu <rssn@163.com>/n");
    //
    return 0;
}
void __exit vpnet_module_exit(void)
{
    device_destroy(vpnet_class, MKDEV(DEVICE_MAJOR, DEVICE_MINOR));
    class_destroy(vpnet_class);
    unregister_chrdev(DEVICE_MAJOR, DEVICE_NAME);
}
module_init(vpnet_module_init);
module_exit(vpnet_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianying Liu <rssn@163.com>");
MODULE_DESCRIPTION("Just-VPN Network driver, v0.9");