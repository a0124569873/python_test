///By Fanxiushu 2013-01-11

#pragma once

#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/if.h>
#include <linux/poll.h>


#define  VNETWK_COUNT      10

#define MAX_SKB_QUENE_LEN   100

struct vnetwk_t
{
    ///
    struct cdev    chr_dev;
    struct class*  vwk_cls;

    int    index;
    struct net_device* net_dev;
    struct net_device_stats stats;

    struct sk_buff_head   skb_q;
    wait_queue_head_t     wait_q;
};

struct netdev_priv_t
{
    struct vnetwk_t* vwk;  
};
///
int vwk_chr_open( struct inode* ino, struct file* fp);
int vwk_chr_release( struct inode* ino, struct file* fp);
int vwk_chr_read( struct file* fp, char* buf, size_t length, loff_t* offset );
int vwk_chr_write( struct file* fp, const char* buf, size_t length, loff_t* offset );
int vwk_chr_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
unsigned int vwk_chr_poll(struct file *file, poll_table *wait);

/// network
int vwk_net_open(struct net_device *dev);
int vwk_net_stop(struct net_device *dev);
int vwk_net_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
struct net_device_stats *vwk_net_stats(struct net_device *dev);
void vwk_net_tx_timeout(struct net_device *dev);
int vwk_net_set_mac_address(struct net_device *dev, void *addr);
int vwk_net_change_mtu(struct net_device *dev, int mtu);
int vwk_net_start_xmit(struct sk_buff *skb, struct net_device *dev);