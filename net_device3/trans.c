//By Fanxiushu 2013-01-11

#include "vnetwk.h"

///字符设备读写
int vwk_chr_open( struct inode* ino, struct file* fp)
{
    struct vnetwk_t* vwk = NULL;
    vwk = container_of( ino->i_cdev, struct vnetwk_t, chr_dev );

    fp->private_data = vwk ; 

    printk(KERN_NOTICE"vwk_chr_open: index=%d\n", vwk->index );
    return 0;
}

int vwk_chr_release( struct inode* ino, struct file* fp)
{
    struct vnetwk_t* vwk = NULL;
    vwk = container_of( ino->i_cdev, struct vnetwk_t, chr_dev );

    return 0;
}

/// read & write 
int vwk_chr_read( struct file* fp, char* buf, size_t length, loff_t* offset )
{
    struct vnetwk_t* vwk = (struct vnetwk_t*)fp->private_data;
    struct sk_buff* skb; 
    int ret = -1; int rr;

    DECLARE_WAITQUEUE(wait, current ); //申明一个等待队列
    ////
    add_wait_queue( &vwk->wait_q, &wait ); //加入到等待队列

    while( 1 ){
        set_current_state( TASK_INTERRUPTIBLE );  //设置进程可休眠状态

        if( (skb = skb_dequeue( &vwk->skb_q )) ){ //有数据可读

            ret = skb->len > length?length:skb->len;

            rr = copy_to_user( buf, skb->data, ret ); //从内核空间复制到用户空间

            vwk->stats.tx_packets++;
            vwk->stats.tx_bytes += ret; 
            ////
            kfree_skb( skb ); 

            netif_wake_queue( vwk->net_dev ); //让上层协议可以继续发送数据包

            break;
        }
        ///
        if( fp->f_flags & O_NONBLOCK ){ //非阻塞状态
            ret = -EAGAIN;
            break;
        }
        ////
        if( signal_pending(current )) { //进程被信号中断
            ret = -ERESTARTSYS;
            break;
        }
        /////其他状态，什么都不做，调用schudle休眠
        schedule(); 

    }

    set_current_state( TASK_RUNNING ); //设置进程可运行
    remove_wait_queue( &vwk->wait_q, &wait ); //移除出等待队列

    printk(KERN_NOTICE"CHR_Read: [%d]\n", ret );

    return ret;
}

int vwk_chr_write( struct file* fp, const char* buf, size_t length, loff_t* offset )
{
    struct vnetwk_t* vwk = (struct vnetwk_t*)fp->private_data;
    struct sk_buff* skb;
    int rr;
    ////
    if( length < 0) return -EINVAL;
    if( length==0) return 0; 

    skb = dev_alloc_skb( length+4);
    if( !skb ){
        vwk->stats.rx_errors++;

        printk(KERN_ALERT"dev_alloc_skb error.\n");
        return -EINVAL;
    }

    skb->dev = vwk->net_dev; 
    skb_reserve( skb, 2 ); //保留 2个字节，干嘛的？
    rr = copy_from_user( skb_put(skb, length ), buf, length ); 
    skb->protocol = eth_type_trans(skb, skb->dev ); 

    netif_rx( skb ); 

    vwk->net_dev->last_rx = jiffies; // ?
    vwk->stats.rx_packets++;
    vwk->stats.rx_bytes += length;
    
    return length;
}

int vwk_chr_ioctl(struct inode *inode, struct file *fp, unsigned int cmd, unsigned long arg)  
{  
    struct vnetwk_t* vwk = (struct vnetwk_t*)fp->private_data;
    printk(KERN_ALERT"vnetwk chr ioctl [index=%d]\n", vwk->index );
    return 0;  
}  

unsigned int vwk_chr_poll(struct file *fp, poll_table *wait)
{
    struct vnetwk_t* vwk = (struct vnetwk_t*)fp->private_data;
    ////
    int mask = POLLOUT|POLLWRNORM; //随时可写
    
    poll_wait( fp, &vwk->wait_q, wait ); //把等待队列加到wait中，函数立即返回 

    if( skb_queue_len( &vwk->skb_q ) > 0 ) //有数据可读
        mask |= POLLIN|POLLRDNORM; 
    ///
    return mask;
}

/////////////////// network 
//打开网络设备
int vwk_net_open(struct net_device *dev)  
{  
    netif_start_queue(dev);  
    return 0;  
}  
//关闭网络设备
int vwk_net_stop(struct net_device *dev)  
{  
    netif_stop_queue(dev);  
    return 0;  
}  
//IOCTL 
int vwk_net_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)  
{  
    struct netdev_priv_t *priv = netdev_priv(dev);
    printk(KERN_ALERT"vnetwk net ioctl [index=%d] \n",priv->vwk->index );
    ///
    return 0;  
}  
//获得设备状态
struct net_device_stats *vwk_net_stats(struct net_device *dev)  
{  
    struct netdev_priv_t *priv = netdev_priv(dev);  
    return &priv->vwk->stats;  
}  
//超时  
void vwk_net_tx_timeout(struct net_device *dev)  
{  
    struct netdev_priv_t *priv = netdev_priv(dev);

    printk(KERN_WARNING "%s: Transmission timed out.\n", dev->name);  

    priv->vwk->stats.tx_errors++; //
    ///
    netif_wake_queue(dev);  
}  
//设置网卡MAC
int vwk_net_set_mac_address(struct net_device *dev, void *addr)  
{  
    //struct netdev_priv_t *priv = netdev_priv(dev);
    struct sockaddr *s = (struct sockaddr *)addr;
    ///
    if( netif_running(dev) != 0 ) {//状态，表示网卡正在运行
        printk(KERN_ALERT"vnetwk set_mac_address err; [netif_running]. \n");
        return -1; 
    }

    memcpy( dev->dev_addr, s->sa_data, ETH_ALEN ); 
    ///////

    printk(KERN_INFO "%s: Setting MAC address to `%02x:%02x:%02x:%02x:%02x:%02x`.\n", dev->name, 
        dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2],
        dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5] );

    ////
    return 0;  
}  
//改变网卡MTU  
int vwk_net_change_mtu(struct net_device *dev, int mtu)  
{  
    printk(KERN_ALERT"change_mtu [MTU=%d].\n", mtu);
    ///
    return 0;  
}  
//从上层发送数据到网卡
int vwk_net_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vnetwk_t* vwk;
    struct netdev_priv_t *priv = netdev_priv(dev);
    vwk = priv->vwk;

    //检查是否有太多数据包等待在队列里
    if( skb_queue_len( &vwk->skb_q ) >= MAX_SKB_QUENE_LEN ){
        vwk->stats.tx_fifo_errors++;
        vwk->stats.tx_dropped++; 
        kfree_skb( skb ); 

        printk(KERN_INFO"hard_start_xmit packet out of MAX_SKB_QUEUE_LEN.\n");
        return 0; 
    }
    ///

    netif_stop_queue( dev ); 

    skb_queue_tail( &vwk->skb_q, skb ); //添加SKB到队列里，这里 skb_queue_tail内部已经是加锁，所以不再另外加锁

    netif_wake_queue( dev ); 

    dev->trans_start = jiffies; //记录传输开始时间

    //唤醒进入休眠等待获得数据的 vwk_chr_read
    wake_up_interruptible( &vwk->wait_q );

    return 0; 
}

