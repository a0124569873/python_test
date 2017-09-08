/*************************************************************************
    > File Name: s3c_virnet.c
    > Author: 
    > Mail: 
    > Created Time: 2016年11月09日 星期三 13时27分51秒
 ************************************************************************/
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/irq.h>

static struct net_device *vnet_dev;

static void virnet_tx_packet(struct sk_buff *skb, struct net_device *dev)
{
    unsigned char *type;
    struct iphdr *ih;
    __be32 *saddr, *daddr, tmp;
    unsigned char tmp_dev_addr[ETH_ALEN];
    struct ethhdr *ethhdr;

    struct sk_buff *rx_skb;

    /* 对调MAC地址 */
    ethhdr = (struct ethhdr *)skb->data;
    memcpy(tmp_dev_addr, ethhdr->h_dest, ETH_ALEN);
    memcpy(ethhdr->h_dest, ethhdr->h_source, ETH_ALEN);
    memcpy(ethhdr->h_source, tmp_dev_addr, ETH_ALEN);

    /*  */
    ih = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;

    tmp = *saddr;
    *saddr = *daddr;
    *daddr = tmp;

    type = skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    *type = 0;

    ih->check = 0;
    ih->check = ip_fast_csum((unsigned char *)ih, ih->ihl);

    rx_skb = dev_alloc_skb(skb->len + 2);
    skb_reserve(rx_skb, 2);
    memcpy(skb_put(rx_skb, skb->len), skb->data, skb->len);

    rx_skb->dev = dev;
    rx_skb->protocol = eth_type_trans(rx_skb, dev);
    rx_skb->ip_summed = CHECKSUM_UNNECESSARY;
    dev->stats.rx_bytes += skb->len;
    dev->stats.rx_packets++;
    netif_rx(rx_skb);
}
static int virnet_send_packet(struct sk_buff *skb, struct net_device *dev)
{
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    netif_stop_queue(dev); //停止该网卡的队列
                           /*把skb的数据写入网卡*/
    //dev_kfree_skb(skb);     //释放skb
    netif_wake_queue(dev); //数据发送成功后唤醒队列
    /* 构造出一个假的sk_buff */

    virnet_tx_packet(skb, dev);

    return 0;
}

static int s3c_virnet_init(void)
{

    /* 分配一个net_device结构体 */
    vnet_dev = alloc_netdev(0, "vnet%d", ether_setup);

    /* 设置 */
    vnet_dev->hard_start_xmit = virnet_send_packet;

    /* MAC地址设置 */
    vnet_dev->dev_addr[0] = 0x07;
    vnet_dev->dev_addr[1] = 0x05;
    vnet_dev->dev_addr[2] = 0x06;
    vnet_dev->dev_addr[3] = 0x07;
    vnet_dev->dev_addr[4] = 0x08;
    vnet_dev->dev_addr[5] = 0x09;

    /* 添加下面的配置后才能ping通 */
    vnet_dev->flags |= IFF_NOARP;
    vnet_dev->features |= NETIF_F_NO_CSUM;

    /* 注册 */
    register_netdev(vnet_dev);

    return 0;
}

static void s3c_virnet_exit(void)
{
    unregister_netdev(vnet_dev);

    free_netdev(vnet_dev);
}

module_init(s3c_virnet_init);
module_exit(s3c_virnet_exit);
MODULE_LICENSE("GPL");