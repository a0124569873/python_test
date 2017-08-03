#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/jiffies.h>
#include <linux/time.h>

static int mem_major = 3;

int a = 10;

int count_num = 0;


extern unsigned long volatile jiffies;



module_param(mem_major, int, S_IRUGO);

struct zxn {
	short	source;
	short	dest;
	int	bb;
	int	aa;
};
struct skb_data {
    char aa[12];
    short	frame;
    char bb[9];
    char	protocol;
};
struct frame_type{
    char aa[12];
    short frame;
};
struct protocol_type{
    char aa[23];
    char protocol;
};
struct http_type{
    char aa[34];
    uint16_t src;  
    uint16_t dest;
};
struct http_type1{
    char aa[54];
    char bb[4];
};

void print_skb_info(struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out) {
    char ip_s[16], ip_d[16];
    char m_s[18], m_d[18];
    struct timeval tv = {0};
    char p_s[5],p_d[5],t_p[5],t_p1[3];

    struct zxn *aaa = (skb->head+skb->transport_header);
    
    struct zxn zzz;
    zzz.source = aaa->source;
    zzz.dest = aaa->dest;
    snprintf(p_s, 5, "%d", zzz.source);
    snprintf(p_d, 5, "%d", zzz.dest);

    jiffies_to_timeval(jiffies, &tv);
    snprintf(ip_s, 16, "%pI4", &ip_hdr(skb)->saddr);
    snprintf(ip_d, 16, "%pI4", &ip_hdr(skb)->daddr);

    snprintf(m_s, 18, "%pM", eth_hdr(skb)->h_source);
    snprintf(m_d, 18, "%pM", eth_hdr(skb)->h_dest);


        //  printk("->:%ld %s:MAC:%s IP:%s:%s <->%s %s %s:%s TYPE:%s TYPE1:%s INT %d\n", 
        // tv.tv_sec,
        // in->name, m_s, ip_s, p_s,
        // out->name, m_d, ip_d, p_d,t_p,t_p1
        // );


    struct skb_data *iptype = skb->data;
    struct frame_type *frame_ty = skb->data;
    



    if(frame_ty->frame == 8){
        struct protocol_type *protocol_ty = skb->data;
        if(protocol_ty->protocol == 6){
            struct http_type *http_ty = skb->data;
            struct http_type1 *http_ty1 = skb->data;
//            if(strstr(http_ty1->bb,"GET")||strstr(http_ty1->bb,"get")||strstr(http_ty1->bb,"get")||strstr(http_ty1->bb,"get")){
                printk("count_num:%d,src_port:%d,dest_port:%d,data:%s",count_num,http_ty->src,http_ty->dest,http_ty1->bb);
                count_num++;
//            }


        }
    }
    
    
   
};

int ip_rcv(struct sk_buff *skb,
    struct net_device *dev,
    struct packet_type *pt,
    struct net_device *orig_dev) {
        
        print_skb_info(skb, dev, orig_dev);
    return NET_RX_DROP;
}

struct packet_type net_filters = {
    .type = __constant_htons(ETH_P_ALL),
    .func = ip_rcv,
};

static int hook_init(void) {
    dev_add_pack(&net_filters);
    printk(KERN_ALERT "%s init!\n", __FILE__);
    return 0;
}

static void hook_exit(void) {
    dev_remove_pack(&net_filters);
    printk(KERN_ALERT "%s exit!\n", __FILE__);
}





MODULE_AUTHOR("HOOK");
MODULE_LICENSE("GPL");

module_init(hook_init);
module_exit(hook_exit);
