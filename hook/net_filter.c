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
#include <linux/string.h>

static int mem_major = 3;

int a = 10;

int tcp_num = 0;
int http_num = 0;
int icmp_num = 0;
int udp_num = 0;


extern unsigned long volatile jiffies;



module_param(mem_major, int, S_IRUGO);

struct frame_type{
    char aa[12];
    short frame;
};
struct protocol_type{
    char aa[23];
    char protocol;
};
struct http_type_port{
    char aa[34];
    unsigned short src;
    unsigned short dest;
};
struct http_type_content{
    char aa[54];
    char content[0];
};

int check_http(char *str){
//    return strstr(str,"GET")
//           ||strstr(str,"POST")
//           ||strstr(str,"HTTP/1.1")
    return strstr(str,"HTTP/1.1")
//    return 1
            ;
}

unsigned short get_num(unsigned short num){
    char *zzz = &num;
    char desta[2];
    desta[0] = zzz[1];
    desta[1] = zzz[0];
    unsigned short *dest = &desta;
    return *dest;
}


void print_skb_info(struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out) {

    struct frame_type *frame_ty = skb->data;

    if(frame_ty->frame == 8){

        struct protocol_type *protocol_ty = skb->data;
        if(protocol_ty->protocol == 6){

            struct http_type_port *http_port = skb->data;
//            if (80 == get_num(http_port->src)){
//                printk("%d\n",count_num1++);
//            }
            struct http_type_content *http_content = skb->data;
            if(check_http(http_content->content)){
//                if(strstr(http_content->content,"GET")){
                printk("http:%d,src_port:%d,dest_port:%d,data:%s\n",http_num,get_num(http_port->src),get_num(http_port->dest),http_content->content);
//                printk("count_num:%d,src_port:%d,dest_port:%d,data:%4.4s\n",count_num,tcp_hdr(skb)->source,tcp_hdr(skb)->dest,http_content->content);
                http_num++;
            }else{
                printk("tcp:%d\n",tcp_num);
                tcp_num++;
            }



        }else if(protocol_ty->protocol == 1){
            printk("icmp:%d\n",icmp_num);
            icmp_num++;
        }else if(protocol_ty->protocol == 16){
            printk("udp:%d\n",udp_num);
            udp_num++;
        }
    }

    //printk("aaaaaaaaaaaaaaaaaaa%d\n",count_num++);
    

}



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
