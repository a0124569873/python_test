#if defined(__LinuxKernelVNB__)
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>

#include <linux/jhash.h>
#include <linux/time.h>
#include <linux/rtc.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <net/route.h>
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_log.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>

#include "veda_ddos/read_fp_shared.h"

#elif defined(__FastPath__)
#include <unistd.h>
#include "fp-includes.h"
#include "fp-main-process.h"
#include "fp-netgraph.h"
#include <fpn-mbuf.h>
#include "net/fp-ethernet.h"
#include "netinet/fp-in.h"
#include "netinet/fp-ip.h"
#include "netinet/fp-udp.h"
#include "netinet/fp-tcp.h"
#include "fp-nfct.h"
#include <fp-nf-tables.h>
#include "fp-netfilter.h"
#include "fp-nf-nat.h"
#include "fp-nf-cache.h"
#include "fpn-cksum.h"
#include "fp-log.h"
#include "server_flow_deal.h"
#include "server_ip_port_deal.h"
#endif

#include <netgraph/ng_ddos.h>
#include "veda_ddos/vlan_function.h"
#include "veda_ddos/general_inline_functions.h"
#include "server_config.h"
#include "fp-arp.h"

static VNB_DEFINE_SHARED(vnb_spinlock_t, list_lock); /* lock for list access */

static const struct ng_cmdlist ng_ddos_cmdlist[] = {
#if defined(__FastPath__)
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_INFO,
		"get_ddos_status",
		NULL,
		&ng_parse_string_type
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_EMPTY,
		"server_empty",
		NULL,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_CONFIG,
		"server_config",
		NULL,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_ADD,
		"server_add",
		&ng_ddos_server_type,
		NULL
	},

	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_DELETE,
		"server_delete",
		&ng_ddos_server_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_UPDATE,
		"server_update",
		&ng_ddos_server_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SHOW_SERVER,
		"show_server",
		NULL,
		&ng_parse_string_type
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SHOW_SERVER_CONFIG,
		"show_server_config",
		&ng_ddos_ip_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_BLACK_WHITE_EMPTY,
		"black_white_empty",
		NULL,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_BLACK_WHITE_CONFIG,
		"black_white_config",
		NULL,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_BLACK_WHITE_ADD,
		"black_white_add",
		&ng_ddos_black_white_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_BLACK_WHITE_DELETE,
		"black_white_del",
		&ng_ddos_black_white_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SHOW_BLACK_WHITE,
		"show_black_white",
		&ng_parse_uint32_type,
		&ng_parse_string_type
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_TEMP_BLACK_WHITE_STATUS,
		"temp_black_white_status",
		NULL,
		&ng_parse_string_type
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_TEMP_BLACK_WHITE_DELETE,
		"temp_black_white_del",
		&ng_ddos_black_white_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_IP_MAC_EMPTY,
		"ip_mac_empty",
		NULL,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_IP_MAC_ADD,
		"ip_mac_add",
		&ng_ddos_ip_mac_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_IP_MAC_DELETE,
		"ip_mac_delete",
		&ng_ddos_ip_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_IP_MAC_UPDATE,
		"ip_mac_update",
		&ng_ddos_ip_mac_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SHOW_IP_MAC,
		"show_ip_mac",
		NULL,
		&ng_parse_string_type
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_FLOW_ADD,
		"server_flow_add",
		&ng_ddos_ip_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SERVER_FLOW_DELETE,
		"server_flow_delete",
		&ng_ddos_ip_type,
		NULL
	},
	{
		NGM_DDOS_COOKIE,
		NGM_DDOS_SHOW_SERVER_FLOW,
		"show_server_flow",
		NULL,
		&ng_parse_string_type
	},
#endif
#if defined(__LinuxKernelVNB__)
	{	0, 0, NULL, NULL, NULL}
#endif
};

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_ddos_constructor;
static ng_rcvmsg_t ng_ddos_rcvmsg;
static ng_shutdown_t ng_ddos_shutdown;
static ng_newhook_t ng_ddos_newhook;
static ng_rcvdata_t ng_ddos_rcvdata;
static ng_disconnect_t ng_ddos_disconnect;

/* Store each hook's link number in the private field */
#define LINK_NUM_DDOS(hook)		(intptr_t)NG_HOOK_PRIVATE(hook)
/*
 * Node type descriptor
 */

static VNB_DEFINE_SHARED(struct ng_type, ng_ddos_typestruct) = {
	version: NG_VERSION,
	name: NG_DDOS_NODE_TYPE,
	mod_event: NULL, /* module event handler (optional) */
	constructor:ng_ddos_constructor, /* node constructor */
	rcvmsg: ng_ddos_rcvmsg, /* control messages come here */
	shutdown: ng_ddos_shutdown, /* reset, and free resources */
	newhook: ng_ddos_newhook, /* first notification of new hook */
	findhook: NULL, /* only if you have lots of hooks */
	connect: NULL, /* final notification of new hook */
	afterconnect:NULL,
	rcvdata: ng_ddos_rcvdata, /* date comes here */
	rcvdataq: ng_ddos_rcvdata, /* or here if being queued */
	disconnect: ng_ddos_disconnect, /* notify on disconnect */
	rcvexception: NULL, /* exceptions come here */
	dumpnode: NULL,
	restorenode: NULL,
	dumphook: NULL,
	restorehook: NULL,
	cmdlist: ng_ddos_cmdlist, /* commands we can convert */
};
NETGRAPH_INIT(ddos, &ng_ddos_typestruct);
NETGRAPH_EXIT(ddos, &ng_ddos_typestruct);

/******************************************************************
 NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 */
static int ng_ddos_constructor(node_p *nodep, ng_ID_t nodeid) {
	priv_p priv;
	int error = 0;

	/* Call superclass constructor */
	if ((error = ng_make_node_common_and_priv(&ng_ddos_typestruct, nodep,
			&priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));

	priv->phy_hooks = ng_malloc(
	NG_DDOS_MAX_LINKS * sizeof(hook_p), M_NOWAIT | M_ZERO);
	if (unlikely(priv->phy_hooks == NULL)) {
		ng_free(priv);
		return (ENOMEM);
	}

#if defined(__FastPath__)
//veda_ddos init

	//detect time init, the time unit is sec	

#endif
#if defined(__LinuxKernelVNB__)

	//kernel vnb init

	/* release shared mem */
	fp_shared = fpn_shmem_mmap("fp-shared", NULL, sizeof(shared_mem_t));

#endif

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->ddos_node = *nodep;
	vnb_spinlock_init(&list_lock);
	/* Done */
	return (0);
}

int fp_ddos_init(void)
{
	fp_shared->default_detect_cycle = 1;
	fp_shared->white_effect_time = 30;
	fp_shared->black_effect_time = 30;

	fp_shared->tcp_ack_number = 0xeeeeeeee;
	fp_shared->stream_return = NGM_DDOS_PBR_RETURN;

	//cpu frequency
	fp_shared->cpu_hz = rte_get_timer_hz();
	memset((uint8_t *)server_table, 0, SERVER_TABLE * sizeof(struct server_table));
	memset((uint8_t *)client_tcp_table, 0, CLIENT_TCP_TABLE * sizeof(struct client_tcp_table));
	memset((uint8_t *)client_udp_table, 0, CLIENT_UDP_TABLE * sizeof(struct client_udp_table));

	

	memcpy(fp_shared->fp_ddos_shm, fp_ddos_shm, sizeof(struct ddos_shm_info) * DDOS_SHM_TOTAL);

	for(int i = 0; i < DDOS_SHM_TOTAL; i++){
		fp_shm_addr[i] = fp_ddos_shm_create(&fp_ddos_shm[i]);
		if(NULL == fp_shm_addr[i])	{			
			printf("Create shared memory for %s failed!\n", fp_ddos_shm[i].name);
			return -1;
		}		
	}

	return 0;
}
/*
 * Method for attaching a new hook
 * There are two kinds of hook:
 *   - the linkrecv/linksend hook which links to an interface
 */
static int ng_ddos_newhook(node_p node, hook_p hook, const char *name) {
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p *link;
	uint32_t linkNum;
	u_long i;

	/* Which hook? */
	if (strncmp(name, NG_DDOS_HOOK_ETH_PREFIX,
			strlen(NG_DDOS_HOOK_ETH_PREFIX)) == 0) {
		const char *cp;
		char *eptr;

		cp = name + strlen(NG_DDOS_HOOK_ETH_PREFIX);
		if (!isdigit(*cp) || (cp[0] == '0' && cp[1] != '\0'))
			return (EINVAL);
		i = strtoul(cp, &eptr, 10);
		if (*eptr != '\0' || i >= NG_DDOS_MAX_LINKS)
			return (EINVAL);
		linkNum = (int) i;
		link = &priv->phy_hooks[linkNum];

	} else
		return (EINVAL);

	if (*link != NULL)
		return (EISCONN);

	/* Setup private info for this link */
	NG_HOOK_SET_PRIVATE(hook, (void * )(intptr_t )linkNum);
	*link = hook;
	return 0;
}

/*
 * Receive a control message
 */
static int ng_ddos_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg) {
	int error = 0;

	struct ng_mesg *resp = NULL;
	priv_p priv = NULL;
	priv = NG_NODE_PRIVATE(node);
	if (!priv) {
		return 0;
	}
	switch (msg->header.typecookie) {
	case NGM_DDOS_COOKIE: {
		switch (msg->header.cmd) {
#if defined(__FastPath__)
	case NGM_DDOS_SERVER_INFO:
	{
		create_ddos_server_info();
		break;
	}
	case NGM_DDOS_SERVER_EMPTY:
	{
	//	memset((uint8_t *)server_table, 0, SERVER_TABLE * sizeof(struct server_table));
		break;
	}
	case NGM_DDOS_SERVER_CONFIG:
	{
		ddos_server_config();
		break;
	}
	case NGM_DDOS_SERVER_ADD:
	{
		struct server_config *p_cfg;

		uint32_t *in = (uint32_t *)msg->data;
		uint32_t dstip = in[0];
		//uint32_t mask = (uint32_t)in[1];

		/*detail server configuration from in[2]*/
		p_cfg = (struct server_config *)(in+2);
		//HOST_PROTECT_PARAM *p_host = &p_cfg->host_prot_para;
        //printf("Syn:%d, syn_ss:%d, ack_rst:%d, udp:%d!\n", p_host->syn_thres, p_host->syn_ss_thres, p_host->ack_rst_thres, p_host->udp_thres);

        //for(uint32_t i = 0; i < p_cfg->tcp_port_num; i++ )
        	//printf("Num:%d, str:%d, end:%d!\n", i, p_cfg->tcp_prot_para[i].start, p_cfg->tcp_prot_para[i].end);
		add_server_node(dstip, p_cfg);
		break;
	}
	case NGM_DDOS_SERVER_UPDATE:
	{
		//uint32_t *pconfig = NULL;
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t dstip = in[0];
		uint32_t mask = in[1];


		/*detail server configuration from in[2]*/
		struct server_config *p_cfg;
		p_cfg = (struct server_config *)(in+2);
		//HOST_PROTECT_PARAM *p_host = &p_cfg->host_prot_para;
        //printf("Syn:%d, syn_ss:%d, ack_rst:%d, udp:%d!\n", p_host->syn_thres, p_host->syn_ss_thres, p_host->ack_rst_thres, p_host->udp_thres);

		//for(uint32_t i = 0; i < p_cfg->tcp_port_num; i++ )
        	//printf("Num:%d, str:%d, end:%d!\n", i, p_cfg->tcp_prot_para[i].start, p_cfg->tcp_prot_para[i].end);
		update_server_node(dstip, mask, p_cfg);
		break;
	}
	case NGM_DDOS_SHOW_SERVER_CONFIG:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t dstip = in[0];
		//printf("dstip:%d.\n", dstip);
		show_server_config(dstip);
		break;
	}
	case NGM_DDOS_SHOW_SERVER:
	{
		show_server_node();
		break;
	}
	case NGM_DDOS_SERVER_DELETE:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t dstip = in[0];
	//	uint16_t dport = (uint16_t)in[1];

		delete_server_node(dstip);
		break;
	}
	case NGM_DDOS_BLACK_WHITE_EMPTY:
	{
		//memset((uint8_t *)black_white_table, 0, BLACK_WHITE_TABLE * sizeof(struct black_white_table));
		break;
	}
	case NGM_DDOS_BLACK_WHITE_CONFIG:
	{
		ddos_black_white_config();
		break;
	}
	case NGM_DDOS_BLACK_WHITE_ADD:
	{		
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t srcip = in[0];
		uint32_t dstip = in[1];
		uint16_t dport = (uint16_t)in[2];
		uint32_t type = in[3];

		add_black_white_node(srcip, dstip, htons(dport), type, 0);
	
		break;
	}
	case NGM_DDOS_BLACK_WHITE_DELETE:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t srcip = in[0];
		uint32_t dstip = in[1];
		uint16_t dport = (uint16_t)in[2];
		uint32_t type = in[3];

		delete_black_white_node(srcip, dstip, htons(dport), type, 0);

		break;
	}
	case NGM_DDOS_SHOW_BLACK_WHITE:
	{
		//show_black_white_node();
		uint32_t *type = (uint32_t *)msg->data;
		if(type[0] <= 0 || type[0] > 3)
			printf("Not supported arg:%u.\n", type[0]);
		if(type[0] & 1)
			show_black_node();
		if(type[0] & 2)
			show_white_node();

		break;
	}
	case NGM_DDOS_TEMP_BLACK_WHITE_STATUS:
	{
		get_temp_black_white_info();

		break;
	}
	case NGM_DDOS_TEMP_BLACK_WHITE_DELETE:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t srcip = in[0];
		uint32_t dstip = in[1];
		uint32_t type = in[3];

		printf("srcip:%d, dstip:%d, type:%d.\n", srcip, dstip, type);

		delete_temp_black_white_node(srcip, dstip, type);

		break;
	}
	case NGM_DDOS_IP_MAC_EMPTY:
	{
		memset((uint8_t *)ip_mac_table, 0, IP_MAC_TABLE* sizeof(struct ip_mac_table));
		break;
	}
	case NGM_DDOS_IP_MAC_ADD:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t ip = in[0];
		uint8_t *mac = (uint8_t *)(in+1);
		add_ip_mac_node(ip, mac);

		break;
	}
	case NGM_DDOS_IP_MAC_UPDATE:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t ip = in[0];
		uint8_t *mac = (uint8_t *)(in+1);
		update_ip_mac_node(ip, mac);
		break;
	}
	case NGM_DDOS_IP_MAC_DELETE:
	{
		uint32_t *in = (uint32_t *)msg->data;
		uint32_t ip = in[0];
		delete_ip_mac_node(ip);

		break;
	}
	case NGM_DDOS_SHOW_IP_MAC:
	{
		show_ip_mac_node();
		uint32_t i = 0, n=0;
		struct ip_mac_node *tmpnode = NULL;
		char ip[16] = {0};
		char *result=NULL;

		NG_MKRESPONSE(resp, msg, IP_MAC_RESULT + 1, M_NOWAIT);
		if (resp == NULL) {
			error = ENOMEM;
			break;
		}
		result = resp->data;

		for(i = 0; i < IP_MAC_TABLE; i++)
		{
			tmpnode = ip_mac_table[i].next;
			while(tmpnode)
			{
				bzero(ip, sizeof(ip));
				IP_2_STR(tmpnode->ip_mac.ip, ip, sizeof(ip));
				n+=snprintf(result+n, IP_MAC_RESULT - n,"%s %x:%x:%x:%x:%x:%x %d |", ip, tmpnode->ip_mac.mac[0],tmpnode->ip_mac.mac[1],tmpnode->ip_mac.mac[2],
					tmpnode->ip_mac.mac[3],tmpnode->ip_mac.mac[4],tmpnode->ip_mac.mac[5],tmpnode->ip_mac.is_config);

				tmpnode = tmpnode->next;
				if(n >= (IP_MAC_RESULT - 1))
				{
		                		printf("****ip_mac_table[%d] Error: %s %d****\n", i, __FILE__, __LINE__);
		                		break;
		             	}
			}
		}
		break;
	}
	case NGM_DDOS_SERVER_FLOW_ADD:
	{
		break;
	}
	case NGM_DDOS_SERVER_FLOW_DELETE:
	{
		break;
	}
	case NGM_DDOS_SHOW_SERVER_FLOW:
	{
		break;
	}
#endif
#if defined(__LinuxKernelVNB__)

#endif
		default:
			error = EINVAL;
			break;
		}
		break;
	}
	default:
		error = EINVAL;
		break;
	}
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);

	return (error);
}

#if defined(__FastPath__)
static int ng_ddos_rcvdata(hook_p hook, struct mbuf *m, meta_p meta) {
#elif defined(__LinuxKernelVNB__)
static int ng_ddos_rcvdata(hook_p hook, struct sk_buff *m, meta_p meta) {
#endif

const node_p node = NG_HOOK_NODE(hook);
priv_p priv = NULL;
uint32_t linkNum = 0;

struct vlan_header *vhdr = NULL;
uint32_t adj_len = 0;
uint16_t ether_type = 0;

#if defined(__LinuxKernelVNB__)

struct iphdr *ip = NULL;

struct nf_conn *ct = NULL;
enum ip_conntrack_info ctinfo;
struct nf_conn_counter *acct = NULL;

#elif defined(__FastPath__)

uint8_t  deal_result = 0;

#endif

if (!node) {
	NG_FREE_DATA(m, meta);
	return (ENOTCONN);
}

priv = NG_NODE_PRIVATE(node);
if (!priv) {
	NG_FREE_DATA(m, meta);
	return (ENOTCONN);
}

/* Get link number */
linkNum = LINK_NUM_DDOS(hook);
if (unlikely(linkNum >= NG_DDOS_MAX_LINKS || hook != priv->phy_hooks[linkNum]))
{
	NG_FREE_DATA(m, meta);
	return (ENOTCONN);
}

#if defined(__FastPath__)

if (unlikely(m_len(m) <= (FP_ETHER_HDR_LEN + NG_VLAN_ENCAPLEN)))
{
	NG_FREE_DATA(m, meta);
	return (ENOTCONN);
}

vhdr = mtod(m, struct vlan_header *);
if(unlikely(vhdr == NULL))
{
	NG_FREE_DATA(m, meta);
	return (ENOTCONN);
}

/* vhdr->encap_proto is safe because inside ethernet header */
if (likely(vhdr->encap_proto != htons(FP_ETHERTYPE_VLAN)))
{
	ether_type = vhdr->encap_proto;
	adj_len = FP_ETHER_HDR_LEN;
}
else
{
	ether_type = vhdr->proto;
	adj_len = (FP_ETHER_HDR_LEN + NG_VLAN_ENCAPLEN);
}
if (unlikely(ether_type == htons(FP_ETHERTYPE_ARP))){
	fp_ifnet_t *ifp = __fp_ifuid2ifnet(m_priv(m)->ifuid);
	if (unlikely(FP_DONE != fp_arp_input(m, ifp))) {
		NG_FREE_DATA(m, meta);
	}

	return (ENOTCONN);
}
else if (likely(ether_type == htons(FP_ETHERTYPE_IP)))
{

	deal_result = server_flow_deal(m, adj_len, linkNum);

	if(deal_result == SEND_TO_OUT)
	{
		if(fp_shared->stream_return == NGM_DDOS_PBR_RETURN){
			REVERSE_ETH(((struct fp_ether_header *) vhdr));
			return ng_send_data_fast(priv->phy_hooks[linkNum], m, meta);
		}

		if(fp_shared->stream_return == NGM_DDOS_MAC_RETURN){
			if(stream_return_mac(m,adj_len)==0){
				NG_FREE_DATA(m, meta);
				return (ENOTCONN);
			}

			return ng_send_data_fast(priv->phy_hooks[linkNum], m, meta);
		}

	}
	else if(deal_result == SEND_BACK)
	{
		return ng_send_data_fast(priv->phy_hooks[linkNum], m, meta);
	}
	else if(deal_result == SEND_TO_KERNEL)
	{
		return send_pkt_to_kernel(m, meta);
	}
	else
	{
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
}
else
{
	return ng_send_data_fast(priv->phy_hooks[linkNum], m, meta);
}

#endif

NG_FREE_DATA(m, meta);
return (ENOTCONN);

}

/*
 * Shutdown processing
 */
static int ng_ddos_shutdown(node_p node) {
const priv_p priv = NG_NODE_PRIVATE(node);
(void) priv;

ng_cutlinks(node);
ng_unname(node);
NG_NODE_SET_PRIVATE(node, NULL);
NG_NODE_UNREF(node);
return 0;
}

/*
 * Hook disconnection
 * If all the hooks are removed, let's free itself.
 */
static int ng_ddos_disconnect(hook_p hook) {
const node_p node = NG_HOOK_NODE(hook);
const priv_p priv = NG_NODE_PRIVATE(node);
uint32_t linkNum;
/* Get link number */
linkNum = LINK_NUM_DDOS(hook);

/* Nuke the link */
if (hook == priv->phy_hooks[linkNum])
	priv->phy_hooks[linkNum] = NULL;
/* If no hooks left, go away */
if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
		&& (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {

	ng_free(priv->phy_hooks);
	ng_rmnode(NG_HOOK_NODE(hook));
}
return 0;
}

#if defined(__LinuxKernelVNB__)
module_init(ng_ddos_init);
module_exit(ng_ddos_exit);
MODULE_LICENSE("GPL");
#endif
