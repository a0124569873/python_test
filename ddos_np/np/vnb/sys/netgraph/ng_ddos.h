#ifndef NG_DDOS_H_
#define NG_DDOS_H_

//both head files
#include <netgraph/vnb_ether.h>
#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_udp.h>
#include <netgraph/vnb_tcp.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

/* Node type name and magic cookie */
#define NG_DDOS_NODE_TYPE    "ddos"
#define NGM_DDOS_COOKIE      946766834

#define NG_DDOS_HOOK_ETH_PREFIX	"eth"	 /* append decimal integer */

/* Maximum number of supported "linkrecv" links */
#define NG_DDOS_MAX_LINKS		256

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_DDOS, "ng_ddos","netgraph ddos");
#else
#define M_NETGRAPH_DDOS M_NETGRAPH
#endif

#if defined(__FastPath__)

#if 0
//server info 
static const struct ng_parse_struct_field ng_ddos_server_fields[] = 
{
	{	"ip", &ng_parse_ipaddr_type, 0},
	{	"port", &ng_parse_uint32_type, 0},
	{	"syn", &ng_parse_uint32_type, 0},
	{	"udp", &ng_parse_uint32_type, 0},
	{	NULL, NULL, 0}
};
static const struct ng_parse_type ng_ddos_server_type = 
{
	.supertype = &ng_parse_struct_type,
	.info = &ng_ddos_server_fields
};
#endif


//black white list
static const struct ng_parse_struct_field ng_ddos_black_white_fields[] = 
{
	{	"srcip", &ng_parse_ipaddr_type, 0},
	{	"dstip", &ng_parse_ipaddr_type, 0},
	{	"dport", &ng_parse_uint32_type, 0},
	{	"type", &ng_parse_uint32_type, 0},
	{	NULL, NULL, 0}
};
static const struct ng_parse_type ng_ddos_black_white_type = 
{
	.supertype = &ng_parse_struct_type,
	.info = &ng_ddos_black_white_fields
};
static const struct ng_parse_fixedarray_info ng_ddos_macaddr_info = {
	&ng_parse_uint8_type,
	6,
	NULL
};
static const struct ng_parse_type ng_ddos_macaddr_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info = &ng_ddos_macaddr_info
};
static const struct ng_parse_struct_field ng_ddos_ip_mac_fields[] = {
	{	"ip", &ng_parse_ipaddr_type, 0},
	{	"mac", &ng_ddos_macaddr_type, 0},
	{	NULL, NULL, 0}
};
static const struct ng_parse_type ng_ddos_ip_mac_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ddos_ip_mac_fields
};
static const struct ng_parse_struct_field ng_ddos_ip_fields[] = {
	{	"ip", &ng_parse_ipaddr_type, 0},
	{	NULL, NULL, 0}
};
static const struct ng_parse_type ng_ddos_ip_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_ddos_ip_fields
};

static const struct ng_parse_type ng_ddos_server_flow_type = 
{
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_ipaddr_type
};


static const struct ng_parse_struct_field ng_ddos_host_fields[] = 
{
	{	"flow_in", &ng_parse_uint32_type, 0},
	{	"pkt_in", &ng_parse_uint32_type, 0},
	{	"flow_out", &ng_parse_uint32_type, 0},
	{	"pkt_out", &ng_parse_uint32_type, 0},
	{	"flow_pol", &ng_parse_uint32_type, 0},
	{	NULL, NULL, 0}
};

static const struct ng_parse_struct_field ng_ddos_host_para_fields[] = 
{
	{	"syn", &ng_parse_uint32_type, 0},
	{	"syn_ss", &ng_parse_uint32_type, 0},
	{	"ack_rst", &ng_parse_uint32_type, 0},
	{	"udp", &ng_parse_uint32_type, 0},
	{	"icmp", &ng_parse_uint32_type, 0},
	{	"tcp_con_in", &ng_parse_uint32_type, 0},
	{	"tcp_con_out", &ng_parse_uint32_type, 0},
	{	"tcp_con_ip", &ng_parse_uint32_type, 0},
	{	"tcp_fre", &ng_parse_uint32_type, 0},
	{	"tcp_idle", &ng_parse_uint32_type, 0},
	{	"udp_con", &ng_parse_uint32_type, 0},
	{	"udp_fre", &ng_parse_uint32_type, 0},
	{	"icmp_fre", &ng_parse_uint32_type, 0},
	{	NULL, NULL, 0}
};

static const struct ng_parse_struct_field ng_ddos_tcp_port_protect_fields[] = 
{
	{	"str", &ng_parse_uint32_type, 0},
	{	"end", &ng_parse_uint32_type, 0},
	{	"on_off", &ng_parse_uint32_type, 0},
	{	"atk_fre", &ng_parse_uint32_type, 0},
	{	"con_lmt", &ng_parse_uint32_type, 0},
	{	"pro_mod", &ng_parse_uint32_type, 0},
	{	NULL, NULL, 0}
};

static const struct ng_parse_struct_field ng_ddos_udp_port_protect_fields[] = 
{
	{	"str", &ng_parse_uint32_type, 0},
	{	"end", &ng_parse_uint32_type, 0},
	{	"on_off", &ng_parse_uint32_type, 0},
	{	"atk_fre", &ng_parse_uint32_type, 0},
	{	"pkt_fre", &ng_parse_uint32_type, 0},
	{	"pro_mod", &ng_parse_uint32_type, 0},
	{	NULL, NULL, 0}
};

static const struct ng_parse_type ng_parse_tcp_prot_fileds = {
		.supertype = &ng_parse_struct_type,
		.info = &(ng_ddos_tcp_port_protect_fields),
};
static const struct ng_parse_fixedarray_info ng_ddos_tcp_prot_info = {
	&ng_parse_tcp_prot_fileds,
	16,
	NULL
};
static const struct ng_parse_type ng_ddos_tcp_prot_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info = &ng_ddos_tcp_prot_info
};

static const struct ng_parse_type ng_ddos_tcp_port_prot_type = {
	.supertype = &ng_parse_struct_type,
	.info = &(const struct ng_parse_struct_field []){
		{
			.name = "port_num",
			.type = &ng_parse_uint32_type,
		},			
		{
			.name = "tcp_port_set",
			.type = &ng_ddos_tcp_prot_type,
			.alignment = 0,
		},
		{
			.name = NULL,
		},
	},
	.private = 0,
};

static const struct ng_parse_type ng_parse_udp_prot_fileds = {
		.supertype = &ng_parse_struct_type,
		.info = &(ng_ddos_udp_port_protect_fields),
};
static const struct ng_parse_fixedarray_info ng_ddos_udp_prot_info = {
	&ng_parse_udp_prot_fileds,
	16,
	NULL
};
static const struct ng_parse_type ng_ddos_udp_prot_type = {
	.supertype = &ng_parse_fixedarray_type,
	.info = &ng_ddos_udp_prot_info
};

static const struct ng_parse_type ng_ddos_udp_port_prot_type = {
	.supertype = &ng_parse_struct_type,
	.info = &(const struct ng_parse_struct_field []){
		{
			.name = "port_num",
			.type = &ng_parse_uint32_type,
		},			
		{
			.name = "udp_port_set",
			.type = &ng_ddos_udp_prot_type,
			.alignment = 0,
		},
		{
			.name = NULL,
		},
	},
	.private = 0,
};

static const struct ng_parse_type ng_ddos_server_type = {
	.supertype = &ng_parse_struct_type,
	.info = &(const struct ng_parse_struct_field []){
		{
			.name = "ip",
			.type = &ng_parse_ipaddr_type,
		},
		{
			.name = "mask",
			.type = &ng_parse_uint32_type,
		},
		{
			.name = "host",
			.type = &(const struct ng_parse_type){
				.supertype = &ng_parse_struct_type,
				.info = &(ng_ddos_host_fields),
				.private = 0,
			},
			.alignment = 0,

		},
		{
			.name = "host_para",
			.type = &(const struct ng_parse_type){
				.supertype = &ng_parse_struct_type,
				.info = &(ng_ddos_host_para_fields),
				.private = 0,
			},
			.alignment = 0,
		},
		{
			.name = "tcp_port_prot",
			.type = &ng_ddos_tcp_port_prot_type,
			.alignment = 0,
		},
		{
			.name = "udp_port_prot",
			.type = &ng_ddos_udp_port_prot_type,
			.alignment = 0,
		},
		{
			.name = NULL,
		},
	},
	.private = 0,
};


/* Netgraph commands */
enum {
	NGM_DDOS_SERVER_INFO = 1,						/* get the host port stats of mimic */
	NGM_DDOS_GET_SYS_TIME,
	NGM_DDOS_SERVER_EMPTY,
	NGM_DDOS_SERVER_CONFIG,
	NGM_DDOS_SERVER_ADD,
	NGM_DDOS_SERVER_UPDATE,
	NGM_DDOS_SERVER_DELETE,
	NGM_DDOS_SHOW_SERVER,
	NGM_DDOS_SHOW_SERVER_CONFIG,
	NGM_DDOS_BLACK_WHITE_EMPTY,
	NGM_DDOS_BLACK_WHITE_CONFIG,
	NGM_DDOS_BLACK_WHITE_ADD,
	NGM_DDOS_BLACK_WHITE_DELETE,
	NGM_DDOS_SHOW_BLACK_WHITE,
	NGM_DDOS_TEMP_BLACK_WHITE_STATUS,
	NGM_DDOS_TEMP_BLACK_WHITE_DELETE,
	NGM_DDOS_IP_MAC_EMPTY,
	NGM_DDOS_IP_MAC_ADD,
	NGM_DDOS_IP_MAC_UPDATE,
	NGM_DDOS_IP_MAC_DELETE,
	NGM_DDOS_SHOW_IP_MAC,
	NGM_DDOS_SERVER_FLOW_ADD,
	NGM_DDOS_SERVER_FLOW_DELETE,
	NGM_DDOS_SHOW_SERVER_FLOW,
};
enum{
	NGM_DDOS_MAC_RETURN=1,			
	NGM_DDOS_MPLS_RETURN,
	NGM_DDOS_PBR_RETURN,		//policy-base routing
};

#endif

/* Per-node private data */
struct ng_ddos_private {
	node_p ddos_node; /* back pointer to node */
	hook_p *phy_hooks;
};
typedef struct ng_ddos_private *priv_p;

extern int ng_ddos_init(void);
extern int fp_ddos_init(void);
#endif /* NG_DDOS_H_ */
