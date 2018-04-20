/*
 * Copyright(c) 2008 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"
#include "fp-log.h"
#include "fp-netfpc.h"

#ifdef CONFIG_MCORE_IPSEC
#include "fp-ipsec-common.h"
#include "fp-ipsec-input.h"
#include "fp-ipsec-replay.h"
#endif

#ifdef CONFIG_MCORE_EMBEDDED_FPDEBUG
#include "fpdebug.h"
#endif

#ifdef CONFIG_MCORE_FPU_RPC
#include "fpu-rpc.h"
#endif

#define TRACE_NETFPC(level, fmt, args...) do {			\
		FP_LOG(level, NETFPC, fmt "\n", ## args);	\
} while(0)

#define NETFPC_MSGTYPE_MAX 512

static FPN_DEFINE_SHARED(fp_netfpc_hdlr_fn, fp_netfpc_hdlr[NETFPC_MSGTYPE_MAX]);

FPN_SLIST_HEAD(fp_netfpc_hook_lst, fp_netfpc_hook);

static FPN_DEFINE_SHARED(struct fp_netfpc_hook_lst,
                         fp_netfpc_hooks[NETFPC_MSGTYPE_MAX]);

int fp_netfpc_register(uint16_t type, fp_netfpc_hdlr_fn cb)
{
	if (type >= NETFPC_MSGTYPE_MAX) {
		TRACE_NETFPC(FP_LOG_ERR, "cannot register netfpc msg 0x%04X:"
		             " max is 0x%04X\n", type, NETFPC_MSGTYPE_MAX - 1);
		return -1;
	}

	if (fp_netfpc_hdlr[type] != NULL)
		TRACE_NETFPC(FP_LOG_WARNING,
		             "overriding netfpc msg type %04X\n", type);

	fp_netfpc_hdlr[type] = cb;

	return 0;
}

static inline fp_netfpc_hdlr_fn fp_netfpc_find_handler(uint16_t type)
{
	return(type < NETFPC_MSGTYPE_MAX ? fp_netfpc_hdlr[type] : NULL);
}

int fp_netfpc_add_hook(uint16_t type, fp_netfpc_hook_t *hook)
{
	if (!hook || !hook->func || type >= NETFPC_MSGTYPE_MAX) {
		fpn_printf("cannot add hook for netfpc msg 0x%04X:"
		           " invalid argument\n", type);
		return -1;
	}
	FPN_SLIST_INSERT_HEAD(&fp_netfpc_hooks[type], hook, next);
	return 0;
}

int fp_netfpc_notif_handler(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	fp_netfpc_hook_t *hook;

	FPN_SLIST_FOREACH (hook, &fp_netfpc_hooks[ctx->netfpc_type], next) {
		hook->func(m, ctx);
	}

	/* this is a notification without ack: just free the msg */
	m_freem(m);

	return 0;
}

int fp_netfpc_cmd_handler(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_if_msg *if_msg;
	fp_netfpc_hook_t *hook;

	if_msg = mtod(m, struct netfpc_if_msg *);
	if_msg->error = 0;

	FPN_SLIST_FOREACH (hook, &fp_netfpc_hooks[ctx->netfpc_type], next) {
		hook->func(m, ctx);
	}

	/* reuse the input mbuf to send the ack with
	 * the error code, m will be freed */
	fp_netfpc_output(m, ctx);

	return 0;
}

/* NETFPC message is raw IPv6, IPPROTO_NETFPC and
 * minimal size is NETFPC_HDRSIZE
 */
int fp_packet_isnetfpc(struct mbuf *m)
{
	struct fp_ip6_hdr *ip6 = mtod(m, struct fp_ip6_hdr *);

	if ((ip6->ip6_vfc & 0xF0) != 0x60)
		return 0;

	if (ip6->ip6_nxt != IPPROTO_NETFPC)
		return 0;

	if (ntohs(ip6->ip6_plen) < NETFPC_HDRSIZE)
		return 0;

	return 1;
}

void fp_netfpc_output(struct mbuf *m, struct fp_netfpc_ctx *ctx)
{
	struct netfpc_hdr *nfh;
	struct fp_ip6_hdr *ip6;
	struct fp_ether_header *eh;

	/* prepend netfpc headers */
	nfh = (struct netfpc_hdr *)m_prepend(m, sizeof(struct netfpc_hdr));
	if (!nfh)
		goto fail;
	nfh->type = htons(ctx->netfpc_type);
	nfh->len = htons(m_len(m) - sizeof(struct netfpc_hdr));

	/* prepend ipv6 headers, reverse addresses */
	ip6 = (struct fp_ip6_hdr *) m_prepend(m, sizeof(struct fp_ip6_hdr));
	if (!ip6)
		goto fail;
	memcpy(ip6, &ctx->ip6, sizeof(struct fp_ip6_hdr));
	memcpy(&ip6->ip6_src, &ctx->ip6.ip6_dst, sizeof(ctx->ip6.ip6_dst));
	memcpy(&ip6->ip6_dst, &ctx->ip6.ip6_src, sizeof(ctx->ip6.ip6_src));
	ip6->ip6_plen = htons(m_len(m) - sizeof(struct fp_ip6_hdr));

	/* prepend ether headers */
	eh = (struct fp_ether_header *) m_prepend(m, sizeof(struct fp_ether_header));
	if (!eh)
		goto fail;
	memcpy(eh->ether_dhost, ctx->eh.ether_shost, FP_ETHER_ADDR_LEN);
	memcpy(eh->ether_shost, ctx->eh.ether_dhost, FP_ETHER_ADDR_LEN);
	eh->ether_type = ctx->eh.ether_type;

	/* send packet as exception */
	fpn_send_exception(m, ctx->input_port);
	FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalBasicExceptions);
	return;
 fail:
	m_freem(m);
}

/* m is raw v6, eh is original ethernet header which is needed to
 * generate the answer. */
void fp_netfpc_input(struct mbuf *m, struct fp_ether_header *eh)
{
	struct netfpc_hdr *nfh;
	struct fp_ip6_hdr *ip6;
	struct fp_netfpc_ctx ctx;
	uint16_t netfpc_len;

	TRACE_NETFPC(FP_LOG_DEBUG, "netfpc intput");

	/* Reset mbuf tags */
	m_tag_reset(m);
	ctx.input_port = m_input_port(m);

	/* Save ethernet header in netfpc context */
	memcpy(&ctx.eh, eh, sizeof(*eh));

	if (m_len(m) < sizeof(struct fp_ip6_hdr) + sizeof(struct netfpc_hdr)) {
		TRACE_NETFPC(FP_LOG_ERR, "header too short");
		m_freem(m);
		return;
	}

	/* Save and remove IPv6 header. */
	ip6 = mtod(m, struct fp_ip6_hdr *);
	memcpy(&ctx.ip6, ip6, sizeof(struct fp_ip6_hdr));
	m_adj(m, sizeof(struct fp_ip6_hdr));
	nfh = mtod(m, struct netfpc_hdr *);
	ctx.netfpc_type = ntohs(nfh->type);
	netfpc_len = ntohs(nfh->len);

	TRACE_NETFPC(FP_LOG_DEBUG, "netfpc type %d", ctx.netfpc_type);
	if (m_len(m) < netfpc_len + sizeof(struct netfpc_hdr)) {
		TRACE_NETFPC(FP_LOG_ERR, "message too short");
		m_freem(m);
		return;
	}

	/* Remove NETFPC header. */
	m_adj(m, sizeof(struct netfpc_hdr));

	switch(ctx.netfpc_type) {
	case NETFPC_MSGTYPE_GR_START:
		fp_netfpc_notif_handler(m, &ctx);
		return;

	case NETFPC_MSGTYPE_NEWIF:
	case NETFPC_MSGTYPE_DELIF:
		fp_netfpc_cmd_handler(m, &ctx);
		return;

#ifdef CONFIG_MCORE_IPSEC
	case NETFPC_MSGTYPE_REPLAYWIN:
#ifdef CONFIG_MCORE_MULTIBLADE
		/* send replaywin get msg to other blades */
		TRACE_NETFPC(FP_LOG_NOTICE, "netfpc replay win ipv4");
		ipsec_replaywin_get_send(m);
		return;
#endif
		break;
#endif /* CONFIG_MCORE_IPSEC */
#ifdef CONFIG_MCORE_IPSEC_IPV6
	case NETFPC_MSGTYPE_REPLAYWIN6:
#ifdef CONFIG_MCORE_MULTIBLADE
		/* send replaywin get msg to other blades */
		TRACE_NETFPC(FP_LOG_NOTICE, "netfpc replay win ipv6");
		ipsec6_replaywin_get_send(m);
		return;
#endif
		break;
#endif /* CONFIG_MCORE_IPSEC_IPV6 */

	case NETFPC_MSGTYPE_EQOS:
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		fp_eqos_config(m, &ctx);
		return;
#endif
		break;

	case NETFPC_MSGTYPE_FPDEBUG:
	{
		struct netfpc_ack_msg *msg;
		int32_t ret;
		struct mbuf *m2;

#ifdef CONFIG_MCORE_EMBEDDED_FPDEBUG
		char *cmd;

		if (!m_is_contiguous(m)) {
			TRACE_NETFPC(FP_LOG_ERR, "Fragmented message\n");
			break;
		}
		cmd = mtod(m, char *);
		if (cmd[netfpc_len-1] != '\0') {
			TRACE_NETFPC(FP_LOG_ERR, "Message not 0-terminated\n");
			break;
		}
		ret = fpdebug_run_command(cmd);
#else
		TRACE_NETFPC(FP_LOG_ERR, "No embedded fpdebug\n");
		ret = -1; /* no fpdebug in FP, return an error via netfpc */
#endif
		m2 = m_alloc();
		if (m2 == NULL) {
			TRACE_NETFPC(FP_LOG_ERR, "Cannot alloc packet\n");
			break;
		}
		m_freem(m);

		msg = (struct netfpc_ack_msg *)m_append(m2, sizeof(*msg));
		if (msg == NULL) {
			m_freem(m2);
			TRACE_NETFPC(FP_LOG_ERR, "Cannot add data in m2\n");
			return;
		}

		msg->error = htonl(ret);
		fp_netfpc_output(m2, &ctx);
		return;
	}

	case NETFPC_MSGTYPE_SET_MTU:
	{
		struct netfpc_mtu_msg *mtu_msg = mtod(m, struct netfpc_mtu_msg *);
		fp_ifnet_t *ifp;

		ifp = fp_ifuid2ifnet(mtu_msg->ifuid);
		if (ifp == NULL) {
			TRACE_NETFPC(FP_LOG_ERR, "bad ifuid\n");
			return;
		}
		TRACE_NETFPC(FP_LOG_INFO, "changing mtu on port %s => %u - %x\n",
		             ifp->if_name, ntohl(mtu_msg->mtu), ntohl(mtu_msg->mtu));
		mtu_msg->error = htonl(fp_interface_set_mtu(ifp, (ntohl(mtu_msg->mtu) & 0xFFFF) ));
		fp_netfpc_output(m, &ctx);
		return;
	}

	case NETFPC_MSGTYPE_SET_MAC:
	{
		struct netfpc_mac_msg *mac_msg = mtod(m, struct netfpc_mac_msg *);
		fp_ifnet_t *ifp;

		ifp = fp_ifuid2ifnet(mac_msg->ifuid);
		if (ifp == NULL) {
			TRACE_NETFPC(FP_LOG_ERR, "bad ifuid\n");
			return;
		}
		TRACE_NETFPC(FP_LOG_INFO, "changing mac on port %s\n", ifp->if_name);
		mac_msg->error = htonl(fp_interface_set_mac(ifp, mac_msg->mac));
		fp_netfpc_output(m, &ctx);
		return;
	}

	case NETFPC_MSGTYPE_SET_FLAGS:
	{
		struct netfpc_flags_msg *flags_msg = mtod(m, struct netfpc_flags_msg *);
		fp_ifnet_t *ifp;
		uint32_t flags;

		ifp = fp_ifuid2ifnet(flags_msg->ifuid);
		if (ifp == NULL) {
			TRACE_NETFPC(FP_LOG_ERR, "bad ifuid\n");
			return;
		}
		TRACE_NETFPC(FP_LOG_INFO, "changing flags on port %s\n", ifp->if_name);
		flags = ntohl(flags_msg->flags);
		flags_msg->error = htonl(fp_interface_set_flags(ifp, flags));
		fp_netfpc_output(m, &ctx);
		return;
	}

	case NETFPC_MSGTYPE_RPC_CLIENT:
	{
#ifdef CONFIG_MCORE_FPU_RPC
		struct netfpc_rpc_msg *rpc_msg = mtod(m, struct netfpc_rpc_msg *);

		TRACE_NETFPC(FP_LOG_INFO, "got %s rpc client, shmem %s\n",
			     (rpc_msg->cmd == NETFPC_RPC_ADD_CLIENT) ? "add" : "del",
			     rpc_msg->shmem_name);
		if (rpc_msg->cmd == NETFPC_RPC_ADD_CLIENT)
			fpu_rpc_client_add(rpc_msg->shmem_name);
		else
			fpu_rpc_client_del(rpc_msg->shmem_name);
#endif
		break;
	}

	default:
	{
		fp_netfpc_hdlr_fn handler;

		if ((handler = fp_netfpc_find_handler(ctx.netfpc_type))!= NULL) {
			handler(m, &ctx);
			return;
		}

		fp_netfpc_input_unknown(m, &ctx, netfpc_len);
		break;
	}
	}
	m_freem(m);
}

void fp_netfpc_input_unknown(struct mbuf *m __fpn_maybe_unused, struct fp_netfpc_ctx *ctx, uint16_t len __fpn_maybe_unused)
{
	TRACE_NETFPC(FP_LOG_NOTICE, "Ignore message type %d", ctx->netfpc_type);
}
