/*
 * Copyright(c) 2008 6WIND
 */
#ifndef __NETFPC_H__
#define __NETFPC_H__

#include "netfpc_var.h"
#include "net/fp-ethernet.h"
#include "netinet/fp-ip6.h"

/* save these headers to be able to answer to the message */
struct fp_netfpc_ctx {
	struct fp_ether_header eh;
	struct fp_ip6_hdr ip6;
	uint16_t netfpc_type;
	uint8_t input_port;
};

typedef int (*fp_netfpc_hdlr_fn)(struct mbuf *m, struct fp_netfpc_ctx *ctx);

typedef struct fp_netfpc_hook {
	FPN_SLIST_ENTRY(fp_netfpc_hook) next;
	fp_netfpc_hdlr_fn func;
} fp_netfpc_hook_t;

/* Register a handler function for a specific netfpc msg type
   Any previously registered handler is overriden by the new one.
 */
extern int fp_netfpc_register(uint16_t type, fp_netfpc_hdlr_fn cb);

/* Standard netfpc notification handler.
   Dispatches the msg to the registered hooks, then frees the message.
 */
extern int fp_netfpc_notif_handler(struct mbuf *m, struct fp_netfpc_ctx *ctx);

/* Standard command handler.
   Dispatch the msg to the registered hooks, then sends the message ack.
 */
extern int fp_netfpc_cmd_handler(struct mbuf *m, struct fp_netfpc_ctx *ctx);

/* Add hook to be called from a generic netfpc reception function.
   This is for being notified of the reception of a netfpc msg.
*/
extern int fp_netfpc_add_hook(uint16_t type, fp_netfpc_hook_t *hook);

/* NETFPC message is raw IPv6, IPPROTO_NETFPC and
 * minimal size is NETFPC_HDRSIZE
 */
extern int fp_packet_isnetfpc(struct mbuf *m);
extern void fp_netfpc_input(struct mbuf *m, struct fp_ether_header *eh);
extern void fp_netfpc_input_unknown(struct mbuf *m, struct fp_netfpc_ctx *ctx, uint16_t len);
extern void fp_netfpc_output(struct mbuf *m, struct fp_netfpc_ctx *ctx);

#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
extern void fp_eqos_config(struct mbuf *m, struct fp_netfpc_ctx *ctx);
#endif

#endif
