/*
 * Copyright 2013 6WIND S.A.
 */
#ifndef _SDSIFD_PKT_H_
#define _SDSIFD_PKT_H_

#define SDSIFD_PROTOCOL_VERSION 1

/* FP => CP messages */
/*
 * SDSIFD_FP_PEER_MSG is sent by the fast path when a new peer is
 * discovered (first message sent)
 */
#define SDSIFD_FP_PEER_MSG           1
/*
 * SDSIFD_FP_IF_MSG is sent to tell the control plane about a fast
 * path interface, or if the running flag changes on the fast path
 * interface 
 */
#define SDSIFD_FP_IF_MSG             2

struct sdsifd_fp_if_msg {
	char     name[IFNAMSIZ];        /* name, used for lookups */
	uint16_t version;               /* protocol version used */
	uint8_t  mac[6];                /* mac, checked only at creation */
	uint32_t mtu;                   /* mtu, checked only at creation */
	uint8_t  running;               /* is the interface running */
	uint8_t  fpib;                  /* is the interface a fpib */
} __attribute__((packed));

/* CP => FP messages */
/*
 * SDSIFD_CP_PEER_MSG is sent by the control plane when a
 * SDSIFD_FP_PEER_MSG message is received
 */
#define SDSIFD_CP_PEER_MSG           3
/*
 * SDSIFD_CP_IF_MSG is sent to tell fast path about up/down status of
 * one of its interface
 */
#define SDSIFD_CP_IF_MSG             4 

struct sdsifd_cp_if_msg {
	char     name[IFNAMSIZ];        /* name, used for lookups */
	uint16_t version;               /* protocol version used */
	uint8_t  up;                    /* is the interface up or down */
} __attribute__((packed));

/* sends a message to a peer, given its stream */
int sdsifd_send_message(uint8_t command, void *data, uint32_t data_len,
			struct stream *stream, int peer_id);
/* fills buf with a format output of the message stored in data */
void sdsifd_pkt_log_msg(uint8_t command, void *data, char *buf, size_t buflen);

#endif /* _SDSIFD_PKT_H_ */
