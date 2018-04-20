/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FPN_IPSEC_INPUT_H__
#define __FPN_IPSEC_INPUT_H__

/* ipsec4_input, ah4_input, esp4_input:
 * return FP_NONE: unable to apply IPsec, tell slow path
 * return FP_DROP: error during IPsec processing
 * return FP_DONE: packet has been decrypted, forwarded and freed,
 go ahead with next packet
 * return FP_KEEP: packet is kept for async treatment.
 */
int ipsec4_input(struct mbuf *m, struct fp_ip *ip);
int ipsec4_input_traversal(struct mbuf *m, struct fp_ip *ip);
int ipsec4_input_finish(struct mbuf *m, fp_sa_entry_t *sa);

typedef int (*input_finish_func)(struct mbuf *, fp_sa_entry_t *);

#ifdef CONFIG_MCORE_IPSEC_VERIFY_INBOUND
int ipsec_check_policy(struct mbuf *m, struct fp_ip *ip);
#endif

int fp_ipsec_input_init(void);

#endif /* __FPN_IPSEC_INPUT_H__ */
