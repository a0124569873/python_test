/*
 * Copyright(c) 2009 6WIND
 */
#ifndef __FPN_IPSEC6_INPUT_H__
#define __FPN_IPSEC6_INPUT_H__

/* ipsec6_input, ah6_input, esp6_input:
 * return FP_NONE: unable to apply IPsec, tell slow path
 * return FP_DROP: error during IPsec processing
 * return FP_DONE: packet has been decrypted, forwarded and freed,
 go ahead with next packet
 * return FP_KEEP: packet is kept for async treatment.
 */
int ipsec6_input(struct mbuf *m, struct fp_ip6_hdr *ip6);
int ipsec6_input_finish(struct mbuf *m, fp_v6_sa_entry_t *sa);

#ifdef CONFIG_MCORE_IPSEC_IPV6_VERIFY_INBOUND
int ipsec6_check_policy(struct mbuf *m, struct fp_ip6_hdr *ip6);
#endif

int fp_ipsec6_input_init(void);

#endif /* __FPN_IPSEC6_INPUT_H__ */
