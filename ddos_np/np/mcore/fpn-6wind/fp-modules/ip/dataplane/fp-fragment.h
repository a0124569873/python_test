/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FP_FRAGMENT_H__
#define __FP_FRAGMENT_H__

int fp_ip_fragment(struct mbuf *m, uint64_t mtu,
		   int (*process_fragment)(struct mbuf *m, void *p1, void *p2),
		   void *p1, void *p2);
int fp_ip_send_fragment(struct mbuf *m, void *p1, void *p2);

#ifdef CONFIG_MCORE_IPV6
int fp_ip6_fragment(struct mbuf *m, uint64_t mtu,
		    int (*process_fragment)(struct mbuf *m, void *p1, void *p2),
		    void *p1, void *p2);
int fp_ip6_send_fragment(struct mbuf *m, void *p1, void *p2);
#endif  /* CONFIG_MCORE_IPV6 */

#endif /* __FP_FRAGMENT_H__ */
