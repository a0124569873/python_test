/*
 * Copyright(c) 2009 6WIND
 */
#ifndef __FPN_IPSEC6_OUTPUT_H__
#define __FPN_IPSEC6_OUTPUT_H__

void fp_ipsec6_output_init(void);

int fp_ipsec6_output(struct mbuf *m);
int ipsec6_output(struct mbuf *m, fp_v6_sa_entry_t *sa, fp_v6_sp_entry_t *sp);

#ifdef CONFIG_MCORE_IPSEC_SVTI
int fp_svti6_output(struct mbuf *m, fp_ifnet_t *ifp);
#endif

#endif /* __FPN_IPSEC6_OUTPUT_H__ */
