/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FPN_IPSEC_OUTPUT_H__
#define __FPN_IPSEC_OUTPUT_H__

void fp_ipsec_output_init(void);

int fp_ipsec_output(struct mbuf *m);
int ipsec4_output(struct mbuf *m, fp_sa_entry_t *sa, fp_sp_entry_t *sp);

#ifdef CONFIG_MCORE_IPSEC_SVTI
int fp_svti_output(struct mbuf *m, fp_ifnet_t *ifp);
#endif

typedef int (*output_func)(struct mbuf *, fp_sa_entry_t *, fp_sp_entry_t *);

#endif /* __FPN_IPSEC_OUTPUT_H__ */
