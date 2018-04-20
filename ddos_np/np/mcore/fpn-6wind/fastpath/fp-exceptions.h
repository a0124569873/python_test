/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FPN_EXCEPTIONS_H__
#define __FPN_EXCEPTIONS_H__

void fp_exception_set_type(struct mbuf *m, uint8_t exc_type);

int fp_prepare_exception(struct mbuf *m, uint8_t exc_class);
int fp_ip_prepare_exception(struct mbuf *m, uint8_t exc_class);

void fp_sp_exception(struct mbuf *m);
#ifdef CONFIG_MCORE_MULTIBLADE
int fp_prepare_fpib_output_req(struct mbuf *m, fp_ifnet_t *ifp);
int fp_prepare_ipsec_output_req(struct mbuf *m, uint8_t blade_id, uint32_t ifuid);
int fp_prepare_ipsec6_output_req(struct mbuf *m, uint8_t blade_id, uint32_t ifuid);
#endif

void fp_send_exception(struct mbuf *m, uint8_t port);

#endif /* __FPN_EXCEPTIONS_H__ */
