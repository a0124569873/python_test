/*
 * Copyright(c) 2006  6WIND
 */
#ifndef __FP_IP_REASS_H__
#define __FP_IP_REASS_H__

int fp_ip_reass_init(void);
int fp_ip_reass(struct mbuf **pm);
int fp_ip_reass_at_offset(struct mbuf **pm, size_t offset);
void fp_ip_reass_display_info(void);

#endif /* __FP_IP_REASS_H__ */
