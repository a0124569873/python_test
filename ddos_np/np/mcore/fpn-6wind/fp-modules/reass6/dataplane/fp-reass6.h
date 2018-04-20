/*
 * Copyright 2014  6WIND
 */
#ifndef __FP_IPV6_REASS_H__
#define __FP_IPV6_REASS_H__

int fp_ipv6_reass_init(void);
int fp_ip6_reass(struct mbuf **pm);
int fp_ip6_reass_at_offset(struct mbuf **pm, size_t offset);

#endif /* __FP_IPV6_REASS_H__ */
