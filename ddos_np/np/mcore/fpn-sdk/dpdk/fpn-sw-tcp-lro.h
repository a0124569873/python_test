/*
 * Copyright(c) 2014 6WIND
 */

#ifndef __FPN_SW_TCP_LRO_H__
#define __FPN_SW_TCP_LRO_H__

/**
 * Reassemble TCP packets using software LRO
 *
 * This function tries to coalesce TCP packets together. This is
 * possible when several packets shares the same addresses and ports,
 * and match some other conditions on flags, options, seq or ack
 * number...
 *
 * @param m_tab
 *   A table a mbuf
 * @param n
 *   A pointer to the number of elements in the table
 * @param lro_pktlen
 *   Maximum size of LRO-coalesced packet
 * @return
 *   The function has no return value, but the values pointer by
 *   m_tab and n are updated properly. The value pointed by n is
 *   lower or equal to the initial value.
 */
void fpn_sw_lro_reass(struct mbuf **m_tab, unsigned *n, unsigned lro_pktlen);

/**
 * Dump statistics related to software LRO
 */
void fpn_sw_lro_dump_stats(void);

/**
 * Init software LRO module
 */
void fpn_sw_lro_init(void);

#endif /* __FPN_SW_TCP_LRO_H__ */
