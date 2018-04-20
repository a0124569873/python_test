/*
 * Copyright(c) 2010 6WIND
 */

#define TCPMSS_CLAMP_PMTU 0xFFFF

/*
 * fp_update_tcpmss_by_dev(...):
 * update tcp syn packet's MSS value by device's tcp4mss|tcp6mss
 *
 * We assume that:
 * 1) call place should be in Layer3(i.e. skb_network_header(skb) should be valid)
 * 2) IP header & TCP header must be checked before calling this function
 *
 * Mangle TCP MSS by device MSS setting:
 * 1.Only mangle SYN packets
 * 2.Only update MSS option if it exist (We don't try to add a New MSS Option if not exist)
 *
 * Return:
 *  0: packet's mss has been updated, or nothing was done (not a TCP syn packet)
 * -1: error, packet was freed
 */
int fp_update_tcpmss_by_dev(struct mbuf *m, fp_ifnet_t *ifp, unsigned int family);

