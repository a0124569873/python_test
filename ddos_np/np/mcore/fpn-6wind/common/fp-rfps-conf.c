/*
 * Copyright(c) 2009 6WIND
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "fp.h"
#include "fp-rfps-conf.h"

/* IPv4 and IPv6 statistics */
void fp_set_rfps_ip(uint32_t tx_period, uint32_t max_msg_per_tick,
		    uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ip.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ip.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ip.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ip.last_stamp++;
}

/* Network Interfaces statistics */
void fp_set_rfps_if(uint32_t tx_period, uint32_t max_msg_per_tick,
		    uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_if.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_if.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_if.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_if.last_stamp++;
}

#ifdef CONFIG_MCORE_IPSEC
/* IPsec SA statistics */
void fp_set_rfps_ipsec_sa(uint32_t tx_period, uint32_t max_msg_per_tick,
			  uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ipsec_sa.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ipsec_sa.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ipsec_sa.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ipsec_sa.last_stamp++;
}

/* IPsec SP statistics */
void fp_set_rfps_ipsec_sp_in(uint32_t tx_period, uint32_t max_msg_per_tick,
			     uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_in.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_in.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_in.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_in.last_stamp++;
}

void fp_set_rfps_ipsec_sp_out(uint32_t tx_period, uint32_t max_msg_per_tick,
			      uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_out.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_out.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_out.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ipsec_sp_out.last_stamp++;
}
#endif /* CONFIG_MCORE_IPSEC */

#ifdef CONFIG_MCORE_IPSEC_IPV6
/* IPv6 IPsec SA statistics */
void fp_set_rfps_ipsec6_sa(uint32_t tx_period, uint32_t max_msg_per_tick,
			   uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ipsec6_sa.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sa.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sa.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sa.last_stamp++;
}

/* IPv6 IPsec SP statistics */
void fp_set_rfps_ipsec6_sp_in(uint32_t tx_period, uint32_t max_msg_per_tick,
			      uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_in.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_in.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_in.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_in.last_stamp++;
}

void fp_set_rfps_ipsec6_sp_out(uint32_t tx_period, uint32_t max_msg_per_tick,
			       uint32_t min_refresh_period)
{
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_out.tx_period          = tx_period;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_out.max_msg_per_tick   = max_msg_per_tick;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_out.min_refresh_period = min_refresh_period;
	fp_shared->fp_rfps.fp_rfps_ipsec6_sp_out.last_stamp++;
}
#endif /* CONFIG_MCORE_IPSEC_IPV6 */

void fp_rfps_conf_init(void)
{
	fp_set_rfps_ip(IP_DFLT_RFPS_TX_PERIOD, IP_DFLT_RFPS_MAX_MSG_PER_TICK,
		       IP_DFLT_RFPS_MIN_REFRESH_PERIOD);
	fp_set_rfps_if(IF_DFLT_RFPS_TX_PERIOD, IF_DFLT_RFPS_MAX_MSG_PER_TICK,
		       IF_DFLT_RFPS_MIN_REFRESH_PERIOD);
#ifdef CONFIG_MCORE_IPSEC
	fp_set_rfps_ipsec_sa(IP_DFLT_RFPS_TX_PERIOD, IP_DFLT_RFPS_MAX_MSG_PER_TICK,
			     IP_DFLT_RFPS_MIN_REFRESH_PERIOD);
	fp_set_rfps_ipsec_sp_in(IF_DFLT_RFPS_TX_PERIOD, IF_DFLT_RFPS_MAX_MSG_PER_TICK,
				IF_DFLT_RFPS_MIN_REFRESH_PERIOD);
	fp_set_rfps_ipsec_sp_out(IF_DFLT_RFPS_TX_PERIOD, IF_DFLT_RFPS_MAX_MSG_PER_TICK,
				 IF_DFLT_RFPS_MIN_REFRESH_PERIOD);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_set_rfps_ipsec6_sa(IP_DFLT_RFPS_TX_PERIOD, IP_DFLT_RFPS_MAX_MSG_PER_TICK,
			      IP_DFLT_RFPS_MIN_REFRESH_PERIOD);
	fp_set_rfps_ipsec6_sp_in(IF_DFLT_RFPS_TX_PERIOD, IF_DFLT_RFPS_MAX_MSG_PER_TICK,
				 IF_DFLT_RFPS_MIN_REFRESH_PERIOD);
	fp_set_rfps_ipsec6_sp_out(IF_DFLT_RFPS_TX_PERIOD, IF_DFLT_RFPS_MAX_MSG_PER_TICK,
				  IF_DFLT_RFPS_MIN_REFRESH_PERIOD);
#endif
}
