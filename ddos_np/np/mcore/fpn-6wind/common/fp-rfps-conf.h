/*
 * Copyright(c) 2009 6WIND
 */

#ifndef __FP_RFPS_CONF_H__
#define __FP_RFPS_CONF_H__

/*
 * Default periods are in milli-seconds
 */

/* Remote Fast Path IPv4 and IPv6 Statistics (IP) */
#define IP_DFLT_RFPS_TX_PERIOD          1000
#define IP_DFLT_RFPS_MAX_MSG_PER_TICK   1
#define IP_DFLT_RFPS_MIN_REFRESH_PERIOD 1000

/* Remote Fast Path Network Interfaces Statistics (IF) */
#define IF_DFLT_RFPS_TX_PERIOD          1000
#define IF_DFLT_RFPS_MAX_MSG_PER_TICK   5
#define IF_DFLT_RFPS_MIN_REFRESH_PERIOD 1000

typedef struct {
	uint32_t last_stamp;         /* last configuration setting stamp */
	uint32_t tx_period;          /* in milliseconds */
	uint32_t max_msg_per_tick;
	uint32_t min_refresh_period; /* in milliseconds */
} rfps_conf_t;

typedef struct {
	rfps_conf_t fp_rfps_ip;
	rfps_conf_t fp_rfps_if;
#ifdef CONFIG_MCORE_IPSEC
	rfps_conf_t fp_rfps_ipsec_sa;
	rfps_conf_t fp_rfps_ipsec_sp_in;
	rfps_conf_t fp_rfps_ipsec_sp_out;
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	rfps_conf_t fp_rfps_ipsec6_sa;
	rfps_conf_t fp_rfps_ipsec6_sp_in;
	rfps_conf_t fp_rfps_ipsec6_sp_out;
#endif
} fp_rfps_t;

extern void fp_rfps_conf_init(void);

#endif
