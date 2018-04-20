/*
 * Copyright (c) 2006 6WIND
 */
#ifndef __FPM_COMMON_H__
#define __FPM_COMMON_H__

#include <syslog.h>
#include "fpc.h"

#define __FPM_ALIGN(x,a) ((x + a - 1) & ~(a - 1))
#define FPM_ALIGN4(x) __FPM_ALIGN(x,4)
#define FPM_ALIGN8(x) __FPM_ALIGN(x,8)

/*
 * Dispatching
 */
extern int fpm_dispatch(const struct cp_hdr *, const uint8_t *);

extern void fpm_monitor_incomplete_nh_entries(void);

#include "netfpc.h"
extern int s_nfpc;
#ifdef CONFIG_MCORE_MULTIBLADE
extern uint32_t fpm_fpib_ifuid;
#endif

/* flag to specify that we are in monoblade co-localized mode */
extern int f_coloc_1cp1fp;
/* flag to specify that we are in co-localized mode, mono or multiblade */
extern int f_colocalized;

/* flag to specify that we want verbose info and debug messages */
extern int f_verbose;

/* flag to specify if FPM must automatically calculate FPTUN size thresholds */
extern int fpm_auto_threshold;

/* Board specific mapping between interface name (SP) and port number (FP) */
extern int fpn_name2port(const char *name);

/* mapping interface name and port number using mapping text file */
extern int fpm_ifname2port_from_file(const char *ifname, int *port);

/* flag indicating fastpath connectivity, used to prevent sending vnb messages */
/* to fastpath if it is not running, avoiding to lock fpm in a reply waiting loop */
extern unsigned int fpn0_status;

#ifdef HA_SUPPORT
/* Check for HA requests */
void fpm_ha_check_request(void);
#endif

/*
 * Graceful restart structures and functions
 */

#define FPM_GRACETIME 30
#define FPM_NH_INCOMPLETE_TIME 60
extern struct event event_graceful_restart;

void fpm_shared_mem_to_cmd(int gr_type);
void fpm_graceful_timer_end(int fd,  short event, void* arg);
void fpm_graceful_timer_abort(void);
void fpm_restart(void);

/*
 *      Display an IP address in readable format.
 */

#ifndef NIP6
#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])
#endif

#endif /* __FPM_COMMON_H__ */
