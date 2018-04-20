/*
 * Copyright (c) 2004, 2006 6WIND
 */

/*
 ***************************************************************
 *
 *          Generic Msg Dumps
 *
 * $Id: cm_dump.h,v 1.9 2009-05-06 09:11:06 dichtel Exp $
 *
 ***************************************************************
 */
#ifndef __CM_DUMP_H__
#define __CM_DUMP_H__

/* Define the length of log buffer */
#define LOG_BUFFER_LEN 1024

#include "fpm.h"

/* CM/FPM message queue debug flags */
#define CM_DUMP_HDR_QUEUED    0x00000001
#define CM_DUMP_EXT_QUEUED    0x00000002
#define CM_DUMP_HEX_QUEUED    0x00000004
#define CM_DUMP_DBG_QUEUED    0x00000008

/* CM/FPM message send debug flags */
#define CM_DUMP_HDR_SENT      0x00000010
#define CM_DUMP_EXT_SENT      0x00000020
#define CM_DUMP_HEX_SENT      0x00000040
#define CM_DUMP_DBG_SENT      0x00000080

/* CM/FPM message recv debug flags */
#define CM_DUMP_HDR_RECV      0x00000100
#define CM_DUMP_EXT_RECV      0x00000200
#define CM_DUMP_HEX_RECV      0x00000400
#define CM_DUMP_DBG_RECV      0x00000800

/* netlink message debug flags */
#define CM_DUMP_HDR_NL_RECV   0x00001000
#define CM_DUMP_EXT_NL_RECV   0x00002000
#define CM_DUMP_HEX_NL_RECV   0x00004000
#define CM_DUMP_DBG_NL_RECV   0x00008000

/* low level socket debug flags */
#define CM_DUMP_DBG_SOCK      0x00010000

/* admin message debug flags */
#define CM_DUMP_HDR_ADM_RECV  0x00100000
#define CM_DUMP_EXT_ADM_RECV  0x00200000
#define CM_DUMP_HEX_ADM_RECV  0x00400000
#define CM_DUMP_DBG_ADM_RECV  0x00800000

#define CM_DUMP_QUEUED  1
#define CM_DUMP_SENT    2
#define CM_DUMP_RECV    3
#define CM_DUMP_FPM     4
#define CM_DUMP_SENT_WITH_PAYLOAD	5
#define CM_DUMP_RECV_WITH_PAYLOAD	6

/* CM/FPM message queue debug flags */
#define CM_DUMP_SKIP_ARP      0x00000001
#define CM_DUMP_SKIP_NDP      0x00000002
#define CM_DUMP_SKIP_ROUTE4   0x00000004
#define CM_DUMP_SKIP_ROUTE6   0x00000008

#define SPACES "        "

typedef  char* (*cm_ifuid2name_t) (uint32_t ifuid);
extern void cm_dump (int, struct fpm_msg *, char *, cm_ifuid2name_t);

extern const char *cm_adm_type2str(u_int16_t type);
extern const char *cm_command2str(u_int32_t type);
extern const char *cm_ipsec_aalg2str(u_int8_t alg);
extern const char *cm_ipsec_ealg2str(u_int8_t alg);

#endif
