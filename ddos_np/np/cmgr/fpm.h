/*
 * Copyright (c) 2004, 2006 6WIND
 */

/*
 ***************************************************************
 *
 *          Generic Msg exchange between
 *    Cache Manager (CM) and  Fast Path Manager (FPM)
 *
 * $Id: fpm.h,v 1.5 2010-05-19 09:25:29 dichtel Exp $
 *
 ***************************************************************
 */
#ifndef __FPM_H__
#define __FPM_H__

#ifdef CONFIG_PORTS_CACHEMGR_DEF_SOCKBUFSIZE
#define CM_DEFAULT_SOCKBUFSIZ CONFIG_PORTS_CACHEMGR_DEF_SOCKBUFSIZE
#else
#define CM_DEFAULT_SOCKBUFSIZ 131070
#endif
#define CM_DEFAULT_IOVLEN     512

#include <sys/queue.h>
/*
 * FPM internal & dumps
 */
struct fpm_msg {
	TAILQ_ENTRY(fpm_msg)   msg_link;     /* chaining stuff       */
	u_int32_t              msg_len;      /* total message length */
	u_int32_t              msg_off;      /* sending start offset */
	struct cp_hdr         *msg_pkt;      /* message itself       */
};

extern void fpm_process_queue(u_int8_t value);
#endif
