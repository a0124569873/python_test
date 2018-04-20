/*
 * Copyright(c) 2009 6WIND. All rights reserved.
 */
#include <net/if.h>
#include "fpm_common.h"

void fp_vnb_oosync(uint32_t expected_seqnum, uint32_t received_seqnum)
{
	syslog(LOG_ERR, "%s: Netlink VNB message(s) has(have) been lost: "\
		   "Received sequence number: %u,  Expected sequence number: %u\n",
		   __FUNCTION__, received_seqnum, expected_seqnum);

	fpm_restart();
	return ;
}
