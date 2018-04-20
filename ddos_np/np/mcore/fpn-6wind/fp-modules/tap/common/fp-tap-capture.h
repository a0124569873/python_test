/*
 * Copyright 2012 6WIND, All rights reserved.
 */

#ifndef __FP_TAP_CAPTURE_H__
#define __FP_TAP_CAPTURE_H__

#define CAP_SHM_NAME "pktcap-shared"

struct fp_tap_pkt {
	uint64_t timestamp;
	uint32_t pkt_len;
	unsigned char data[];
};

#endif
