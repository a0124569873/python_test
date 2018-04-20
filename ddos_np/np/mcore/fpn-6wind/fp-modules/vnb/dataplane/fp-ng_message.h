/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __NG_MESSAGE_FP_H__
#define __NG_MESSAGE_FP_H__

struct ng_fp_hdr {
	uint32_t error:8;
	uint32_t len:8;	   /* length in 32-bit words of following path */
	uint32_t last_frag:1; /* set to 1 if it's the last frag */
	uint32_t reserved:15;
	uint32_t offset;

	uint8_t  path[0];
} __attribute__ ((packed));

typedef struct ng_fp_hdr ng_fp_hdr_t;

#define NG_FP_HDR_SIZE sizeof(ng_fp_hdr_t)

#endif
