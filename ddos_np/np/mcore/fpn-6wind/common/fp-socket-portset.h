/*
 * Copyright 2013 6WIND, All rights reserved.
 */

#ifndef __FP_SOCKET_PORTSET_H__
#define __FP_SOCKET_PORTSET_H__

/* bitfield (one bit per source port) */
typedef struct fp_socket_portset {
	uint8_t	bitfield[65536 / sizeof(uint8_t)];
} fp_socket_portset_t;

static inline int
fp_socket_portset_testbit(fp_socket_portset_t *set, uint16_t port)
{
	return set->bitfield[port>>3] & (1 << (port & 7));
}

static inline void
fp_socket_portset_setbit(fp_socket_portset_t *set, uint16_t port)
{
	set->bitfield[port>>3] |= (1 << (port & 7));
}

static inline void
fp_socket_portset_resetbit(fp_socket_portset_t *set, uint16_t port)
{
	set->bitfield[port>>3] &= ~(1 << (port & 7));
}

#endif /* __FP_SOCKET_PORTSET_H__ */
