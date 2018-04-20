/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdint.h>
#include <inttypes.h>

extern int fps_nl_init(void);

struct fps_nl_stats {
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

extern int fps_nl_get_stats(char *devname, struct fps_nl_stats *stats);
