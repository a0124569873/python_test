/*
 * Copyright (C) 2013 6WIND
 */
#define _GNU_SOURCE

#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ifuid.h"

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
uint32_t ifname2ifuid (const char *ifname, uint32_t vrfid)
{
	unsigned long hash = 0;
	int len = strnlen(ifname, IFNAMSIZ);
	unsigned char c;
	char *vrf = (char *)&vrfid;
	vrfid = htonl(vrfid);

	while (len--) {
		c = *ifname++;
		hash = (hash + (c << 4) + (c >> 4)) * 11;
	}

	len = sizeof(uint32_t);
	while (len--) {
		c = *vrf++;
		hash = (hash + (c << 4) + (c >> 4)) * 11;
	}

        return (htonl(hash * GOLDEN_RATIO_PRIME_32));
}
