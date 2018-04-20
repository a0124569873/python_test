/*
 * Copyright (c) 2007 6WIND
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <net/if.h>
#include "fpm_common.h"
#include "fp.h"
#include "libfp_shm.h"

/*
 * mapping port/interface: we use the ifindex as portid
 */
int fpn_name2port(const char *name) {
	int port = -1;
	
	if (fpm_ifname2port_from_file(name,&port)==0)
		return port;
	else
		port = if_nametoindex(name);

	if (port == 0)
		return -1;

	return port;
}
