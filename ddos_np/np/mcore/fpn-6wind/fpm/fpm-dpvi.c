#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <net/if.h>	/* IFNAMSIZ */
#include "fpm_common.h"

#define PROC_FILE "/proc/sys/dpvi/list_interfaces"

static int
fpm_ifname2port_from_proc(const char *ifname, int *port)
{
	char buf[64];
	char *dpvi_name, *end;
	FILE *fp = fopen(PROC_FILE, "r");
	int id = -1;

	if (!fp) {
		syslog(LOG_ERR, "Unable to open " PROC_FILE);
		return -1;
	}

	*port = -1;

	/*
	 * proc looks like:
	 * 0 eth1_0
	 * 1 eth2_0
	 * 2 eth3_0
	 * 3 eth4_0
	 */
	while (fgets(buf, sizeof(buf), fp)) {

		end = strchr(buf, '\n');
		if (end == NULL)
			continue;
		end[0] = '\0';

		dpvi_name = strchr(buf, ' ');
		if (dpvi_name == NULL)
			continue;

		dpvi_name[0] = '\0';
		dpvi_name++;

		/* parse port id */
		end = NULL;
		id = strtoul(buf, &end, 0);
		if ((buf[0] == '\0') || (end == NULL) || (*end != '\0'))
			continue;

		if (!strcmp(dpvi_name, ifname)) {
			*port = id;
			break;
		}
	}
	fclose(fp);

	if (*port < 0)
		return -1;

	return 0;
}

int fpn_name2port(const char *name) {
	int port = -1;

	if (fpm_ifname2port_from_proc(name, &port) == 0)
		return port;

	/* unknown mapping */
	return -1;
}
