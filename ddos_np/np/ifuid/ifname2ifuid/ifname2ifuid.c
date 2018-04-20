/*
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "ifuid.h"

void show_usage (char *progname)
{
	printf ("%s <ifname> <vrfid>\n", progname);
	exit (1);
}


int main(int argc, char ** argv)
{
	uint32_t ifuid, vrfid;
	char *ifname;

	if (argc != 3)
		show_usage (argv[0]);
	ifname = argv[1];
	vrfid = atoi(argv[2]);

	ifuid = ifname2ifuid(ifname, vrfid);
	printf ("%s %d: 0x%"PRIx32"\n", ifname, vrfid, ntohl (ifuid));
	exit (0);
}

