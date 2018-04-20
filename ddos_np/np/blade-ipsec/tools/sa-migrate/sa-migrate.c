/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdio.h>

#include <stdlib.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <linux/xfrm.h>
#include "blade-ipsec.h"

extern char *optarg;
extern int optind, opterr, optopt;

static void usage(void)
{
	printf("usage:\n"
	       "sa-migrate --type (single|byfp)\n"
	       "for single:\n"
	       "\t--dst (v4|v6) --proto proto --spi 0xspi\n"
	       "for byfp:\n"
	       "\t--s_fpid id\n"
	       "for all:\n"
	       "\t--vrfid vrfid\n"
	       "\t--gap gap\n"
	       "\t--d_fpid id\n");
}

int main(int argc, char **argv)
{
	int err;

	struct nl_sock *sk;
	struct nl_msg *msg;
	void *hdr;

	uint32_t gap = 0;
	uint32_t vrfid = 0;
	uint8_t type = 0;
	uint8_t d_fpid = 0;
	uint8_t s_fpid = 0;
	struct xfrm_usersa_id p;
	int id;
	int fail = 0;

	char ch;
	int option_index = 0;
	struct option long_options[] = {
		{"help",   no_argument, 0,  'h' },
		{"type",   required_argument, 0,  't' },
		/* for single migration */
		{"dst",    required_argument, 0,  'd' },
		{"proto",  required_argument, 0,  'p' },
		{"spi",    required_argument, 0,  's' },
		/* for bulk migration*/
		{"s_fpid", required_argument, 0,  'F' },
		/* migration description */
		{"vrfid",  required_argument, 0,  'v' },
		{"gap",    required_argument, 0,  'g' },
		{"d_fpid", required_argument, 0,  'f' },
		{0,        0,                 0,  0 }
	};

	memset(&p, 0, sizeof(p));

	while ((ch = getopt_long(argc, argv, "ht:d:p:s:F:v:g:f:", long_options, &option_index)) != EOF) {
		switch (ch) {
		/* type single or byfpid */
		case 't':
			if (!strcmp("single", optarg))
				type = BLADE_IPSEC_MIG_SINGLE;
			else if (!strcmp("byfp", optarg))
				type = BLADE_IPSEC_MIG_BULK_BY_FP;
			else {
				printf("unknown type %s\n", optarg);
				fail = 1;
			}
			break;

		/* for single migration */
		case 'd':
			if (type != BLADE_IPSEC_MIG_SINGLE) {
				printf("'dst' option only for 'single' type\n");
				fail = 1;
				break;
			}
			p.family = AF_INET;
			if (inet_pton(p.family, optarg, &p.daddr) <= 0) {
				p.family = AF_INET6;
				/* try v6 if v4 failed */
				if (inet_pton(p.family, optarg, &p.daddr) <= 0) {
					printf("invalid address %s for 'dst'", optarg);
					fail = 1;
					p.family = 0;
				}
			}
			break;

		case 'p':
		{
			struct protoent *pp;

			if (type != BLADE_IPSEC_MIG_SINGLE) {
				printf("'proto' option only for 'single' type\n");
				fail = 1;
				break;
			}

			pp = getprotobyname(optarg);
			if (pp)
				p.proto = pp->p_proto;
			else {
				printf("invalid 'proto' option %s\n", optarg);
				fail = 1;
			}
			break;
		}

		case 's':
			if (type != BLADE_IPSEC_MIG_SINGLE) {
				printf("'spi' option only for 'single' type\n");
				fail = 1;
				break;
			}
			p.spi = htonl(strtoul(optarg, NULL, 0));
			break;

		case 'F':
			if (type != BLADE_IPSEC_MIG_BULK_BY_FP) {
				printf("'s_fpid' option only for 'byfp' type\n");
				fail = 1;
				break;
			}
			s_fpid = (uint8_t)strtoul(optarg, NULL, 0);
			break;

		case 'v':
			vrfid = strtoul(optarg, NULL, 0);
			break;

		case 'g':
			gap = strtoul(optarg, NULL, 0);
			break;

		case 'f':
			d_fpid = (uint8_t)strtoul(optarg, NULL, 0);
			break;

		case 'h':
			usage();
			return -1;

		default:
			fail = 1;
			break;
		}

	}

	if (type == 0) {
		printf("no type provided\n");
		goto bad_opt;
	}

	/* check options */
	if (type == BLADE_IPSEC_MIG_SINGLE) {
		if (p.family == 0) {
			printf("no address provided\n");
			fail = 1;
		}
		if (p.spi == 0) {
			printf("no spi provided\n");
			fail = 1;
		}
	}

	if (type == BLADE_IPSEC_MIG_BULK_BY_FP) {
		if (s_fpid == 0) {
			printf("no src fpid provided\n");
			fail = 1;
		}
	}

	if (d_fpid == 0) {
		printf("no dst fpid provided\n");
		fail = 1;
	}

	if (fail)
		goto bad_opt;

	sk = nl_socket_alloc();
	if (!sk) {
		printf("could not allocated nl_sock\n");
		goto end;
	}

	err = genl_connect(sk);
	if (err < 0) {
		printf("genl_connect failed (%s)\n", nl_geterror(err));
		goto end;
	}

	id = genl_ctrl_resolve(sk, BLADE_IPSEC_FAMILY_NAME);
	if (id < 0) {
		printf("unknown generic family %s - try to insert blade-ipsec.ko (%s)\n", BLADE_IPSEC_FAMILY_NAME, nl_geterror(id));
		goto end;
	}

	msg = nlmsg_alloc();
        if (msg == NULL) {
		printf("could not allocated nlmsg\n");
		goto end;
	}

        hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, /* xxx */id,
			  0, 0, BLADE_IPSEC_C_MIGRATE, 1);
        if (hdr == NULL) {
		printf("unable to write genl header\n");
		nlmsg_free(msg);
		goto end;
	}

	nla_put_u8(msg, BLADE_IPSEC_A_TYPE, type);

	if (type == BLADE_IPSEC_MIG_SINGLE)
		nla_put(msg, BLADE_IPSEC_A_SA_ID, sizeof(struct xfrm_usersa_id), &p);
	else if (type == BLADE_IPSEC_MIG_BULK_BY_FP)
		nla_put_u8(msg, BLADE_IPSEC_A_SRC_FP, s_fpid);

	nla_put_u8(msg, BLADE_IPSEC_A_DST_FP, d_fpid);
	nla_put_u32(msg, BLADE_IPSEC_A_GAP, gap);
	if (vrfid)
		nla_put_u32(msg, BLADE_IPSEC_A_VRFID, vrfid);

        if ((err = nl_send_auto(sk, msg)))
                printf("unable to send message: %s\n", nl_geterror(err));
        nlmsg_free(msg);

	return 0;

end:
	nl_socket_free(sk);
	return -1;

bad_opt:
	printf("\n");
	usage();
	return -1;
}
