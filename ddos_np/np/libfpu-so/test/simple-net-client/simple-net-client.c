/*
 * Copyright 2013 6WIND. All rights reserved.
 */

#define _GNU_SOURCE /* for getopt_long */

#include <alloca.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#define DEFAULT_DST_IP "127.0.0.1"
#define DEFAULT_DST_PORT 5000
#define DEFAULT_BUFSIZE 65536

uint16_t dst_port = DEFAULT_DST_PORT;
struct sockaddr_in dst_sin;
int forever = 0;
int udp = 0;
int bufsize = DEFAULT_BUFSIZE;

static void
usage(const char *prog, int code)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Simple tcp/udp client\n\n");
	fprintf(stderr, "Usage : \n");
	fprintf(stderr, "  %s [options]\n", prog);
	fprintf(stderr,
		" -h, --help\n"
		"            show help\n");
	fprintf(stderr,
		" -d ADDR, --dest-addr=ADDR\n"
		"            dest ip address (default is %s).\n",
		DEFAULT_DST_IP);
	fprintf(stderr,
		" -p PORT, --port=PORT\n"
		"            dest tcp/udp port (default is %d)\n",
		DEFAULT_DST_PORT);
	fprintf(stderr,
		" -b SIZE, --bufsize=SIZE\n"
		"            len of data given to write() (default is %d)\n",
		DEFAULT_BUFSIZE);
	fprintf(stderr,
		" -f, --forever\n"
		"            send data until the program is interrupted\n");
	fprintf(stderr,
		" -u, --udp\n"
		"            use udp protocol\n");
	fprintf(stderr, "\n");
	exit(code);
}

static void
parse_args(int argc, char **argv)
{
	int ch;
	const char * prog = argv[0];
	int option_index;

	static struct option lgopts[] = {
		{"help", 0, 0, 'h'},
		{"dest-addr", 1, 0, 'd'},
		{"port", 1, 0, 'p'},
		{"bufsize", 1, 0, 'b'},
		{"forever", 0, 0, 'f'},
		{"udp", 0, 0, 'u'},
		{NULL, 0, 0, 0}
	};

	/* default IP */
	inet_pton(AF_INET, DEFAULT_DST_IP, &dst_sin.sin_addr);

	while ((ch = getopt_long(argc, argv,
				 "h"  /* help */
				 "d:" /* dest-addr */
				 "p:" /* port */
				 "b:" /* bufsize */
				 "f" /* forever */
				 "u" /* udp */
				 , lgopts, &option_index)) != -1) {

		switch (ch) {
		case 'h':
			usage(prog, 0);
			break;
		case 'd':
			if (inet_pton(AF_INET, optarg, &dst_sin.sin_addr) <= 0) {
				perror("inet_pton()");
				usage(prog, 1);
			}
			break;
		case 'p':
			dst_port = atoi(optarg);
			break;
		case 'b':
			bufsize = atoi(optarg);
			break;
		case 'f':
			forever = 1;
			break;
		case 'u':
			udp = 1;
			break;
		default:
			fprintf(stderr, "invalid option\n");
			usage(prog, 1);
		}
	}

	dst_sin.sin_family = AF_INET;
	dst_sin.sin_port = htons(dst_port);
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		fprintf(stderr, "invalid option\n");
		usage(prog, 1);
	}
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	int s, ret;
	char *buf;

	parse_args(argc, argv);

	buf = alloca(bufsize);
	if (buf == NULL)
		return 1;
	memset(buf, 0, bufsize);

	/* Ignore SIGPIPE, see this link for more info:
	 * http://www.mail-archive.com/libevent-users@monkey.org/msg01606.html */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 ||
	    sigaction(SIGPIPE, &sa, 0) == -1) {
		perror("failed to ignore SIGPIPE; sigaction");
		return 1;
	}

	if (udp)
		s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	else
		s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		perror("socket() failed\n");
		return 1;
	}

	ret = connect(s, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
	if (ret < 0) {
		perror("connect() failed");
		return 1;
	}

	do {
		ret = write(s, buf, bufsize);
		if (ret < 0) {
			perror("write() failed");
			return 1;
		}
	} while (forever == 1);

	ret = close(s);
	if (ret < 0) {
		perror("close() failed");
		return 1;
	}

	return 0;
}
