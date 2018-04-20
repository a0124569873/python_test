/**
 * Kernel table mapping command line
 *
 * This command line communicates with ktables module, allowing to configure
 * it and to print configuration.
 */

/*-
   * Copyright (c) <2011>, 6WIND
   * All rights reserved.
   */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/genetlink.h>

#include "ktables_config.h"
#include "module/ktables.h"

#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD_LEN(len)	(len - NLA_HDRLEN)

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	1024

#define TOLOWER(x) ((x) | 0x20)
#define ISXDIGIT(x)    (('0' <= (x) && (x) <= '9') || \
                ('a' <= (x) && (x) <= 'f') || \
                ('A' <= (x) && (x) <= 'F'))
#define ISDIGIT(c)    ('0' <= (c) && (c) <= '9')

struct msgtemplate {
	struct nlmsghdr n __attribute__ ((aligned(NLMSG_ALIGNTO)));
	union {
		struct {
			struct genlmsghdr g __attribute__
						((aligned(NLMSG_ALIGNTO)));
			char buf[MAX_MSG_SIZE];
		};
		struct nlmsgerr nlerr;
	};
};

struct global_s {
	int		nl_sd;
	uint32_t	pid;
	struct fnd_s {
		uint32_t	s:1,
				i:1,
				t:1,
				ta:1,
				p:1,
				m:1,
				d:1;
	} fnd;
	uint32_t	nl_grp_id;
	uint16_t	nl_family_id;
} glob;

/**
 * Print the content of a kernel table
 *
 * @param table
 *   Pointer to the kernel table
 * @return
 *   N/A
 */
void
print_one_table(uint8_t *table)
{
        int i;
        for(i = 0; i < KT_TABLE_SIZE; i++) {
                printf("%02x", table[i]);
        }
        printf("\n");
}

/**
 * Convert a string to an uint8 value
 *
 * @param cp
 *   A pointer to the string which will be converted to an uint8
 * @param len
 *   Len of the string
 * @param value
 *   A pointer to the result of the conversion
 * @return
 *   0 on success, -1 otherwise
 */
int
strtouint8(char *cp, int len, uint8_t *value)
{
        int i = 0;
        uint8_t tmp;

        if (cp[0] == '0' && TOLOWER(cp[1]) == 'x') {
                cp += 2;
        }

        *value = 0;
        while ( i < len) {
                if(!ISXDIGIT(cp[i])) {
                        return -1;
                }
                else {
                        tmp = ISDIGIT(cp[i]) ? (uint8_t)(cp[i] - '0') :
                                (uint8_t)(TOLOWER(cp[i]) -'a' + 10);
			if (len == 1)
				*value = tmp;
			else
				*value += (i%2) ? tmp : tmp << 4;
                        i++;
                }
        }
        return 0;
}

/**
 * Convert a string to a kernel table
 *
 * @param cp
 *   A pointer to the string which will be converted to a ktable
 * @param value
 *   A pointer to the kernel table
 * @return
 *   0 on success, -1 otherwise
 */
int
strtoktable(char *cp, uint8_t *value)
{
        int i = 0;

        if (cp[0] == '0' && TOLOWER(cp[1]) == 'x') {
                cp += 2;
        }

        memset(value, 0, KT_TABLE_SIZE);
        while ( i < KT_TABLE_SIZE) {
                if (strtouint8(cp + 2*i, 2, &value[i]) < 0) {
                        return -1;
                }
                else {
                        i++;
                }
        }

        return 0;
}

/**
 * Prints command usage
 *
 * @param argv
 *   the argv pointer given to main()
 * @return
 *   N/A
 */
void
usage(char **argv)
{
	printf("Usage: %s [-h] [<-t[table]> <-s value> <-p> [-i index] [-m]]\n"
		"\t-h       : Print this help and exit\n"
		"\t-t table : mapping table (0 to %d, or all)\n"
		"\t  -p       : Print table\n"
		"\t  -s value : Set configuration (in hex)\n"
		"\t	        If index is specified, value is one byte\n"
		"\t	        If not, value is an 8 bytes hex value\n"
		"\t	        (0x0102030405060708 for example)\n"
		"\t  -i index : Index in table, if not specified, whole table\n"
		"\t  -m       : Monitor netlink messages\n",
		argv[0], CONFIG_KTABLES_MAX_TABLES-1);
}

/**
 * Send a message to a specific generic netlink socket
 *
 * @param sd
 *   The socket descriptor on which to send the message
 * @param nlmsg_type
 *   netlink message type, or the generic netlink family Id
 * @param genl_cmd
 *   The generic netlink command (KT_CMD_MAP_GET for example)
 * @param nla_type
 *   The netlink attribute type (KT_ATTR_SET_ONE_BYTE for example)
 * @param nla_data
 *   A pointer to the data (the attribute) to copy in the message
 * @param nla_len
 *   The attribute length (data length)
 * @param flags
 *   Optional flags (NLM_F_REQUEST | NLM_F_DUMP for dump)
 * @return
 *   0 on success, an error code otherwise
 */
int
send_cmd(int sd, __u16 nlmsg_type, __u8 genl_cmd, __u16 nla_type,
	void *nla_data, int nla_len, uint16_t flags)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = flags;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = glob.pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	if (glob.fnd.d) {
#define DUMP_MSG	40
		int i;
		printf("First %d byte of the msg sent\n", DUMP_MSG);
		for (i = 0; i < DUMP_MSG; i++) {
			printf("%2d ", i);
			if (i%8 == 7)
				printf(" ");
		}
		printf("\n");
		for (i = 0; i < DUMP_MSG; i++) {
			printf("%02x ", ((uint8_t *)buf)[i]);
			if (i%8 == 7)
				printf(" ");
		}
		printf("\n");
	}

	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (glob.fnd.d)
			printf("sending (r=%d)\n", r);
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return r;
	}
	if (glob.fnd.d)
		printf("msg sent (r=%d)\n", r);

	return 0;
}

/**
 * Parse the groups sub message when retrieving family info
 *
 * @param na
 *   A pointer to the netlink attributes including all group attributes
 * @param tot_len
 *   The total length of the groups attribute
 * @return
 *   N/A
 */
static void
parse_groups(struct nlattr *na, int tot_len)
{
	int	len;
	int	grp_len;
	int	aggr_len;
	struct nlattr *grp_na;

	len = 0;
	while (len < tot_len) {
		len += NLA_ALIGN(na->nla_len);
		if (glob.fnd.d)
			printf("grp #%02d\n", na->nla_type);
		if (na->nla_type > 1) { /* only one group supported for now */
			na = (struct nlattr *) ((char *) na + len);
			continue;
		}

		aggr_len = NLA_PAYLOAD_LEN(na->nla_len);
		grp_na = (struct nlattr *) NLA_DATA(na);
		grp_len = 0;
		while (grp_len < aggr_len) {
			grp_len += NLA_ALIGN(grp_na->nla_len);
			switch (grp_na->nla_type) {
			/**
			 * As long as only one group is used, there
			 * is no reason to do a more complex algorithm
			 */
			case CTRL_ATTR_MCAST_GRP_ID:
				glob.nl_grp_id = *(uint32_t *) NLA_DATA(grp_na);
				if (glob.fnd.d)
					printf("grp id = %d\n",
						glob.nl_grp_id);

				break;
			case CTRL_ATTR_MCAST_GRP_NAME:
				if (glob.fnd.d)
					printf("grp name %s\n",
						(char *)NLA_DATA(grp_na));
				break;
			default:
				if (glob.fnd.d)
					printf("Unknown grp nested attr %d\n",
						grp_na->nla_type);
				break;
			}
			grp_na = (struct nlattr *) ((char *) grp_na + grp_len);
		}
		na = (struct nlattr *) ((char *) na + len);
	}
}

/**
 * Retrieve the id of a generic netlink family
 *
 * @param sd
 *   The netlink socket descriptor
 * @return
 *   The id of the netlink family on success, -1 otherwise
 * @note
 *   If an error occurs, prints a message to stdout
 */
int
get_family_id(int sd)
{
	struct msgtemplate msg;
	int	len;
	int	recv_len;
	int	rc;
	struct nlattr *na;

	rc = send_cmd(sd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, KT_NL_FAMILY_NAME,
			strlen(KT_NL_FAMILY_NAME)+1, NLM_F_REQUEST);
	if (rc < 0) {
		printf("Error sending family cmd (%d:%s)\n",
			errno, strerror(errno));
		return -1;
	}
	recv_len = recv(sd, &msg, sizeof(msg), 0);
	if (msg.n.nlmsg_type == NLMSG_ERROR) {
		printf("Error: recv family error msg\n");
		return -1;
	}
	if (recv_len < 0) {
		printf("Error: recv family (%d)\n", recv_len);
		return -1;
	}
	if (!NLMSG_OK((&msg.n), recv_len)) {
		printf("Error: recv family msg nok\n");
		return -1;
	}


	recv_len = GENLMSG_PAYLOAD(&msg.n);
	na	 = (struct nlattr *) GENLMSG_DATA(&msg);
	len	 = 0;
	while (len < recv_len) {
		len += NLA_ALIGN(na->nla_len);
		switch (na->nla_type) {
		case CTRL_ATTR_FAMILY_ID:
			glob.nl_family_id = *(uint16_t *) NLA_DATA(na);
			if (glob.fnd.d)
				printf("family id:%d\n", glob.nl_family_id);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			parse_groups(NLA_DATA(na),
					NLA_PAYLOAD_LEN(na->nla_len));
			break;
		case CTRL_ATTR_FAMILY_NAME:
		case CTRL_ATTR_VERSION:
		case CTRL_ATTR_HDRSIZE:
		case CTRL_ATTR_MAXATTR:
		case CTRL_ATTR_OPS:
			if (glob.fnd.d)
				printf("Unused family attr %d\n",
					na->nla_type);
			break;
		default:
			if (glob.fnd.d)
				printf("Unknown family attr %d\n",
					na->nla_type);
			break;
		}
		na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
	}

	return glob.nl_family_id;
}

/**
 * Open, bind and get family id of our generic netlink family
 *
 * @return
 *   the socket descriptor on success, -1 otherwise
 * @note
 *   If an error occurs, prints a message to stdout
 */
int
open_nl_socket(void)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		printf("Error opening socket (%d)\n", errno);
		return -1;
	}
	if (glob.fnd.d)
		printf("fd:%d\n", fd);

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		printf("Error binding socket (%d)\n", errno);
		close(fd);
		return -1;
	}
	if (glob.fnd.d)
		printf("bind done\n");

	/* Retrieve netlink family Id */
	glob.nl_family_id = get_family_id(fd);
	if (glob.nl_family_id < 0) {
		printf("Error: Could not retreive netlink family id\n");
		close(fd);
		return -1;
	}

	return fd;
}

/**
 * Set one byte in a kernel table
 *
 * @param table
 *   The table number (from 0 to CONFIG_KTABLES_MAX_TABLES)
 * @param idx
 *   The index of the byte in table (from 0 to 7)
 * @param value
 *   The value to set to this byte
 * @return
 *   0 on success, an error code otherwise
 */
int
set_one_byte(int table, int idx, uint8_t value)
{
	int ret;
	struct attr_byte_s	attr_b;

	attr_b.table	= table;
	attr_b.idx	= (uint8_t)idx;
	attr_b.value	= value;

	ret = send_cmd(glob.nl_sd, glob.nl_family_id, KT_CMD_MAP_SET,
		KT_ATTR_SET_ONE_BYTE, &attr_b, sizeof(attr_b), NLM_F_REQUEST);
	if (glob.fnd.d)
		printf("Sent set req for table %u, ret=%d %d %d %02x\n", table,
			ret, attr_b.table, attr_b.idx, attr_b.value);
	if (ret < 0) {
		printf("Error sending request (%d:%s)\n",
			errno, strerror(errno));
		return ret;
	}

	return 0;
}

/**
 * Set a whole kernel table
 *
 * @param table
 *   The table number (from 0 to CONFIG_KTABLES_MAX_TABLES)
 * @param value
 *   The byte array to set to table
 * @return
 *   0 on success, an error code otherwise
 */
int
set_one_table(int table, uint8_t *value)
{
	int ret;
	struct attr_table_s	attr_t;

	attr_t.table	= table;
	memcpy(attr_t.table_value, value, KT_TABLE_SIZE);

	ret = send_cmd(glob.nl_sd, glob.nl_family_id, KT_CMD_MAP_SET,
			KT_ATTR_SET_ONE_TABLE, &attr_t, sizeof(attr_t),
			NLM_F_REQUEST);
	if (glob.fnd.d) {
		printf("Sent set req for table %u, ret=%d %d ", table, ret, attr_t.table);
		print_one_table(attr_t.table_value);
	}
	if (ret < 0) {
		printf("Error sending request (%d:%s)\n",
			errno, strerror(errno));
		return ret;
	}

	return 0;
}

/**
 * Print the content of a kernel table
 *
 * @param table
 *   The table number (from 0 to CONFIG_KTABLES_MAX_TABLES)
 * @return
 *   0 on success, an error code otherwise
 */
int
show_one_table(uint32_t table)
{
	int ret;

	ret = send_cmd(glob.nl_sd, glob.nl_family_id, KT_CMD_MAP_GET,
			KT_ATTR_GET_ONE_TABLE, &table, sizeof(table),
			NLM_F_REQUEST);
	if (glob.fnd.d)
		printf("Sent Get req for table %u, ret=%d\n", table, ret);
	if (ret < 0) {
		printf("Error sending request (%d:%s)\n",
			errno, strerror(errno));
		return ret;
	}

	return 0;
}

/**
 * Print the content of all kernel table
 *
 * This function can be very verbose if there is a large number
 * of kernel tables
 *
 * @return
 *   0 on success, an error code otherwise
 */
int
dump_all_tables(void)
{
	int ret;

	ret = send_cmd(glob.nl_sd, glob.nl_family_id, KT_CMD_MAP_DUMP,
			0, NULL, 0, NLM_F_REQUEST | NLM_F_DUMP);
	if (glob.fnd.d)
		printf("Sent Dump req, ret=%d\n", ret);
	if (ret < 0) {
		printf("Error sending request (%d:%s)\n",
			errno, strerror(errno));
		return ret;
	}

	return 0;
}

/**
 * Wait for answers from Ktables module
 *
 * Called after a request, this function will wait some seconds
 * for answer(s) from ktables module. Depending on request, this
 * function can be pretty verbose (on dump especially)
 *
 * @param sd
 *   The netlink socket descriptor
 * @return
 *   0 on success, an error code otherwise
 */
int
wait_answers(int sd)
{
	int		flags;
	int		ret;
	int		recv_len;
	int		len;
	int		err;
	fd_set		rfds;
	struct nlmsgerr *nl_err;
	struct timeval	tv;
	struct nlattr	*na;
	struct attr_byte_s	*attr_b;
	struct attr_table_s	*attr_t;
	struct msgtemplate	msg;

	flags = fcntl(sd, F_GETFL);
	fcntl(sd, F_SETFL, flags | O_NONBLOCK);

	err = 0;
	do {
		FD_ZERO(&rfds);
		FD_SET(sd, &rfds);

		if (glob.fnd.m) {
			/* Monitoring, no timeout */
			ret = select(sd+1, &rfds, NULL, NULL, NULL);
		} else {
			tv.tv_sec = 5;
			tv.tv_usec = 0;

			ret = select(sd+1, &rfds, NULL, NULL, &tv);
		}

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("select()");
			err = ret;
			break;
		} else if (ret == 0) {
			printf("No answer within %lu seconds.\n", tv.tv_sec);
			err = -ETIMEDOUT;
			break;
		}
		if (!FD_ISSET(sd, &rfds))
			continue;

		recv_len = recv(glob.nl_sd, &msg, sizeof(msg), 0);
		if (glob.fnd.d)
			printf("received %d bytes\n", recv_len);
		if (recv_len < 0) {
			printf("nonfatal reply error: errno %d\n", errno);
			err = errno;
			break;
		}
		if (msg.n.nlmsg_type == NLMSG_ERROR ||
		    !NLMSG_OK((&msg.n), recv_len)) {
			nl_err = NLMSG_DATA(&msg);
			printf("fatal reply error,  errno %d\n", nl_err->error);
			err = nl_err->error;
			break;
		}

		if (glob.fnd.d)
			printf("nlmsghdr size=%zu, nlmsg_len=%d, recv_len=%d\n",
				sizeof(struct nlmsghdr), msg.n.nlmsg_len,
				recv_len);


		recv_len = GENLMSG_PAYLOAD(&msg.n);

		na = (struct nlattr *) GENLMSG_DATA(&msg);

		len	= 0;
		while (len < recv_len) {
			len += NLA_ALIGN(na->nla_len);
			switch (na->nla_type) {
			case KT_TYPE_ONE_TABLE:
				/* Dump a table */
				attr_t = NLA_DATA(na);
				printf("ktable[%02u]: ", attr_t->table);
				print_one_table(attr_t->table_value);
				/* If printing all tables, check if this one
				 * is the last one.
				 */
				if (glob.fnd.ta && (attr_t->table ==
						CONFIG_KTABLES_MAX_TABLES - 1))
					glob.fnd.ta = 0;
				break;
			case KT_TYPE_ONE_BYTE_SET:
				/* Answer for our command */
				attr_b = NLA_DATA(na);
				printf("table[%u][%u] set to %02x\n",
					attr_b->table, attr_b->idx,
					attr_b->value);
				break;

			default:
				printf("Unknown nla_type %d\n", na->nla_type);
				break;
			}
			na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
		}
	} while (glob.fnd.ta || glob.fnd.m);

	/* restore previous attributes */
	fcntl(sd, F_SETFL, flags);
	return err;
}

/**
 * Prints error message on invalid arguments
 *
 * @param opt
 *   The corresponding option character
 * @param argv
 *   the argv pointer given to main()
 * @return
 *   N/A
 */
void
invalid_arg(int opt, char *argv[])
{
	printf("Invalid argument to -%c (%s)\n",
		opt, optarg);
	usage(argv);
	exit(EXIT_FAILURE);
}

/**
 * main entry of the program
 *
 * @param argc
 *   The number of arguments
 * @param argv
 *   A pointers table containing the arguments list
 * @return
 *   EXIT_SUCCESS on success, EXIT_FAILURE otherwise
 */
int
main(int argc, char *argv[])
{
	uint8_t         byte_value;
	uint8_t         table_value[KT_TABLE_SIZE];
	long		table, idx;
	int		opt;
	int		len;
	int		err;
	char		*str;
	int		ret;

	idx	= 0;
	table	= -1;
	memset(&glob.fnd, 0, sizeof(glob.fnd));

	if (argc == 1) {
		usage(argv);
		exit(EXIT_FAILURE);
	}
	opterr = 0;
	while ((opt = getopt(argc, argv, ":hmdpt::s:i:")) != -1) {
		switch (opt) {
		case 'd':
			glob.fnd.d = 1;
			break;
		case 'm':
			glob.fnd.m = 1;
			break;
		case 't':
			glob.fnd.t = 1;
			if (optarg == NULL)
				break;
			if (strcasecmp(optarg, "all") == 0) {
				glob.fnd.ta = 1;
				break;
			}
			errno = 0;
			table = strtol(optarg, &str, 10);
			if (errno || *str)
				invalid_arg(opt, argv);
			break;
		case 'i':
			glob.fnd.i = 1;
			errno = 0;
			idx = strtol(optarg, &str, 10);
			if (errno || *str)
				invalid_arg(opt, argv);
			break;
		case 'p':
			glob.fnd.p = 1;
			break;
		case 's':
			glob.fnd.s = 1;
			len = strlen(optarg);
			if (strncasecmp(optarg, "0x", 2) == 0)
				len -= 2;
			if (len != 1 && len != 2 && len != KT_TABLE_SIZE*2)
				invalid_arg(opt, argv);
			if (len == 1 || len == 2)
				ret = strtouint8(optarg, len, &byte_value);
			else
				ret = strtoktable(optarg, table_value);
			if (ret != 0)
				invalid_arg(opt, argv);
			break;
		case 'h':
			usage(argv);
			exit(EXIT_SUCCESS);
		case ':':
			printf("Missing attribute to -%c\n", optopt);
			usage(argv);
			exit(EXIT_FAILURE);
		case '?':
			printf("Unknown option -%c\n", optopt);
		default: /* never know... */
			usage(argv);
			exit(EXIT_FAILURE);
		}
	}

	if (glob.fnd.d) {
		if (glob.fnd.d)
			printf("d\n");
		if (glob.fnd.m)
			printf("m\n");
		if (glob.fnd.ta)
			printf("t:all\n");
		if (glob.fnd.t) {
			if (table != -1)
				printf("t:%lu\n", table);
			else
				printf("t\n");
		}
		if (glob.fnd.i)
			printf("i:%lu\n", idx);
		if (glob.fnd.p)
			printf("p\n");
		if (glob.fnd.s) {
			if (glob.fnd.i)
				printf("s:%02x\n", byte_value);
			else
				print_one_table(table_value);
		}
	}

	glob.pid = getpid();
	glob.nl_sd = open_nl_socket();
	if (glob.nl_sd < 0)
		exit(EXIT_FAILURE);
	err = EXIT_SUCCESS;

	/* Mapping tables */
	if (glob.fnd.ta) {
		if (dump_all_tables()) {
			err = EXIT_FAILURE;
			goto end;
		}
		wait_answers(glob.nl_sd);
	} else if (glob.fnd.t) {
		if (!glob.fnd.s && !glob.fnd.p && !glob.fnd.m) {
			printf("For mapping tables, -p, -s or "
				"-m are mandatory\n");
			usage(argv);
			err = EXIT_FAILURE;
			goto end;
		}
		if (!glob.fnd.m && (table == -1)) {
			printf("For mapping tables, with '-p' or '-s', a"
				" table value is mandatory\n");
			usage(argv);
			err = EXIT_FAILURE;
			goto end;
		}

#ifndef SOL_NETLINK
/* normally defined in bits/socket.h but not available in some
 * toolchains.
 */
#define SOL_NETLINK 270
#endif
		/* Monitor netlink socket, we should never return from this */
		if (glob.fnd.m) {
			setsockopt(glob.nl_sd, SOL_NETLINK,
				NETLINK_ADD_MEMBERSHIP, &glob.nl_grp_id,
				sizeof(glob.nl_grp_id));
			wait_answers(glob.nl_sd);
			goto end; /* never know... */
		}
		/* If needed, set values */
		if (glob.fnd.s) {
			if (glob.fnd.i)
				set_one_byte(table, idx, byte_value);
			else
				set_one_table(table, table_value);
			wait_answers(glob.nl_sd);
		}
		/* Then, eventually, dump them */
		if (glob.fnd.p) {
			show_one_table(table);
			wait_answers(glob.nl_sd);
		}
	}

end:
	close(glob.nl_sd);
	exit(err);
}
