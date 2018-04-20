/*
 * Copyright(c) 2013-2014 6WIND
 * All rights reserved
 */

#ifndef __FastPath__
#include <stdio.h>
#include <string.h>
#endif

#include "fpn.h"
#include "fp.h"
#include "fpdebug.h"
#include "fpdebug-priv.h"

#if defined(__FastPath__)
#include <rte_ethdev.h>
#endif

/*
 * Command to configure RETA entries of a given port.
 */
#define FPDEBUG_RSS_RETA_SET_USAGE \
	"\n\trss-reta-set Pi index i[ j]* queue Qj"	\
	"\n\t Pi: the port number" \
	"\n\t i[ j]*: a blank/tab-separated list of RETA entries" \
	"\n\t Qj: the RX queue index to record into the RETA entries"

/*
 * Command to display RETA entries of a given port.
 */
#define FPDEBUG_RSS_RETA_SHOW_USAGE \
	"\n\trss-reta-show Pi [index i [j]]" \
	"\n\t Pi: the port number" \
	"\n\t index i: the optional index of a RETA entry" \
	"\n\t index i j: the optional indices of a range of RETA entries" \
	"\n\t (by default, all 128 RETA entries of the port are displayed)"

/*
 * Command to configure the RSS hash functions used to compute the RSS hash
 * value of [IP] input packets received on a given port.
 * Disable RSS filtering on the port if no hash function is supplied.
 */
#define FPDEBUG_RSS_HASH_FUNC_SET_USAGE \
	"\n\trss-hash-func-set Pi [hf]*" \
	"\n\t Pi: the port number" \
	"\n\t [hf]*: a blank/tab-separated list of RSS hash functions" \
	" among the following ones:"\
	"\n\t        ip4 ip6 ip6-ex tcp4 tcp6 tcp6-ex udp4 udp6 udp6-ex" \
	"\n\t Disable RSS filtering is no hash function is supplied"

/*
 * Command to display the current set of RSS hash functions, if any, that
 * are used to compute the RSS hash of [IP] input packets received on a
 * given port.
 */
#define FPDEBUG_RSS_HASH_FUNC_SHOW_USAGE \
	"\n\trss-hash-func-show Pi" \
	"\n\t Pi: the port number"

/*
 * Command to configure the [40-byte] RSS hash key used to compute the
 * RSS hash value of [IP] input packets received on a given port.
 */
#define FPDEBUG_RSS_HASH_KEY_SET_USAGE \
	"\n\trss-hash-key-set Pi key" \
	"\n\t Pi: the port number" \
	"\n\t key: the 40-bytes key as a contiguous set of 80 hexadecimal" \
	" digits (2 hexa digits par byte)"

/*
 * Command to display the current [40-byte] RSS hash key used to compute the
 * RSS hash value of [IP] input packets received on a given port.
 */
#define FPDEBUG_RSS_HASH_KEY_SHOW_USAGE \
	"\n\trss-hash-key-show Pi" \
	"\n\t Pi: the port number"

#if defined(__FastPath__)
static void
rte_port_op_diag_print(char *port_id_arg, int diag)
{
	switch (diag) {
	case (-ENODEV):
		fpdebug_fprintf(stderr, "invalid port index %s", port_id_arg);
		break;
	case (-ENOTSUP):
		fpdebug_fprintf(stderr, "operation not supported by hardware");
		break;
	default:
		fpdebug_fprintf(stderr, "operation failed. diag=%d", -diag);
		break;
	}
}

static inline int
int_arg_parse(char *int_arg)
{
	char *end;
	unsigned long long arg_value;

	arg_value = strtoull(int_arg, &end, 0);
	if (*end == 0)
		return (int) arg_value;
	return -1;
}

static inline int
port_index_arg_parse(char *port_idx_arg)
{
	int port_idx;

	port_idx = int_arg_parse(port_idx_arg);
	if (port_idx >= 0)
		return (int) port_idx;
	fpdebug_fprintf(stderr, "wrong port index %s\n", port_idx_arg);
	return -1;
}

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
#define ETH_RSS_RETA_NUM_ENTRIES ETH_RSS_RETA_SIZE_64
#endif

/* RSS Redirection Table configuration */
static int
reta_index_arg_parse(char *reta_idx_arg)
{
	int reta_idx;

	reta_idx = int_arg_parse(reta_idx_arg);
	if ((reta_idx >= 0) && (reta_idx < ETH_RSS_RETA_NUM_ENTRIES))
		return (int) reta_idx;
	fpdebug_fprintf(stderr, "wrong RETA entry index %s\n", reta_idx_arg);
	return -1;
}

static inline void
fpdebug_rss_reta_set_usage(const char *reason)
{
	fpdebug_fprintf(stderr, "rss-reta-set: %s%s\n",
			reason, FPDEBUG_RSS_RETA_SET_USAGE);
}

static int
fpdebug_rss_reta_set(char *tok)
{
	
	int nb_args;
	int port_idx;
	int rxq_idx;
	int reta_idx;
	int diag;
	int i;

	nb_args = gettokens(tok);
	if (nb_args < 5) {
		fpdebug_rss_reta_set_usage("wrong nb. of arguments");
		return -1;
	}
	if (strcmp(chargv[1], "index") != 0) {
		fpdebug_rss_reta_set_usage("keyword \"index\" is missing");
		return -1;
	}
	if (strcmp(chargv[nb_args - 2], "queue") != 0) {
		fpdebug_rss_reta_set_usage("keyword \"queue\" is missing");
		return -1;
	}
	port_idx = port_index_arg_parse(chargv[0]);
	rxq_idx  = int_arg_parse(chargv[nb_args - 1]);
	if (rxq_idx < 0) {
		fpdebug_fprintf(stderr, "invalid RX queue index %s\n",
				chargv[nb_args - 1]);
		return -1;
	}
	
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
	struct rte_eth_rss_reta_entry64 reta_conf;
	reta_conf.mask = 0;
	for (i = 2; i < nb_args - 2; i++) {
		reta_idx = reta_index_arg_parse(chargv[i]);
		if (reta_idx < 0)
			return -1;
		reta_conf.reta[reta_idx] = rxq_idx;
		reta_conf.mask |= (UINT64_C(1) << reta_idx);
	}
	diag = rte_eth_dev_rss_reta_update((uint8_t) port_idx, &reta_conf, nb_args - 4);

#else
	struct rte_eth_rss_reta reta_conf;	
	reta_conf.mask_lo = 0;
	reta_conf.mask_hi = 0;
	for (i = 2; i < nb_args - 2; i++) {
		reta_idx = reta_index_arg_parse(chargv[i]);
		if (reta_idx < 0)
			return -1;
		reta_conf.reta[reta_idx] = rxq_idx;
		if (reta_idx < ETH_RSS_RETA_NUM_ENTRIES / 2)
			reta_conf.mask_lo |= (UINT64_C(1) << reta_idx);
		else
			reta_conf.mask_hi |= (UINT64_C(1) << (reta_idx - ETH_RSS_RETA_NUM_ENTRIES / 2));
	}
	diag = rte_eth_dev_rss_reta_update((uint8_t) port_idx, &reta_conf);
#endif	
	if (diag == 0)
		return 0;
	if (diag == -EINVAL)
		fpdebug_fprintf(stderr, "invalid RX queue index %s\n",
				chargv[nb_args - 1]);
	else
		rte_port_op_diag_print(chargv[0], diag);
	return -1;
}

static inline void
fpdebug_rss_reta_show_usage(const char *reason)
{
	fpdebug_fprintf(stderr, "rss-reta-show: %s\n%s\n",
			reason, FPDEBUG_RSS_RETA_SHOW_USAGE);
}

static int
fpdebug_rss_reta_show(char *tok)
{
	int nb_args;
	int port_idx;
	int reta_i;
	int reta_j;
	int diag;
	int i;

	nb_args = gettokens(tok);
	if ((nb_args < 1) || (nb_args == 2) || (nb_args > 4)) {
		fpdebug_rss_reta_show_usage("wrong nb. of arguments");
		return -1;
	}
	port_idx = port_index_arg_parse(chargv[0]);
	if (port_idx < 0)
		return -1;
	if (nb_args >= 3) {
		if (strcmp(chargv[1], "index") != 0) {
			fpdebug_rss_reta_show_usage("keyword \"index\" is"
						    " missing");
			return -1;
		}
		reta_i = reta_index_arg_parse(chargv[2]);
		if (reta_i < 0)
			return -1;
		if (nb_args == 4) {
			reta_j = reta_index_arg_parse(chargv[3]);
			if (reta_j < 0)
				return -1;
		} else
			reta_j = reta_i;
	} else {
		reta_i = 0;
		reta_j = ETH_RSS_RETA_NUM_ENTRIES - 1;
	}
#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)    
	struct rte_eth_rss_reta_entry64 reta_conf;
	reta_conf.mask = 0;
	for (i = reta_i; i < reta_j; i++) {
		reta_conf.mask |= (UINT64_C(1) << i);
	}
	diag = rte_eth_dev_rss_reta_query((uint8_t) port_idx, &reta_conf, reta_j - reta_i);

#else	
	struct rte_eth_rss_reta	reta_conf;
	reta_conf.mask_lo = 0;
	reta_conf.mask_hi = 0;
	for (i = reta_i; i <= reta_j; i++) {
		if (i < ETH_RSS_RETA_NUM_ENTRIES / 2)
			reta_conf.mask_lo |= (UINT64_C(1) << i);
		else
			reta_conf.mask_hi |= (UINT64_C(1) << (i - ETH_RSS_RETA_NUM_ENTRIES / 2));
	}
	diag = rte_eth_dev_rss_reta_query((uint8_t) port_idx, &reta_conf);
#endif

	if (diag != 0) {
		rte_port_op_diag_print(chargv[0], diag);
		return -1;
	}
	fpdebug_printf("  RX RSS indirection table (RETA) of port %d:",
		       port_idx);
	for (i = reta_i; i <= reta_j; i++) {
		if ((i - reta_i) % 8 == 0)
			fpdebug_printf("\n    %3d:", i);
		fpdebug_printf(" %d", reta_conf.reta[i]);
	}
	fpdebug_printf("\n");
	return 0;
}

#if BUILT_DPDK_VERSION >= DPDK_VERSION(1, 7, 1)
/*
 * RSS hash functions
 */
struct rss_hash_func {
	const char *hf_name;
	uint64_t hf_value;
};

#if BUILT_DPDK_VERSION > DPDK_VERSION(1,7,1)
#define ETH_RSS_IPV4_UDP ETH_RSS_NONFRAG_IPV4_UDP
#define ETH_RSS_IPV6_UDP ETH_RSS_NONFRAG_IPV6_UDP
#define ETH_RSS_IPV4_TCP ETH_RSS_NONFRAG_IPV4_UDP
#define ETH_RSS_IPV6_TCP ETH_RSS_NONFRAG_IPV6_UDP

#endif

static struct rss_hash_func rss_hash_functions[] = {
	{"ip4", ETH_RSS_IPV4},
	{"ip6", ETH_RSS_IPV6},
	{"ip6-ex", ETH_RSS_IPV6_EX},
	{"udp4", ETH_RSS_IPV4_UDP},
	{"udp6", ETH_RSS_IPV6_UDP},
	{"tcp4", ETH_RSS_IPV4_TCP},
	{"tcp6", ETH_RSS_IPV6_TCP},
	{"tcp6-ex", ETH_RSS_IPV6_TCP_EX},
	{"udp6-ex", ETH_RSS_IPV6_UDP_EX},
};

#define NB_RSS_HASH_FUNCS \
	(sizeof(rss_hash_functions) / sizeof(rss_hash_functions[0]))
#endif

static inline void
fpdebug_rss_hash_func_set_usage(void)
{
	fpdebug_fprintf(stderr, "%s\n", FPDEBUG_RSS_HASH_FUNC_SET_USAGE);
}

static int
fpdebug_rss_hash_func_set(char *tok)
{
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1, 7, 1)
	struct rte_eth_rss_conf rss_conf;
	int nb_args;
	int port_id;
	int diag;
	int i;
	unsigned int j;

	rss_conf.rss_key = NULL;
	rss_conf.rss_hf = 0;

	nb_args = gettokens(tok);
	if (nb_args < 2) {
		fpdebug_rss_hash_func_set_usage();
		return -1;
	}
	port_id = port_index_arg_parse(chargv[0]);
	if (port_id < 0)
		return -1;
	for (i = 1; i < nb_args; i++) {
		for (j = 0; j < NB_RSS_HASH_FUNCS; j++) {
			if (! strcmp(chargv[i],
				     rss_hash_functions[j].hf_name)) {
				rss_conf.rss_hf |=
					rss_hash_functions[j].hf_value;
				break;
			}
		}
		if (j == NB_RSS_HASH_FUNCS) {
			fpdebug_fprintf(stderr,
					"invalid RSS hash function name %s\n",
					chargv[i]);
			fpdebug_rss_hash_func_set_usage();
			return -1;
		}
	}
	diag = rte_eth_dev_rss_hash_update((uint8_t)port_id, &rss_conf);
	if (diag == 0)
		return 0;
	rte_port_op_diag_print(chargv[0], diag);
#endif
	return -1;
}

static inline void
fpdebug_rss_hash_func_show_usage(void)
{
	fpdebug_fprintf(stderr, "%s\n", FPDEBUG_RSS_HASH_FUNC_SHOW_USAGE);
}

static int
fpdebug_rss_hash_func_show(char *tok)
{
#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
	uint64_t rss_hf;
#else    
	uint16_t rss_hf;
#endif
	
	struct rte_eth_rss_conf rss_conf;
	int nb_args;
	int port_id;
	int diag;

	rss_conf.rss_key = NULL;
	rss_conf.rss_hf = 0;
	nb_args = gettokens(tok);
	if (nb_args != 1) {
		fpdebug_fprintf(stderr, "wrong nb. of arguments");
		fpdebug_rss_hash_func_show_usage();
		return -1;
	}
	port_id = port_index_arg_parse(chargv[0]);
	if (port_id < 0)
		return -1;
	diag = rte_eth_dev_rss_hash_conf_get((uint8_t)port_id, &rss_conf);
	if (diag != 0) {
		rte_port_op_diag_print(chargv[0], diag);
		return -1;
	}
	rss_hf = rss_conf.rss_hf;
	if (rss_hf == 0) {
		printf("RSS disabled on port %d\n", port_id);
		return 0;
	}
	printf("RSS hash functions on port %d:\n ", port_id);
	if (rss_hf & ETH_RSS_IPV4)
		printf("ip4");
	if (rss_hf & ETH_RSS_IPV4_TCP)
		printf(" tcp4");
	if (rss_hf & ETH_RSS_IPV4_UDP)
		printf(" udp4");
	if (rss_hf & ETH_RSS_IPV6)
		printf(" ip6");
	if (rss_hf & ETH_RSS_IPV6_EX)
		printf(" ip6-ex");
	if (rss_hf & ETH_RSS_IPV6_TCP)
		printf(" tcp6");
	if (rss_hf & ETH_RSS_IPV6_TCP_EX)
		printf(" tcp6-ex");
	if (rss_hf & ETH_RSS_IPV6_UDP)
		printf(" udp6");
	if (rss_hf & ETH_RSS_IPV6_UDP_EX)
		printf(" udp6-ex");
	printf("\n");

	return 0;
}

#if BUILT_DPDK_VERSION >= DPDK_VERSION(1, 7, 1)
#define RSS_HASH_KEY_LENGTH 40
static uint8_t
hexa_digit_to_value(char hexa_digit)
{
	if ((hexa_digit >= '0') && (hexa_digit <= '9'))
		return (uint8_t) (hexa_digit - '0');
	if ((hexa_digit >= 'a') && (hexa_digit <= 'f'))
		return (uint8_t) ((hexa_digit - 'a') + 10);
	if ((hexa_digit >= 'A') && (hexa_digit <= 'F'))
		return (uint8_t) ((hexa_digit - 'A') + 10);
	/* Invalid hexa digit */
	return 0xFF;
}

static uint8_t
parse_and_check_key_hexa_digit(char *key, int idx)
{
	uint8_t hexa_v;

	hexa_v = hexa_digit_to_value(key[idx]);
	if (hexa_v == 0xFF)
		fpdebug_fprintf(stderr, "invalid key: character %c at "
				"position %d is not a valid hexa digit\n",
				key[idx], idx);
	return hexa_v;
}
#endif

static inline void
fpdebug_rss_hash_key_set_usage(void)
{
	fpdebug_fprintf(stderr, "%s\n", FPDEBUG_RSS_HASH_KEY_SET_USAGE);
}

static int
fpdebug_rss_hash_key_set(char *tok)
{
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1, 7, 1)
	struct rte_eth_rss_conf rss_conf;
	uint8_t hash_key[RSS_HASH_KEY_LENGTH];
	char *key;
	uint8_t xdgt0;
	uint8_t xdgt1;
	int nb_args;
	int port_id;
	int diag;
	int i;

	nb_args = gettokens(tok);
	if (nb_args != 2) {
		fpdebug_fprintf(stderr, "wrong nb. of arguments");
		fpdebug_rss_hash_key_set_usage();
		return -1;
	}
	/* Check the length of the RSS hash key */
	key = chargv[1];
	if (strlen(key) != (RSS_HASH_KEY_LENGTH * 2)) {
		fpdebug_fprintf(stderr, "key length: %d invalid (!= %d)\n",
				(int) strlen(key), RSS_HASH_KEY_LENGTH * 2);
		fpdebug_rss_hash_key_set_usage();
		return -1;
	}
	/* Translate RSS hash key into binary representation */
	for (i = 0; i < RSS_HASH_KEY_LENGTH; i++) {
		xdgt0 = parse_and_check_key_hexa_digit(key, (i * 2));
		if (xdgt0 == 0xFF)
			return -1;
		xdgt1 = parse_and_check_key_hexa_digit(key, (i * 2) + 1);
		if (xdgt1 == 0xFF)
			return -1;
		hash_key[i]= (uint8_t) ((xdgt0 * 16) + xdgt1);
	}
	port_id = port_index_arg_parse(chargv[0]);
	if (port_id < 0)
		return -1;
	rss_conf.rss_key = NULL;
	diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (diag == 0) {
		rss_conf.rss_key = hash_key;
		diag = rte_eth_dev_rss_hash_update((uint8_t)port_id, &rss_conf);
	}
	if (diag == 0)
		return 0;
	rte_port_op_diag_print(chargv[0], diag);
#endif
	return -1;
}

static inline void
fpdebug_rss_hash_key_show_usage(void)
{
	fpdebug_fprintf(stderr, "%s\n", FPDEBUG_RSS_HASH_KEY_SHOW_USAGE);
}

static int
fpdebug_rss_hash_key_show(char *tok)
{
#if BUILT_DPDK_VERSION >= DPDK_VERSION(1, 7, 1)
	struct rte_eth_rss_conf rss_conf;
	uint8_t rss_hash_key[RSS_HASH_KEY_LENGTH];
	int nb_args;
	int port_id;
	int diag;
	unsigned int i;

	nb_args = gettokens(tok);
	if (nb_args != 1) {
		fpdebug_fprintf(stderr, "wrong nb. of arguments");
		fpdebug_rss_hash_key_show_usage();
		return -1;
	}
	port_id = port_index_arg_parse(chargv[0]);
	if (port_id < 0)
		return -1;
	rss_conf.rss_key = rss_hash_key;
	diag = rte_eth_dev_rss_hash_conf_get((uint8_t)port_id, &rss_conf);
	if (diag != 0) {
		rte_port_op_diag_print(chargv[0], diag);
		return -1;
	}
	printf("RSS hash key on port %d:\n", port_id);
	for (i = 0; i < sizeof(rss_hash_key); i++)
		printf("%02X", rss_hash_key[i]);
	printf("\n");
#endif
	return 0;
}

#else /* defined(__FastPath__) */

#define fpdebug_rss_reta_set fpdebug_send_to_fp
#define fpdebug_rss_reta_show fpdebug_send_to_fp
#define fpdebug_rss_hash_func_set fpdebug_send_to_fp
#define fpdebug_rss_hash_func_show fpdebug_send_to_fp
#define fpdebug_rss_hash_key_set fpdebug_send_to_fp
#define fpdebug_rss_hash_key_show fpdebug_send_to_fp

#endif /* !defined(__FastPath__) */

static CLI_COMMAND rss_cmds[] = {
	{ "rss-reta-set", fpdebug_rss_reta_set,
	  "Configure RSS RETA entries of a port"
	  FPDEBUG_RSS_RETA_SET_USAGE },
	{ "rss-reta-show", fpdebug_rss_reta_show,
	  "Display RSS RETA entries of a port"
	  FPDEBUG_RSS_RETA_SHOW_USAGE },
	{ "rss-hash-func-set", fpdebug_rss_hash_func_set,
	  "Set RSS hash functions of a port"
	  FPDEBUG_RSS_HASH_FUNC_SET_USAGE },
	{ "rss-hash-func-show", fpdebug_rss_hash_func_show,
	  "Display RSS hash functions of a port"
	  FPDEBUG_RSS_HASH_FUNC_SHOW_USAGE },
	{ "rss-hash-key-set", fpdebug_rss_hash_key_set,
	  "Set RSS hash key of a port"
	  FPDEBUG_RSS_HASH_KEY_SET_USAGE },
	{ "rss-hash-key-show", fpdebug_rss_hash_key_show,
	  "Display RSS hash functions of a port"
	  FPDEBUG_RSS_HASH_KEY_SHOW_USAGE },
	{ NULL, NULL, NULL },
};
static cli_cmds_t rss_cli = {
	.module = "rss",
	.c = rss_cmds,
};

static void fpdebug_rss_init(void) __attribute__ ((constructor));
void fpdebug_rss_init(void)
{
	fpdebug_add_commands(&rss_cli);
}
