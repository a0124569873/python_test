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
 * Command to configure the link flow-control of a given port.
 */
#define FPDEBUG_LINK_FLOW_CONTROL_SET_USAGE		\
	"\n\tlink-flow-control-set Pi rx on|off tx on|off [highth h "	\
	"lowth l pause t [send-xon]]"					\
	"\n\t Pi:        the port number"				\
	"\n\t rx on/off: enable/disable reception of pause frames"	\
	"\n\t tx on/off: enable/disable transmission of pause frames"	\
	"\n\t ---- optional mandatory arguments with \"tx on\":"	\
	"\n\t highth h:  the amount \"h\" of allocated bytes in the "	\
	"NIC memory that"						\
	"\n\t            triggers the transmission of a XOFF frame"	\
	"\n\t lowth l:   the amount \"l\" of allocated bytes in the "	\
	"NIC memory that"						\
	"\n\t            triggers the transmission of a XON frame"	\
	"\n\t pause t:   the value of the pause duration, also used "	\
	"\n\t            for refresh period of the pause frame transmission" \
	"\n\t send-xon:  enable the transmission of XON frames"

#if defined(__FastPath__)
static inline void
link_flow_control_set_usage(void)
{
	fpdebug_fprintf(stderr, FPDEBUG_LINK_FLOW_CONTROL_SET_USAGE);
}

static inline int
int_arg_parse(char *arg, const char *arg_name)
{
	char *end;
	unsigned long long arg_value;

	arg_value = strtoull(arg, &end, 0);
	if (*end == 0)
		return (int) arg_value;
	fpdebug_fprintf(stderr, "argument %s: invalid value %s\n",
			arg_name, arg);
	return -1;
}

static int
on_off_arg_parse(char *arg)
{
	if (strcmp(arg, "on") == 0)
		return 1;
	if (strcmp(arg, "off") == 0)
		return 0;
	fpdebug_fprintf(stderr, "%s: invalid on|off argument\n", arg);
	return -1;
}

static int
keyword_arg_parse(char *arg, const char *keyword)
{
	if (strcmp(arg, keyword) == 0)
		return 1;
	fpdebug_fprintf(stderr,
			"argument %s != mandatory keyword %s", arg, keyword);
	return -1;
}

static void
link_flow_control_set_diag_print(int diag)
{
	fpdebug_fprintf(stderr, "link-flow-control-set: ");
	switch (diag) {
	case (-ENODEV):
		fpdebug_fprintf(stderr, "invalid port index %s", chargv[0]);
		break;
	case (-ENOTSUP):
		fpdebug_fprintf(stderr, "operation not supported by hardware");
		break;
	case (-EINVAL):
		fpdebug_fprintf(stderr, "bad parameter");
		break;
	case (-EIO):
		fpdebug_fprintf(stderr, "flow control setup failed");
		break;
	default:
		fpdebug_fprintf(stderr, "operation error. diag=%d", -diag);
		break;
	}
}

static int
fpdebug_link_flow_control_set(char *tok)
{
	struct rte_eth_fc_conf fc_conf;
	int nb_args;
	int port_id;
	int num_arg;
	int on_off;
	int diag;

	fc_conf.mode = RTE_FC_NONE;
	fc_conf.send_xon = 0;
	nb_args = gettokens(tok);
	if (nb_args < 5) {
		fpdebug_fprintf(stderr, "wrong number of arguments");
		goto bad_arg;
	}

	/*
	 * Parse mandatory arguments.
	 */
	port_id = int_arg_parse(chargv[0], "port index");
	if (port_id < 0)
		goto bad_arg;
	if (keyword_arg_parse(chargv[1], "rx") < 0)
		goto bad_arg;
	on_off = on_off_arg_parse(chargv[2]);
	if (on_off == -1)
		goto bad_arg;
	if (on_off)
		fc_conf.mode = RTE_FC_RX_PAUSE;
	if (keyword_arg_parse(chargv[3], "tx") < 0)
		goto bad_arg;
	on_off = on_off_arg_parse(chargv[4]);
	if (on_off == -1)
		goto bad_arg;
	if (on_off == 0) { /* TX pause disabled */
		if (nb_args > 5) {
			fpdebug_fprintf(stderr, "wrong number of arguments");
			goto bad_arg;
		}
		/*
		 * Must set appropriate values to TX-specific parameters
		 * to comply with coherency checks that are systematically
		 * performed by drivers.
		 */
		fc_conf.high_water = 3;
		fc_conf.low_water = 2;
		fc_conf.pause_time = 0xFFFF;
		diag = rte_eth_dev_flow_ctrl_set((uint8_t) port_id, &fc_conf);
		if (diag == 0)
			return 0;
		link_flow_control_set_diag_print(diag);
		return -1;
	}

	/* TX pause enabled. */
	if ((nb_args < 11) || (nb_args > 12)) {
		fpdebug_fprintf(stderr, "wrong number of arguments");
		goto bad_arg;
	}
	fc_conf.mode = (fc_conf.mode == RTE_FC_NONE) ?
		RTE_FC_TX_PAUSE : RTE_FC_FULL;

	/*
	 * Parse TX specific mandatory options.
	 */
	if (keyword_arg_parse(chargv[5], "highth") < 0)
		goto bad_arg;
	num_arg = int_arg_parse(chargv[6], "highth");
	if (num_arg < 0)
		goto bad_arg;
	fc_conf.high_water = (uint32_t) num_arg;

	if (keyword_arg_parse(chargv[7], "lowth") < 0)
		goto bad_arg;
	num_arg = int_arg_parse(chargv[8], "lowth");
	if (num_arg < 0)
		goto bad_arg;
	fc_conf.low_water = (uint32_t) num_arg;

	if (keyword_arg_parse(chargv[9], "pause") < 0)
		goto bad_arg;
	num_arg = int_arg_parse(chargv[10], "pause");
	if (num_arg < 0)
		goto bad_arg;
	fc_conf.pause_time = (uint16_t) num_arg;

	if (nb_args == 12) {
		if (keyword_arg_parse(chargv[11], "send-xon") < 0)
			goto bad_arg;
		fc_conf.send_xon = 1;
	}
	diag = rte_eth_dev_flow_ctrl_set((uint8_t) port_id, &fc_conf);
	if (diag == 0)
		return 0;
	link_flow_control_set_diag_print(diag);
	return -1;
bad_arg:
	link_flow_control_set_usage();
	return -1;
}

#else /* defined(__FastPath__) */

#define fpdebug_link_flow_control_set fpdebug_send_to_fp

#endif /* !defined(__FastPath__) */

static CLI_COMMAND link_flow_cmds[] = {
	{ "link-flow-control-set", fpdebug_link_flow_control_set,
	  "Configure link flow control of a port"
	  FPDEBUG_LINK_FLOW_CONTROL_SET_USAGE },
	{ NULL, NULL, NULL },
};
static cli_cmds_t link_flow_cli = {
	.module = "link_flow",
	.c = link_flow_cmds,
};

static void fpdebug_link_flow_init(void) __attribute__ ((constructor));
void fpdebug_link_flow_init(void)
{
	fpdebug_add_commands(&link_flow_cli);
}
