#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <linux/types.h>
#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <xt_IPSECOUT.h>

static void IPSECOUT_help(void)
{
	printf("IPSECOUT v%s options:\n", XTABLES_VERSION);
}

static struct xtables_target fptun_target = {
	.family		= AF_INET,
	.name		= "IPSECOUT",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= IPSECOUT_help,
	.init		= NULL,
	.parse		= NULL,
	.print		= NULL,
	.save		= NULL,
	.extra_opts	= NULL,
};

static struct xtables_target fptun_target6 = {
	.family		= AF_INET6,
	.name		= "IPSECOUT",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= IPSECOUT_help,
	.init		= NULL,
	.parse		= NULL,
	.print		= NULL,
	.save		= NULL,
	.extra_opts	= NULL,
};

void _init(void)
{
	xtables_register_target(&fptun_target);
	xtables_register_target(&fptun_target6);
}
