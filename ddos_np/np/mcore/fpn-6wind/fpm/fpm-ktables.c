/**
 * Kernel table interface
 *
 */

/*-
   * Copyright (c) <2011>, 6WIND
   * All rights reserved.
   */
#include <stdlib.h>
#include "fpn.h"
#include <net/if.h>
#include "fpc.h"
#include "fpm_plugin.h"

#include <fp-ktables.h>

static int
fpm_ktables_set(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ktables *cpk = (struct cp_ktables *)request;

	fp_ktables_set(ntohl(cpk->n), cpk->table);

	return 0;
}

static void
fpm_ktables_init(__attribute__((unused)) int graceful)
{
	fpm_register_msg(CMD_KTABLES_SET, fpm_ktables_set, NULL);
}

static struct fpm_mod fpm_ktables_mod = {
	.name = "ktables",
	.init = fpm_ktables_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_ktables_mod);
}
