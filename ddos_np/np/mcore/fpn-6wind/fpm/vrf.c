/*
 * Copyright 2014 6WIND S.A.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fpm_vrf.h"

#include "fp.h"

static TAILQ_HEAD(handler_list, fpm_vrf_handler) handler_head;

static int fpm_vrf_delete(const uint8_t *request, const struct cp_hdr *hdr)
{
	const uint32_t vrfid = ntohl(*((const int *)request)) & FP_VRFID_MASK;
	struct fpm_vrf_handler *handler;

	if (f_verbose)
		syslog(LOG_DEBUG, "%s: vrfid: %u\n", __func__, vrfid);

	if (vrfid >= FP_MAX_VR) {
		syslog(LOG_ERR, "%s: wrong vrfid (%u) (vrfid > FP_MAX_VR (%u))",
		       __func__, vrfid, FP_MAX_VR);
		return EXIT_FAILURE;
	}

	TAILQ_FOREACH_REVERSE(handler, &handler_head, handler_list, link) {
		if (f_verbose)
			syslog(LOG_DEBUG, "%s: call %s\n", __func__,
			       handler->name);
		handler->del(vrfid);
	}

	return EXIT_SUCCESS;
}

int fpm_vrf_register(struct fpm_vrf_handler *handler)
{
	if (handler->name == NULL ||
	    handler->del == NULL)
		return -EINVAL;

	if (f_verbose)
		syslog(LOG_DEBUG, "%s: add %s\n", __func__, handler->name);

	TAILQ_INSERT_TAIL(&handler_head, handler, link);
	return 0;
}

static void fpm_vrf_init(__attribute__((unused)) int graceful)
{
	fpm_register_msg(CMD_VRF_DELETE, fpm_vrf_delete, NULL);
}

static struct fpm_mod fpm_vrf_mod = {
	.name = "vrf",
	.init = fpm_vrf_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	TAILQ_INIT(&handler_head);
	fpm_mod_register(&fpm_vrf_mod);
}
