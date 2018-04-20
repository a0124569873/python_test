/*
 * Copyright (c) 2006 6WIND
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/queue.h>

#include "fpm_plugin.h"
#include "fpm_common.h"

#include "fp-jhash.h"

/* fpm_dispatch:
 * This function calls appropriate module APIs based on the msg
 * type received from CM. The sequence number, which is a unique
 * id passed by CM, is passed to the corresponding FPM modules.
 * The FPM uses this unique number as the correlator.
 */
#include "fp.h"
#ifdef CONFIG_MCORE_TAP_BPF
#include "fp-bpf.h"
#endif

#define FPM_MAX_MSG 2048
#define FPM_MSG_HASH_SIZE 2048
#define FPM_MSG_HASH_MASK (FPM_MSG_HASH_SIZE - 1)

/* msg table */
fpm_msg_t fpm_msg_table[FPM_MAX_MSG];

SLIST_HEAD(fpm_msg_list, fpm_msg);

/* msg hash table */
struct fpm_msg_list fpm_msg_list[FPM_MSG_HASH_SIZE];

/* calculate a hash value from the msg id */
static inline uint32_t fpm_msg_to_hash(uint32_t msgid)
{
	return fp_jhash_1word(msgid) & FPM_MSG_HASH_MASK;
}

/* retrieve msg handler by id */
static inline fpm_msg_handler_t fpm_find_msg_handler(uint32_t msgid)
{
	uint32_t h;
	fpm_msg_t *msg;

	h = fpm_msg_to_hash(msgid);

	SLIST_FOREACH (msg, &fpm_msg_list[h], next) {
		if (msg->msgid == msgid)
			return msg->handler;
	}

	return NULL;
}

/* retrieve graceful handler by id */
fpm_graceful_handler_t fpm_find_graceful_handler(uint32_t msgid)
{
	uint32_t h;
	fpm_msg_t *msg;

	h = fpm_msg_to_hash(msgid);

	SLIST_FOREACH (msg, &fpm_msg_list[h], next) {
		if (msg->msgid == msgid)
			return msg->graceful;
	}

	return NULL;
}

/* register a fpm message id associated with a handler callback */
int fpm_register_msg(uint32_t msgid, fpm_msg_handler_t handler, fpm_graceful_handler_t graceful)
{
	static uint32_t next_idx = 0;

	if (handler == NULL) {
		syslog(LOG_ERR, "cannot register command type %08X:"
		       " handler function is null\n", msgid);
		return 1;
	}

	if (next_idx == FPM_MAX_MSG) {
		syslog(LOG_ERR, "cannot register command type %08X:"
		       " no more commands available\n", msgid);
		return 1;
	}

	if (fpm_find_msg_handler(msgid) != NULL)
		syslog(LOG_WARNING, "overriding command type %08X\n", msgid);

	fpm_msg_t *msg = &fpm_msg_table[next_idx];
	msg->msgid = msgid;
	msg->handler = handler;
	msg->graceful = graceful;

	uint32_t h = fpm_msg_to_hash(msgid);

	/* insert msg into hash table */
	SLIST_INSERT_HEAD(&fpm_msg_list[h], msg, next);

	next_idx++;

	return 0;
}

int
fpm_dispatch(const struct cp_hdr *hdr, const uint8_t *req)
{
	uint32_t msgid = ntohl(hdr->cphdr_type);
	fpm_msg_handler_t msg_handler;

#ifdef HA_SUPPORT
	fpm_ha_check_request();
#endif

	/* Add all the commands to the updates list when graceful
	 * restart is in progress. This depends on the protocol being
	 * "graceful-restarted". */
	if (fpm_graceful_restart_in_progress != 0)
		fpm_cmd_create_and_enqueue(FPM_GR_CP_LIST, msgid, req);

	/* now process the command */

	if ((msg_handler = fpm_find_msg_handler(msgid)) != NULL)
		return msg_handler(req, hdr);

	if (f_verbose)
		syslog(LOG_DEBUG,
		       "WARNING: command type %08X not implemented yet\n",
		       msgid);

	return -1;
}
