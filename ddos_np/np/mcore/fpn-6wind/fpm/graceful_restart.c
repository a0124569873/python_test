/*
 * Copyright (c) 2008 6WIND
 */

/*
 * FPM Graceful restart mechanisms
 *
 * First list: From shared memory to command list
 * This list will contain the creation commands that would be
 * necessary to rebuilt the configuration from scratch. It will be
 * built when the gracetime is started.
 *
 * Second list: CM updates to command list
 * When we receive an update from the CM, we will add it to a list. We
 * will take into account creations and deletions.
 *
 * Diffing the two lists
 *
 * When the gracetime is over, for each fp_cmds, we will compare the
 * elements in the start list and the update list (using their id).
 *
 * If we find an element in both list, it was updated, so we don't
 * need to do anything.
 *
 * If an element is available only in the update list, it was created
 * between the stop and the restart of the daemon, we don't need to do
 * anything.
 *
 * If an element is available only in the start list, it has been
 * removed between the stop and the restart of the daemon. We remove
 * it from the shared memory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <event.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"
#include "rt_dump.h"

#define FPM_CMD_DUMP_SIZE 256

#define _PF(f) case f: str = #f ; break;

extern fpm_graceful_handler_t fpm_find_graceful_handler(uint32_t msgid);

TAILQ_HEAD(fpm_cmds_list, fpm_cmd);

struct fpm_cmds_list fpm_shmem_cmds[FPM_CMD_MAX];
struct fpm_cmds_list fpm_cp_cmds[FPM_CMD_MAX];

static void fpm_cmd_dump_cmd(fpm_cmd_t* fpm_cmd);

/* Search for a command in a fpm_cmd_table */
static fpm_cmd_t* fpm_cmd_lookup(fpm_cmd_t* fpm_cmd, struct fpm_cmds_list *fpm_cmd_list)
{
	fpm_cmd_t* cur = NULL;

	TAILQ_FOREACH(cur, fpm_cmd_list, next) {
		if ((cur->cmd == fpm_cmd->cmd) && !(cur->comp(cur, fpm_cmd))) {
			if (f_verbose)
				syslog(LOG_INFO, "already there :");
			fpm_cmd_dump_cmd(cur);
			fpm_cmd_dump_cmd(fpm_cmd);
			return cur;
		}
	}

	return cur;
}

const char *
fpm_fpmcmd_name(int fpmcmd)
{
	char *str="unknown";

	switch(fpmcmd) {
		_PF(FPM_CMD_IPSEC_SA)
		_PF(FPM_CMD_IPSEC_SP)
		_PF(FPM_CMD_ROUTE)
		_PF(FPM_CMD_INTERFACE_ADDR)
		_PF(FPM_CMD_L2)
		_PF(FPM_CMD_BLADE)
		_PF(FPM_CMD_TUNNEL)
		_PF(FPM_CMD_INTERFACE)

		default:
			break;
	}

	return str;
}

/* return true if the fpm-command is part of of this partial graceful
 * restart */
int fpm_cmd_match_gr_type(enum fpm_cmds group, u_int32_t gr_type)
{
	if (gr_type == 0)
		return 0;

	switch (group) {
	case FPM_CMD_ROUTE:
	case FPM_CMD_INTERFACE_ADDR:
	case FPM_CMD_L2:
	case FPM_CMD_BLADE:
	case FPM_CMD_TUNNEL:
	case FPM_CMD_INTERFACE:
		if (gr_type & CM_GR_TYPE_ROUTE) {
			return 1;
		}
		return 0;

	case FPM_CMD_IPSEC_SA:
	case FPM_CMD_IPSEC_SP:
		if (gr_type & CM_GR_TYPE_XFRM) {
			return 1;
		}
		return 0;
		
	default:
		return 0;
	}
	return 0;
}

/* Dump one command */
static void fpm_cmd_dump_cmd(fpm_cmd_t* fpm_cmd)
{
	char string[FPM_CMD_DUMP_SIZE];

	/* Use command handler to generate display string */
	fpm_cmd->display(fpm_cmd, string, FPM_CMD_DUMP_SIZE);

	/* Ensure string is null terminated */
	string[FPM_CMD_DUMP_SIZE-1] = 0;

	/* Display string */
	syslog(LOG_DEBUG, "%s", string);
}

/* Dump the update list and the start list */
static void fpm_cmd_dump(void)
{
	fpm_cmd_t* fpm_cmd;
	enum fpm_cmds i;

	syslog(LOG_DEBUG, "*** Dumping control plane cmds list ***\n");

	for (i = 0; i < FPM_CMD_MAX; i++) {
		if (!fpm_cmd_match_gr_type(i, fpm_graceful_restart_in_progress))
			continue;
		syslog(LOG_DEBUG, "***** %s *****\n", fpm_fpmcmd_name(i));
		TAILQ_FOREACH(fpm_cmd, &fpm_cp_cmds[i], next) {
			fpm_cmd_dump_cmd(fpm_cmd);
		}
	}

	syslog(LOG_DEBUG, "*** Dumping shared mem list ***\n");

	for (i = 0; i < FPM_CMD_MAX; i++) {
		if (!fpm_cmd_match_gr_type(i, fpm_graceful_restart_in_progress))
			continue;
		syslog(LOG_DEBUG, "***** %s *****\n", fpm_fpmcmd_name(i));
		TAILQ_FOREACH(fpm_cmd, &fpm_shmem_cmds[i], next) {
			fpm_cmd_dump_cmd(fpm_cmd);
		}
	}
}

static int fpm_cmd_default_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	return memcmp(cmd1->data, cmd2->data, cmd1->len);
}

static void fpm_cmd_default_display(const fpm_cmd_t *fpm_cmd,
                                    char *buffer, int len)
{
	char *data = fpm_cmd->data;

	if (data == NULL)
		/* Display command */
		snprintf(buffer, len, "command %d\n", fpm_cmd->cmd);
	else {
		int idx = 0, cur, data_len;

		/* Display command */
		cur = snprintf(buffer, len, "command %d data", fpm_cmd->cmd);

		/* Then display available data, limited to 32 bytes  */
		data_len = fpm_cmd->len > 32 ? 32 : fpm_cmd->len;
		while ((cur < len) && (idx < data_len)) {
			cur += snprintf(&buffer[cur], len - cur, " %2.2x", data[idx++]);
		}

		/* Add cr */
		if (cur < len) buffer[cur++] = '\n';
	}

	/* Ensure string is NULL terminated */
	buffer[len-1] = 0;
}

fpm_cmd_t *fpm_cmd_alloc(int data_size)
{
	fpm_cmd_t *fpm_cmd;

	/* Allocate command */
	fpm_cmd = calloc(1, sizeof(fpm_cmd_t));
	if (fpm_cmd == NULL) {
		syslog(LOG_ERR, "%s: can not allocate cmd memory", __FUNCTION__);
		return NULL;
	}

	/* Allocate memory for data */
	if (data_size > 0) {
		fpm_cmd->data = calloc(data_size, 1);
		if (fpm_cmd->data == NULL) {
			syslog(LOG_ERR, "%s: can not allocate data memory", __FUNCTION__);
			fpm_cmd_free(fpm_cmd);
			return NULL;
		}

		/* Store data length */
		fpm_cmd->len = data_size;
	}

	/* Set default functions */
	fpm_cmd->comp = fpm_cmd_default_comp;
	fpm_cmd->display = fpm_cmd_default_display;

	/* All is OK */
	return fpm_cmd;
}

/* Free a command and the data contained in it */
void fpm_cmd_free(fpm_cmd_t* fpm_cmd)
{
	/* Free datas */
	if (fpm_cmd->data) {
		free(fpm_cmd->data);
		fpm_cmd->data = NULL;
	}

	free(fpm_cmd);
}

/* Create a command containing data, with index cmd in the update list */
int fpm_cmd_create_and_enqueue(enum list_type list, u_int32_t cmd,
                               const void *data)
{
	fpm_cmd_t *fpm_cmd;
	struct fpm_cmds_list *fpm_cmd_table;
	fpm_graceful_handler_t graceful_handler = fpm_find_graceful_handler(cmd);

	/* Graceful restart not managed, exit */
	if (graceful_handler == NULL)
		return 0;

	/* Get translated message, or NULL if nothing to do or error */
	fpm_cmd = graceful_handler(fpm_graceful_restart_in_progress, cmd, data);
	if (fpm_cmd == NULL)
		return 0;

	/* Get table */
	fpm_cmd_table = (list == FPM_GR_CP_LIST ? fpm_cp_cmds : fpm_shmem_cmds);

	/* If we don't need to manage that kind of command, exit */
	/* or if element is already in list */
	if ((fpm_cmd->group >= FPM_CMD_MAX) ||
	    (fpm_cmd_lookup(fpm_cmd, &fpm_cmd_table[fpm_cmd->group]))) {
		fpm_cmd_free(fpm_cmd);
		return -1;
	}

	/* Add the element */
	TAILQ_INSERT_HEAD(&fpm_cmd_table[fpm_cmd->group], fpm_cmd, next);
	return 0;
}

/* Read the shared memory and make the start list with it */
void fpm_shared_mem_to_cmd(int gr_type)
{
	struct fpm_mod_entry *entry;

	STAILQ_FOREACH(entry, &fpm_mod_list, next) {
		if (entry->mod->shared_cmd != NULL)
			entry->mod->shared_cmd(gr_type, FPM_GR_SHMEM_LIST);
	}
}

/* Compare two lists of commands, and execute the commands (inverted) that are only in the start list */
void fpm_compare_lists(struct fpm_cmds_list *fpm_start, struct fpm_cmds_list *fpm_updates)
{
	fpm_cmd_t *fpm_cmd;
	fpm_cmd_t *cursor;

	/* TODO: Every N commands, do a ha check */
	while ((fpm_cmd = TAILQ_FIRST(fpm_start)) != NULL) {
		int remove = 1;
		TAILQ_FOREACH(cursor, fpm_updates, next) {
			if ((cursor->cmd == fpm_cmd->cmd) && 
			   !(fpm_cmd->comp(cursor, fpm_cmd))) {
				remove = 0;

			   	/* Remove entry from fpm_updates list, entry found can not match twice */
			   	/* This will speed up future processings on this list */
				TAILQ_REMOVE(fpm_updates, cursor, next);
				fpm_cmd_free(cursor);
				break;
			}
		}
		if (remove && (fpm_cmd->revert != NULL)) {
			if (f_verbose)
				syslog(LOG_DEBUG, "%s: removing from the system ", __FUNCTION__);
			fpm_cmd_dump_cmd(fpm_cmd);
			fpm_cmd->revert(fpm_cmd);
		}

		/* Remove entry from fpm_start list immediately */
		TAILQ_REMOVE(fpm_start, fpm_cmd, next);
		fpm_cmd_free(fpm_cmd);
	}
}

/* Compare two tables */
void fpm_compare_tables(struct fpm_cmds_list *fpm_start, struct fpm_cmds_list *fpm_updates)
{
	enum fpm_cmds i;

	/* For each command type, compare the associated lists */
	for (i = 0; i < FPM_CMD_MAX; i++) {
		if (fpm_cmd_match_gr_type(i, fpm_graceful_restart_in_progress))
			fpm_compare_lists(&fpm_start[i], &fpm_updates[i]);
	}
}

/* Free a table */
static void fpm_free_table(struct fpm_cmds_list *fpm_cmd_table)
{
	fpm_cmd_t *fpm_cmd;
	int i;

	for (i=0 ; i<FPM_CMD_MAX ; i++) {
		while ((fpm_cmd = TAILQ_FIRST(&fpm_cmd_table[i])) != NULL) {
			TAILQ_REMOVE(&fpm_cmd_table[i], fpm_cmd, next);
			fpm_cmd_free(fpm_cmd);
		}
	}
}

void fpm_graceful_timer_end(int fd,  short event, void* arg)
{
	syslog(LOG_INFO, "%s()\n", __FUNCTION__);
	fpm_cmd_dump();
	fpm_compare_tables(fpm_shmem_cmds, fpm_cp_cmds);

	fpm_graceful_restart_in_progress = 0;
	fpm_free_table(fpm_shmem_cmds);
	fpm_free_table(fpm_cp_cmds);

#ifdef CONFIG_MCORE_IPSEC
	/* Force FP to rebuild the trie */
	fp_spd_out_commit();
	fp_spd_in_commit();
#ifdef CONFIG_MCORE_IPSEC_TRIE
	fp_spd_trie_out_commit();
	fp_spd_trie_in_commit();
#endif
#endif
}

void fpm_graceful_timer_abort()
{
	syslog(LOG_INFO, "%s()\n", __FUNCTION__);
	fpm_graceful_restart_in_progress = 0;

	fpm_free_table(fpm_shmem_cmds);
	fpm_free_table(fpm_cp_cmds);
}

static int
fpm_graceful_restart_done(const uint8_t *request, const struct cp_hdr *hdr)
{
	/* if graceful restart is running, delete the timer */
	if (fpm_graceful_restart_in_progress)  {
		evtimer_del(&event_graceful_restart);

		/* Call timer end */
		fpm_graceful_timer_end(0, 0, NULL);
	}

	return 0;
}

static int
fpm_do_graceful_restart(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_graceful_restart *gr = (struct cp_graceful_restart *)request;
	uint32_t gr_type;
	uint32_t new_gr_type;
	struct timeval tv;

	gr_type = ntohl(gr->gr_type);
	syslog(LOG_INFO, "%s(type=%d)", __FUNCTION__, gr_type);

	if (gr_type & fpm_graceful_restart_in_progress) {
		syslog(LOG_WARNING, "%s(): a graceful restart of same type "
		       "is already in progress (type=%x)\n",
		       __FUNCTION__, gr_type);
	}

	/* if graceful restart is running, delete the timer */
	if (fpm_graceful_restart_in_progress) 
		evtimer_del(&event_graceful_restart);
	
	tv.tv_sec = FPM_GRACETIME;
	tv.tv_usec = 0;
	
	/* only convert from shared_mem the gr-types that are not
	 * already in progress */
	new_gr_type = gr_type & (~fpm_graceful_restart_in_progress);
	fpm_shared_mem_to_cmd(new_gr_type);
	
	/* update the state with the new graceful restart type */
	fpm_graceful_restart_in_progress |= gr_type;

	evtimer_set(&event_graceful_restart, fpm_graceful_timer_end, NULL);
	evtimer_add(&event_graceful_restart, &tv);

	return 0;
}

static void fpm_graceful_restart_init(__attribute__((unused)) int graceful)
{
	int queue;

	/* Initialize queues */
	for (queue=0 ; queue<FPM_CMD_MAX ; queue++) {
		TAILQ_INIT(&fpm_shmem_cmds[queue]);
		TAILQ_INIT(&fpm_cp_cmds[queue]);
	}

	/* Register messages */
	fpm_register_msg(CMD_GRACEFUL_RESTART, fpm_do_graceful_restart, NULL);
	fpm_register_msg(CMD_GRACEFUL_DONE, fpm_graceful_restart_done, NULL);
}

static struct fpm_mod fpm_graceful_restart_mod = {
	.name = "graceful_restart",
	.init = fpm_graceful_restart_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_graceful_restart_mod);
}
