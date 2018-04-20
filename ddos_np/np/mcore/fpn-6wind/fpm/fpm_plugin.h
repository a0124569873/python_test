/*
 * Copyright (c) 2014 6WIND
 */
#ifndef __FPM_PLUGIN_H__
#define __FPM_PLUGIN_H__

#include <sys/queue.h>
#include "fpc.h"

enum list_type {
	FPM_GR_CP_LIST,
	FPM_GR_SHMEM_LIST,
};

/* Graceful restart groups, deletion order follows this order */
enum fpm_cmds {
	FPM_CMD_IPSEC_SA=0,
	FPM_CMD_IPSEC_SP,
	FPM_CMD_ROUTE,
	FPM_CMD_INTERFACE_ADDR,
	FPM_CMD_L2,
	FPM_CMD_BLADE,
	FPM_CMD_TUNNEL,
	FPM_CMD_INTERFACE,
	FPM_CMD_SVTI,
	FPM_CMD_MAX
#define FPM_CMD_UNKNOWN FPM_CMD_MAX
};

typedef struct fpm_cmd {
	TAILQ_ENTRY(fpm_cmd) next;  /* Chaining */
	uint32_t cmd;               /* Command */
	uint16_t len;               /* size of data */
	enum fpm_cmds group;        /* family for ordering */
	void *data;                 /* pointer to data */

	/* Function to compare fpm_cmd structures */
	int (*comp)(const struct fpm_cmd *fpm_cmd1,
	            const struct fpm_cmd *fpm_cmd2);

	/* Function to send a reverted message to fastpath */
	int (*revert)(const struct fpm_cmd *fpm_cmd);

	/* Function used to store in a  buffer a description of the command */
	void (*display)(const struct fpm_cmd *fpm_cmd, char *buffer, int len);
} fpm_cmd_t;

typedef void (*fpm_mod_init_t)(int graceful);
typedef int (*fpm_mod_shared_cmd_t)(int gr_type, enum list_type list);

typedef int (*fpm_msg_handler_t)(const uint8_t *request,
                                 const struct cp_hdr *hdr);
typedef fpm_cmd_t *(*fpm_graceful_handler_t)(int gr_type, uint32_t cmd,
                                             const void *data);

typedef struct fpm_msg {
	SLIST_ENTRY(fpm_msg) next;
	uint32_t msgid;
	fpm_msg_handler_t handler;
	fpm_graceful_handler_t graceful;
} fpm_msg_t;

struct fpm_mod {
	char *name;
	fpm_mod_init_t init;
	fpm_mod_shared_cmd_t shared_cmd;
};

struct fpm_mod_entry {
	STAILQ_ENTRY(fpm_mod_entry) next;
	struct fpm_mod *mod;
};

STAILQ_HEAD(fpm_mod_list, fpm_mod_entry);
extern struct fpm_mod_list fpm_mod_list;

int fpm_mod_register(struct fpm_mod *mod);
struct fpm_mod_entry *fpm_mod_find(char *name);

extern int fpm_register_msg(uint32_t msgid, fpm_msg_handler_t handler,
                            fpm_graceful_handler_t graceful);

/* FPM interfaces table management functions */
typedef int (*fpm_interface_del_event_t)(uint32_t ifuid);
int fpm_interface_register_del_event(uint8_t type,
				     fpm_interface_del_event_t handler);

/* Graceful commands management functions*/
extern uint32_t fpm_graceful_restart_in_progress;
extern fpm_cmd_t *fpm_cmd_alloc(int data_size);
extern void fpm_cmd_free(fpm_cmd_t *);
extern int fpm_cmd_match_gr_type(enum fpm_cmds group, uint32_t gr_type);
extern int fpm_cmd_create_and_enqueue(enum list_type list, uint32_t cmd,
                                      const void *data);

extern char *vnb_name;
extern int fpm_wipe_vnb_nodes;

extern uint8_t spd_hash_loc_plen;
extern uint8_t spd_hash_rem_plen;
extern uint8_t spd6_hash_loc_plen;
extern uint8_t spd6_hash_rem_plen;

#endif /* __FPM_PLUGIN_H__ */
