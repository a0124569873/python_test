/*
 * Copyright(c) 2011 6WIND
 */

/* #define FPDEBUG_DEBUG 1 */
#ifdef FPDEBUG_DEBUG
#define FPDEBUG_TRACE(fmt, args...) do { \
	fpdebug_printf("FPDEBUG: " fmt "\n", ## args); \
} while (0)
#else
#define FPDEBUG_TRACE(x...)
#endif

#define FPDEBUG_ERRX(fmt, args...) do { \
	fpdebug_printf(fmt "\n", ## args); \
	goto end; \
} while (0)

#define FPDEBUG_PARAM_ERR(msg, usage, args...) do {	\
	fpdebug_printf(msg "\n", ## args);		\
	fpdebug_printf("Usage: " usage "\n");		\
} while(0)

typedef struct {
	const char *name;
	int  (*func)(char *tok);
	const char *help;
} CLI_COMMAND;

typedef struct cli_cmds {
	FPN_STAILQ_ENTRY(cli_cmds) next;
	const char *module;
	CLI_COMMAND *c;
} cli_cmds_t;

int fpdebug_add_commands(cli_cmds_t *cmds);
int fpdebug_del_commands(const char *module);

void fpdebug_prompt(void);
int fpdebug_run_command(char *cli_input);
int fpdebug_interact(void);
void fpdebug_init(void);
int fpdebug_load_config(const char *filename);

/* post a command to an online fast path core */
int fpdebug_post_cmd(const char *string, unsigned cpu);
