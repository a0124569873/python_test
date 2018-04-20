/*
 * Copyright(c) 2012 6WIND
 */
#ifndef _FPN_FTRACE_
#define _FPN_FTRACE_

/*
 * fpn-ftrace allows to dynamically hook the enter/exit of the functions
 * and log these traces in a file.
 */

#define FPN_FTRACE_LOG_FILE "/tmp/fpn-ftrace.log"

#if defined(CONFIG_MCORE_VFP_FTRACE)

/* initialize the fpn-ftrace subsystem */
void fpn_ftrace_init(const char *progname);

/* add a function in the ftrace list: each time the program enters/exits
 * this function, a log is added in FPN_FTRACE_LOG_FILE. The logs between
 * the enter/exit are indented to understand the call graph easily. */
int fpn_ftrace_hook(const char *name);

/* remove a function from the ftrace list */
int fpn_ftrace_unhook(const char *name);

/* print in the log file, indented at the same level than the caller */
int fpn_ftrace_printf(const char *format, ...);

/* list all hooked functions */
void fpn_ftrace_list(void);

/* dump the current call stack */
void fpn_ftrace_callstack(void);

#else
static inline void fpn_ftrace_init(__fpn_maybe_unused const char *progname) {}
static inline int fpn_ftrace_printf(__fpn_maybe_unused const char *format, ...) { return 0; }
static inline int fpn_ftrace_hook(__fpn_maybe_unused const char *name) { return -1; }
static inline int fpn_ftrace_unhook(__fpn_maybe_unused const char *name) { return -1; }
static inline void fpn_ftrace_list(void) {}
static inline void fpn_ftrace_callstack(void) {}
#endif

#endif /* _FPN_FTRACE_ */
