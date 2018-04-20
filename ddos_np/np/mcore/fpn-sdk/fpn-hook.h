/*
 * Copyright 2013 6WIND S.A.
 */

#ifndef __FPN_HOOK_H__
#define __FPN_HOOK_H__

#ifdef CONFIG_MCORE_FPN_HOOK

#include <sys/queue.h>

/**
 * Hookable symbol descriptor
 */
typedef struct fpn_hook {
	SLIST_ENTRY(fpn_hook)   next;    /**< Next symbol in list */
	const char            * sym;     /**< Symbol name */
	void                  * ind;     /**< Location of current symbol value */
} fpn_hook_t;

/**
 * List of hookable symbols
 */
typedef SLIST_HEAD(fpn_hook_list, fpn_hook) fpn_hook_list_t;
extern fpn_hook_list_t fpn_hookable_syms;

/**
 * Hookable symbol declaration
 */
#define FPN_HOOK_DECLARE(hook) extern __typeof__(hook) *ind_ ##hook;

/**
 * Hookable symbol registration, must be called once per symbol, after
 * symbol definition.
 */
#define FPN_HOOK_REGISTER(hook) __typeof__(hook) *ind_ ##hook = hook; \
	fpn_hook_t sym_ ##hook  = { .sym = #hook, .ind = &ind_ ##hook }; \
	static __attribute__((constructor)) void constructor_ ##hook (void) \
		{ SLIST_INSERT_HEAD(&fpn_hookable_syms, &sym_ ##hook, next); }

/**
 * All hookable calls to symbol must be cast through FPN_HOOK_CALL
 */
#define FPN_HOOK_CALL(hook) ind_ ##hook

/**
 * Setup hookable symbol chain that allows a plugin to call the previous
 * implementation of the hook.
 */
#define FPN_HOOK_CHAIN(hook) \
	static __typeof__(hook) *prev_ ##hook; \
	static __attribute__((constructor)) void constructor_ ##hook (void) \
		{ prev_ ##hook = ind_ ##hook; }

/**
 * FPN_HOOK_PREV must be used to call the previous hook handler in a module.
 * FPN_HOOK_CHAIN must be first called on the specified symbol before using
 * FPN_HOOK_PREV.
 */
#define FPN_HOOK_PREV(hook) prev_ ##hook

/**
 * Update list of hookable symbols values
 *
 * This function must be used after each dynamic library load through
 * dlopen to update the values of the hookable symbols.
 *
 * @param[in] handle
 *   handle returned by dlopen on last dynamic library load.
 *
 */
extern void fpn_hook_update_syms(void *handle);

/**
 * Scan all dynamic libraries already loaded
 *
 * This function must be used to update the list of hookable symbols
 * on all automatically preloaded dynamic library.
 *
 */
extern void fpn_hook_scan_libs(void);

#else

#define FPN_HOOK_DECLARE(hook)
#define FPN_HOOK_REGISTER(hook)
#define FPN_HOOK_CALL(hook) hook
#define FPN_HOOK_CHAIN(hook)
#define FPN_HOOK_PREV(hook) hook

#endif
#endif
