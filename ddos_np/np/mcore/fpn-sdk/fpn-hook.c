/*
 * Copyright 2014 6WIND S.A.
 */

#define _GNU_SOURCE /* for dl_iterate_phdr */

#include "fpn.h"
#include "fpn-hook.h"

#include <stdlib.h>
#include <link.h>
#include <dlfcn.h>

/* List of hookable symbols */
fpn_hook_list_t fpn_hookable_syms;

/**
 * This function is the callback provided to dl_iterate_phdr.
 * For each dynamic library descriptor already loaded, we update
 * the symbols location of our hookable symbols.
 */
static int fpn_hook_dl_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	(void) size;
	(void) data;

	if ((info->dlpi_name != NULL) &&
		(info->dlpi_name[0] != 0)) {
		void *handle;

		/* Get dlopen handle, no new handle is created, it is the one already created for first dlopen */
		handle = dlopen(info->dlpi_name, RTLD_LAZY|RTLD_NOLOAD);

		/* Update hooks symbols */
		fpn_hook_update_syms(handle);
	}

	return 0;
}

/**
 * Update list of symbols after a dlopen.
 */
void fpn_hook_update_syms(void *handle)
{
	fpn_hook_t *hook;

	/* Nothing to do if no handle specified */
	if (handle == NULL)
		return;

	/* Get all hookable symbols location in last dynamic module */
	SLIST_FOREACH(hook, &fpn_hookable_syms, next) {
		void *sym = dlsym(handle, hook->sym);

		/* overwrite current location if found */
		if (sym != NULL)
			* (void **) hook->ind = sym;
	}
}

/**
 * Update list of symbols for all already loaded dynamic modules.
 */
void fpn_hook_scan_libs(void)
{
	dl_iterate_phdr(fpn_hook_dl_callback, NULL);
}

