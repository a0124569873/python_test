/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#include "fpn.h"
#include "fpn-assert.h"

#ifdef HAVE_GLIBC_BACKTRACE
#include <execinfo.h>
#endif

#if defined(CONFIG_MCORE_VFP_FTRACE)
void fpn_backtrace(void)
{
	fpn_ftrace_callstack();
}

#elif defined(HAVE_GLIBC_BACKTRACE)
#define BACKTRACE_MAX 20
void fpn_backtrace(void)
{
	int bt_size;
	int i;
	void *bt_buffer[BACKTRACE_MAX];
	char **bt_string;

	bt_size = backtrace(bt_buffer, BACKTRACE_MAX);
	bt_string = backtrace_symbols(bt_buffer, bt_size);
	if (bt_string != NULL) {
		for (i = 0; i < bt_size; i++)
			fpn_printf("%s\n", bt_string[i]);
		free(bt_string);
	}
}

#else /* HAVE_GLIBC_BACKTRACE */

/* Generic definition for fpn_backtrace(). It can be overridden. */

void fpn_backtrace_generic(void)
{
}

void fpn_backtrace(void) __attribute__((weak, alias("fpn_backtrace_generic")));

#endif /* HAVE_GLIBC_BACKTRACE */

/* Generic definition for fpn_abort(). It can be overridden. */

void fpn_abort_generic(void)
{
	fpn_printf("%s: abort on core %d\n", __func__, fpn_get_core_num());
	fpn_backtrace();
	while (1)
		;
}

void fpn_abort(void) __attribute__((weak, alias("fpn_abort_generic")));

#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE

void fpn_assert_fail(const char *path, unsigned int line, const char *func,
                     const char *cond)
{
	const char *i;

	/* strip leading directory names */
	for (i = path; (*i != '\0'); ++i)
		if (*i == '/')
			path = (i + 1);
	fpn_printf("%s:%d: %s: assertion `%s' failed.\n",	\
		   path, line, func, cond);
	fpn_abort();
}

#endif /* CONFIG_MCORE_FPN_ASSERT_ENABLE */

