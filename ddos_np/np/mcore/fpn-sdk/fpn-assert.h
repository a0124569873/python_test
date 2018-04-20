/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#ifndef _FPN_ASSERT_H_
#define _FPN_ASSERT_H_

/*
 * Stop execution at least on the current core and display a generic message
 * on the console. This function never returns.
 */

extern void fpn_abort(void) __attribute__((__noreturn__));
extern void fpn_abort_generic(void);

/*
 * Display a backtrace of function calls.
 */

extern void fpn_backtrace(void);

/*
 * Display the given format string on the console and call fpn_abort().
 */

#define fpn_panic(...) (fpn_printf(__VA_ARGS__), fpn_abort())

#ifdef CONFIG_MCORE_FPN_ASSERT_ENABLE

/*
 * Wrapper for fpn_assert_fail(). If the argument evaluates to 0, a message is
 * displayed on the console and a call to fpn_abort() is made.
 */

#define FPN_ASSERT(cond)						\
	(!!(cond) ?							\
	 (void)0 :							\
	 fpn_assert_fail(__FILE__, __LINE__, __func__, # cond))

/*
 * When called, display a message including the file name (path), the
 * current line, the current function and the condition string that produced
 * the ret value, then call fpn_abort().
 *
 * This function only exists when FPN_ASSERT_ENABLE is defined and must not
 * be called directly. Use FPN_ASSERT() instead.
 */

extern void fpn_assert_fail(const char *path, unsigned int line,
                            const char *func, const char *cond)
	__attribute__((noreturn));

#else /* CONFIG_MCORE_FPN_ASSERT_ENABLE */

#define FPN_ASSERT(cond) ((void)0)

/*
 * This macro is used as a placeholder for fpn_assert_fail() when
 * FPN_ASSERT_ENABLE is undefined.
 */

#define fpn_assert_fail(p, l, f, c) ((void)0)

#endif /* CONFIG_MCORE_FPN_ASSERT_ENABLE */

#endif /* _FPN_ASSERT_H_ */
