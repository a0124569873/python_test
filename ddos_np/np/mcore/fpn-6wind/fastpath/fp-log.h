/*
 * Copyright(c) 2008 6WIND
 */

#ifndef __FP_LOG_H__
#define __FP_LOG_H__

#include "fp-syslog.h"

#ifdef CONFIG_MCORE_DEBUG

/*
 * With CONFIG_MCORE_DEBUG defined, if loglevel/logtype matches
 * the configuration in fp-shared then print on console
 * or send to syslog.
 */
#define FP_LOG_COND(l, t)                                            \
	(unlikely((l) <= fp_shared->debug.level &&                   \
            (t) & fp_shared->debug.type))

#else /* CONFIG_MCORE_DEBUG */

/*
 * If CONFIG_MCORE_DEBUG is not defined, only display critical logs. As the
 * loglevel is specified as a constant, the compiler won't generate
 * the code if the test is false.
 */
 #define FP_LOG_COND(l, t)                                            \
	((l) <= FP_LOG_DEFAULT)

#endif /* CONFIG_MCORE_DEBUG */

#define FP_LOG(l, t, ...)					\
	((FP_LOG_COND((l), FP_LOGTYPE_ ## t)) ?			\
	 (((fp_shared->debug.mode == FP_LOG_MODE_CONSOLE) ?	\
	   fpn_printf(# t ": " __VA_ARGS__) :			\
	   fp_syslog((l), # t ": " __VA_ARGS__)),		\
	  (void)0) :						\
	 (void)0)

/* dump a mbuf */
#define FP_LOG_MBUF(l, t, m, len)                                    \
    do {                                                             \
        if (FP_LOG_COND(l, t)) {                                     \
            m_dump((m), (len));                                      \
        }                                                            \
    } while(0)

/* user logs */
#define TRACE_USER(level, fmt, args...) do {                         \
		FP_LOG(level, USER, fmt "\n", ## args);	             \
} while(0)

#endif /* __FP_LOG_H__ */
