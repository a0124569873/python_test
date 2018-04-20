/*
 * Copyright 6WIND, All rights reserved.
 */

#ifndef FPU_SO_H
#define FPU_SO_H

#define FPU_SO "fpu-so"

struct fpu_so_args {
#define FPU_SO_LOG_INIT     0x0001
#define FPU_SO_LOG_GLIBC    0x0002
#define FPU_SO_LOG_RPC      0x0004
#define FPU_SO_LOG_EPOLL    0x0008
#define FPU_SO_LOG_ALL      0xffff
	int debug;

#define FPU_SO_LOG_ERR     0 /* error conditions */
#define FPU_SO_LOG_WARNING 1 /* warning conditions */
#define FPU_SO_LOG_INFO    2 /* informational message */
#define FPU_SO_LOG_DEBUG   3 /* debug-level message */
	int loglevel;

	/* don't use fastpath, directly calls glibc */
	int bypass;
};

extern struct fpu_so_args fpu_so_args;
extern struct fpu_rpc_fp_shmem *fp_shmem;
extern __thread struct fpu_rpc_app_shmem *app_shmem;
extern __thread int unix_sock;

/* debug fast path to libfpu-so messages */
#define fpu_so_log(level, type, fmt, args...)			\
	if (FPU_SO_LOG_##level <= fpu_so_args.loglevel ||	\
	    fpu_so_args.debug & FPU_SO_LOG_##type)		\
		fprintf(stderr, FPU_SO " " #level " " #type	\
			" %s:%d " fmt, __func__,		\
			 __LINE__, ## args)

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

extern void fpu_so_glibc_init(void);

#endif /* FPU_SO_H */
