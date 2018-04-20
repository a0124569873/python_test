/*
 * FPU-SO - Fast Path Userland SOckets
 * Copyright 2012-2013 6WIND, All rights reserved.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <getopt.h>

#ifdef HAVE_LUA
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

#include "fpu-rpc-var.h"
#include "libfpu-so.h"
#include "fpu-so-rpc.h"

static int fpu_so_tokenize(char* *pargv[], char *line);
static void fpu_so_optparse(char *fpu_so_opt);

struct fpu_so_args fpu_so_args;

#ifdef HAVE_LUA
static char* luafile = NULL; /* LUA script to preload */
static const char* luacons = NULL; /* LUA stream console */
static lua_State *fpu_soL = NULL;
#endif

static void fpu_so_usage(void)
{
	printf("\n\nUsage:\n"
	       "\tFPU_SO_OPT=\"-h -v\"\n"
	       "\n"
	       "\t-h (--help): display this help message\n"
	       "\t-v (--version): display the version\n"
	       "\t-d 0xN (--debug): Debug mask\n"
	       "\t-D LEVEL (--loglevel): debug level when not in mask\n"
	       "\t-b (--bypass): directly calls glibc\n"
#ifdef HAVE_LUA
	       "\t-l FILE (--luafile): Default LUA configuration file\n"
	       "\t-c FILE (--luacons): Default LUA console Unix stream socket file\n"
#endif
	       "\n");
}

#ifdef HAVE_LUA
static int fpu_so_usageL(lua_State *L)
{
	int argc = lua_gettop(L);
	if (argc != 0)
		fpu_so_log(INIT, ERR, "%s: invalid argument", __func__);
	fpu_so_usage();
	return 0;
}
#endif

/*
 * Unfortunately the kernel headers do not export the TASK_COMM_LEN
 * macro.
 * So we have to define it here.
 */
#define TASK_COMM_LEN 16
#define TASKFMT "/proc/self/task/%d/comm"
#define gettid() ((pid_t)syscall(SYS_gettid))

static void
fpu_so_set_progname(const char *name)
{
	char fname[sizeof(TASKFMT) + 9];
	size_t name_len = strlen(name);
	int fd, ret;

	snprintf(fname, sizeof(fname), TASKFMT, gettid());

	fd = open(fname, O_RDWR);
	if (fd == -1) {
		fpu_so_log(WARNING, INIT, "%s\n", fname);
		return;
	}

	ret = write(fd, name, name_len);
	(void) ret; /* silent compiler warning */
	close(fd);
}

static int
fpu_so_get_progname(char *name, size_t buflen)
{
	char fname[sizeof(TASKFMT) + 9];
	int fd, n;

	if (buflen < TASK_COMM_LEN)
		return -1;

	snprintf(fname, sizeof(fname), TASKFMT, gettid());

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		fpu_so_log(WARNING, INIT, "%s\n", fname);
		return -1;
	}

	n = read(fd, name, buflen);
	close(fd);

	/* replace \n by \0 */
	if (n > 0) {
		name[n-1] = '\0';
		n--;
	}

	return n;
}

static void
fpu_so_init_progname(void)
{
	char oldname[128];
	char newname[128];

	if (fpu_so_get_progname(oldname, sizeof(oldname)) <= 0)
		return;

	snprintf(newname, sizeof(newname), "fpu-so-%s", oldname);
	fpu_so_set_progname(newname);
}


void __attribute__((constructor))
_fpu_so_init(void)
{
	const char *sofile;
	char *fpu_so_opt;

	sofile = getenv("LD_PRELOAD");
	printf(FPU_SO" init preload %s using %s\n",
	       program_invocation_short_name, sofile);

	fpu_so_opt = getenv("FPU_SO_OPT");
	if (fpu_so_opt != NULL) {
		fpu_so_opt = strdup(fpu_so_opt);
		if (fpu_so_opt == NULL) {
			fprintf(stderr, "Cannot allocate memory\n");
			exit(1);
		}
		fpu_so_optparse(fpu_so_opt);
	}

#ifdef HAVE_LUA
	if (luafile || luacons) {
		fpu_soL = lua_open();

		// XXX or luaL_loadfile(fpu_soL, luafile); lua_pcall() ???
		// TODO: manage return cases of lua_error(fpu_soL)
		luaL_openlibs(fpu_soL);

		// make fpu_so_usage() available to Lua programs
		lua_register(fpu_soL, "fpu_so_usage", fpu_so_usageL);

		if (luafile) {
			int err;

			/* run load our Lua script */
			err = luaL_dofile(fpu_soL, luafile);
			if (err) {
				error(0, EINVAL, "Error loading Lua %s", luafile);
				return;
			}
		}
		lua_getglobal(fpu_soL, "bypass");     // -4
		lua_getglobal(fpu_soL, "debug");      // -3
		lua_getglobal(fpu_soL, "loglevel");   // -2
		lua_getglobal(fpu_soL, "luacons");    // -1
		if (lua_isnumber(fpu_soL, -4))
			fpu_so_args.bypass = lua_tointeger(fpu_soL, -4);
		if (lua_isnumber(fpu_soL, -3))
			fpu_so_args.debug = lua_tointeger(fpu_soL, -3);
		if (lua_isnumber(fpu_soL, -2))
			fpu_so_args.loglevel = lua_tointeger(fpu_soL, -2);
		if (lua_isstring(fpu_soL, -1))
			luacons = lua_tostring(fpu_soL, -1);
	}
#endif /* HAVE_LUA */

	/* Initialise rpc structures before hooking */
	fpu_so_rpc_preinit();

	fpu_so_glibc_init();

	fpu_so_init_progname();

	if (fpu_so_args.bypass == 0)
		if (fpu_so_rpc_init() < 0) {
			fprintf(stderr, "initialisation has failed, please "
			        "check that fastpath has been started\n");
			exit(1);
		}
}

static void
fpu_so_optparse(char* fpu_so_opt)
{
	int argc;
	char **argv;
	int fpu_so_nopt = 0; /* next option */

	memset(&fpu_so_args, 0, sizeof(fpu_so_args));
	fpu_so_args.loglevel = FPU_SO_LOG_INFO;

	argc = fpu_so_tokenize(&argv, fpu_so_opt);

	do {
		static const struct option fpu_so_lopt[] = {
			{ .name = "help", .has_arg = 0, .val = 'h'},
			{ .name = "version", .has_arg = 0, .val = 'v'},
			{ .name = "debug", .has_arg = 1, .val = 'd'},
			{ .name = "loglevel", .has_arg = 1, .val = 'D'},
			{ .name = "bypass", .has_arg = 0, .val = 'b'},
#ifdef HAVE_LUA
			{ .name = "luafile", .has_arg = 1, .val = 'l'},
			{ .name = "luacons", .has_arg = 1, .val = 'c'},
#endif
			{ NULL, 0, NULL, 0}
		};

		fpu_so_nopt = getopt_long(argc, argv,
					 "h"  /* help */
					 "v"  /* version */
					 "d:" /* debug MASK */
					 "D:" /* loglevel */
					 "b"  /* bypass */
					 "l:" /* luafile FILE */
					 "c:" /* luacons FILE */
					 , fpu_so_lopt, NULL);

		switch (fpu_so_nopt) {
			case -1:
				break;

			case 'd':
				fpu_so_args.debug = strtoul(optarg, NULL, 0);
				break;

			case 'D':
				fpu_so_args.loglevel = strtoul(optarg, NULL, 0);
				break;

			case 'b':
				fpu_so_args.bypass = 1;
				break;

#ifdef HAVE_LUA
			case 'l':
				luafile = optarg;
				break;

			case 'c':
				luacons = optarg;
				break;
#endif /* HAVE_LUA */

			case 'v':
				printf(FPU_SO"<%s> version 0.1\n",
				       program_invocation_short_name);
				exit(0);
				break;

			case 'h':
			case '?': /* getopt_long() fallback */
				fpu_so_usage();
				exit(0);
				break;

			default:
				fprintf(stderr, FPU_SO" getopt_long error %c\n",
					fpu_so_nopt);
				break;
		}
	} while (fpu_so_nopt != -1);

	/* reset arg vectors for the following main() */
	optarg = NULL;
	optind = 0;
	optopt = 0; /* in case of any errors */

	while (argc --) {
		free(argv[argc]);
	}
	free(argv);
}

/*
 * Convert a string in a argc/argv format
 * Usage:
 *   argc = fpu_so_tokenize(&argv, command_line);
 */
static int fpu_so_tokenize(char **pargv[], char *cmd)
{
	char *s, *token, *saveptr;
	char **ret_argv = NULL;
	int i;

	ret_argv = malloc(sizeof(char *));
	ret_argv[0] = strdup("fpu-so");
	for (i = 1, s = cmd; ; i++, s = NULL) {
		token = strtok_r(s, " \n\r\t", &saveptr);
		if (token == NULL)
			break;
		ret_argv = realloc(ret_argv, sizeof(char *) * (i + 1));
		ret_argv[i] = strdup(token);
	}

	*pargv = ret_argv;
	return i;
}
