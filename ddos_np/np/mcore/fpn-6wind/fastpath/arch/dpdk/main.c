/*
 * Copyright(c) 2010  6WIND
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <poll.h>
#include <getopt.h>

#ifdef CONFIG_MCORE_FP_PLUGINS
#include <glob.h>
#include <dlfcn.h>
#endif

#include "fpn.h"
#include "fpn-ip.h"
#if defined(CONFIG_MCORE_FPVI_TAP)
#include "dpdk/fpn-tuntap-dpdk.h"
#endif
#include "fp-includes.h"
#include "fp-init.h"
#include "fp-main-process.h"
#include "fp-shared.h"
#include "fpdebug.h"
#include "fp-module-internal.h"
#include "fp-fork.h"

#include "fp-test-fpn0.h"

#ifdef CONFIG_MCORE_L2SWITCH
#include "fp-l2switch.h"
#endif

#ifdef CONFIG_MCORE_FPU_RPC
#include "fpu-rpc.h"
#endif

#ifdef CONFIG_MCORE_SOCKET
#include "fp-so.h"
#endif

shared_mem_t *fp_shared;

struct config_file_elt {
	FPN_STAILQ_ENTRY(config_file_elt) next;
	char *filename;
};
FPN_STAILQ_HEAD(config_file_list, config_file_elt);
static struct config_file_list config_file_list =
	FPN_STAILQ_HEAD_INITIALIZER(config_file_list);

#ifdef CONFIG_MCORE_FP_PLUGINS
struct plugin_elt {
	FPN_STAILQ_ENTRY(plugin_elt) next;
	char *filename;
	void *handle;
};
FPN_STAILQ_HEAD(plugin_list, plugin_elt);
static struct plugin_list plugin_list =
	FPN_STAILQ_HEAD_INITIALIZER(plugin_list);

/* only used when passing plugins at the moment */
static unsigned int verbose = 0;
#endif

static unsigned int foreground = 0;

/* done for each lcore */
static int init_one_lcore(__attribute__((unused)) void *arg)
{
	char thread_name[16] = { 0 };
	unsigned lcore_id = rte_lcore_id();
	printf("Init core %u\n", lcore_id);

	snprintf(thread_name, sizeof(thread_name), "fp-rte:%u", lcore_id);
	fpn_thread_setname(thread_name);

	return 0;
}

/* done once by master lcore */
static int init_global(void)
{
	void *addr;
	struct config_file_elt *cfg;
#ifdef CONFIG_MCORE_FP_PLUGINS
	struct plugin_elt *plugin;
	unsigned int i;
#endif

	addr = fp_shared_alloc();
	fp_shared = addr;
	if (addr == NULL)
		return -1;

#ifdef CONFIG_MCORE_L2SWITCH
	l2switch_shared = l2switch_shared_alloc();
#endif

	if (fp_process_init_global() < 0)
		return -1;

#ifdef CONFIG_MCORE_FP_PLUGINS
	for (i=0; i<FP_MAX_PLUGINS; i++)
		memset(fp_shared->fpplugins[i], 0, FP_PLUGINSNAME_MAXLEN);

	i = 0;
	FPN_STAILQ_FOREACH(plugin, &plugin_list, next) {
		plugin->handle = dlopen(plugin->filename, RTLD_NOW | RTLD_GLOBAL);
		if (plugin->handle == NULL) {
			fprintf(stderr, "cannot load %s: %s\n",
			        plugin->filename, dlerror());
			return -1;
		}
		if (i<FP_MAX_PLUGINS)
			memcpy(fp_shared->fpplugins[i], plugin->filename,
				FP_PLUGINSNAME_MAXLEN - 1);
		else
			fprintf(stderr,
				"%s plugin not stored for fpcmd show-loaded-plugins\n",
				plugin->filename);
		i++;
		if (verbose)
			printf("plugin %s loaded\n", plugin->filename);
#ifdef CONFIG_MCORE_FPN_HOOK
		fpn_hook_update_syms(plugin->handle);
#endif
	}

#endif

	fp_modules_init();

	FPN_STAILQ_FOREACH(cfg, &config_file_list, next) {
#ifdef CONFIG_MCORE_EMBEDDED_FPDEBUG
		if (fpdebug_load_config(cfg->filename) < 0)
			return -1;
#else
		fprintf(stderr, "Could not load config: CONFIG_MCORE_EMBEDDED_FPDEBUG is not enabled\n");
		return -1;
#endif
	}

	return 0;
}

static int start_cmdline_lcore(__attribute__((unused)) void *arg)
{
#ifdef CONFIG_MCORE_EMBEDDED_FPDEBUG
	fpdebug_interact();
#else
	printf("CONFIG_MCORE_EMBEDDED_FPDEBUG is not enabled\n");
#endif
	return 0;
}

static const fpn_mainloop_ops_t mainloop_ops = {
#ifdef CONFIG_MCORE_L2SWITCH
	.input      = fp_l2switch_input,
#else
	.input      = fp_process_input,
#endif
	.soft_input = fp_process_soft_input,
#ifdef CONFIG_MCORE_FPU_RPC
	.hook       = fpu_rpc_hook,
#endif
};

static void
usage(const char *prgname)
{
	printf("%s [EAL options] -- [FPN options] -- [-f config-file] ",
	       prgname);
#ifdef CONFIG_MCORE_SOCKET
	printf("[--nb-sockets=NB_SOCKETS] ");
#endif
	printf("\n\n");
	printf("   -F            : foreground mode (no daemon)\n");
	printf("   -f config-file: specify a fpdebug configuration file to\n"
	       "                   be applied at initialization.\n");
#ifdef CONFIG_MCORE_FP_PLUGINS
	printf("   -p plugin     : specify plugins to be loaded during init\n");
	printf("   -v            : verbose output\n");
#endif
#ifdef CONFIG_MCORE_SOCKET
	printf("   --nb-sockets: number of sockets supported by the\n"
	       "                 tcp stack.\n");
#endif
	printf("   -h            : display help\n");
}

#ifdef CONFIG_MCORE_SOCKET
/* return 0 if the integer is in [min,max] (in this case, *ret is
 * filled with the value), else -1 on error */
static int
fpn_parse_uint(const char *q_arg, unsigned min, unsigned max, int *ret,
	       unsigned base)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, base);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n < min)
		return -1;
	if (n > max)
		return -1;

	*ret = n;
	return 0;
}
#endif

#ifdef CONFIG_MCORE_FP_PLUGINS
static int
add_plugin(char *filename)
{
	struct plugin_elt *plugin = malloc(sizeof(*plugin));

	if (plugin == NULL) {
		fprintf(stderr, "cannot alloc plugin elt\n");
		return -1;
	}
	plugin->filename = strdup(filename);
	if (plugin->filename == NULL) {
		fprintf(stderr, "cannot alloc plugin name\n");
		free(plugin);
		return -1;
	}
	FPN_STAILQ_INSERT_TAIL(&plugin_list, plugin, next);
	return 0;
}
#endif

static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	struct config_file_elt *cfg;
#ifdef CONFIG_MCORE_SOCKET
	int val;
#endif

	static struct option lgopts[] = {
#ifdef CONFIG_MCORE_SOCKET
		{"nb-sockets", 1, 0, 0},
#endif

		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "hFf:p:v",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 'F':
			foreground = 1;
			break;
		/* config file */
		case 'f':
			cfg = malloc(sizeof(*cfg));
			if (cfg == NULL) {
				fprintf(stderr, "cannot alloc cfg file elt\n");
				exit(1);
			}
			cfg->filename = strdup(optarg);
			if (cfg->filename == NULL) {
				fprintf(stderr, "cannot alloc cfg file name\n");
				exit(1);
			}
			FPN_STAILQ_INSERT_TAIL(&config_file_list, cfg, next);
			break;

		/* plugins */
		case 'p':
		{
#ifdef CONFIG_MCORE_FP_PLUGINS
			glob_t gl;
			unsigned int i;

			/* use quotes so that shell won't try to expand * */
			if (optarg[0] == '\'' &&
			    optarg[strlen(optarg)-1] == '\'') {
				optarg[strlen(optarg)-1] = '\0';
				optarg++;
			}

			if (glob(optarg, 0, NULL, &gl)) {
				if (add_plugin(optarg) < 0)
					exit(1);
				continue;
			}

			for (i = 0; i < gl.gl_pathc; i++) {
				if (add_plugin(gl.gl_pathv[i]) < 0)
					exit(1);
			}

			globfree(&gl);
#else
			fprintf(stderr, "option -p %s ignored, plugins are not "
			        "supported in this version\n", optarg);
#endif
		}
			break;

#ifdef CONFIG_MCORE_FP_PLUGINS
		case 'v':
			verbose++;
			break;
#endif

		case 'h':
			usage(prgname);
			exit(0);

		/* long options */
		case 0:
#ifdef CONFIG_MCORE_SOCKET
			if (!strcmp(lgopts[option_index].name, "nb-sockets")) {
				if (fpn_parse_uint(optarg, 0, 0xffffffff,
						   &val, 10) < 0) {
					printf("invalid sockets number\n");
					usage(prgname);
					return -1;
				}
				fp_nb_sockets = val;
			}
#endif
			break;

		default:
			usage(prgname);
			exit(1);
		}
	}

	if (optind > 0)
		argv[optind-1] = prgname;

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (fp_fork() < 0)
		return -1;

	ret = fpn_sdk_init(argc, argv);
	if (ret < 0)
		return -1;
	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		return -1;

#ifdef CONFIG_MCORE_FP_PLUGINS
	{
		const char *pattern;
		glob_t gl;

		if (!(pattern = getenv("FP_PLUGINS")))
			pattern = DEFAULT_FP_PLUGINS;

		if (!glob(pattern, 0, NULL, &gl)) {
			unsigned int i;

			for (i = 0; i < gl.gl_pathc; i++) {
				if (add_plugin(gl.gl_pathv[i]) < 0)
					return -1;
			}

			globfree(&gl);
		}
	}
#endif

	/* register mainloop ops asap, so that plugins can override it */
	fpn_register_mainloop_ops(&mainloop_ops);

	/* only master from this point */
	if (init_global() < 0) {
		fprintf(stderr, "cannot initialize fast path\n");
		return -1;
	}

	/* do init per core for all 'fast path' lcores */
	fpn_job_run_oncpumask(&fpn_coremask, init_one_lcore, NULL, FPN_JOB_SKIP_MASTER);
	init_one_lcore(NULL);
	fpn_job_wait_status(&fpn_coremask, FPN_JOB_STATE_DONE, FPN_JOB_SKIP_MASTER);

	/* start particular lcores */
#if defined(CONFIG_MCORE_FPVI_TAP)
	if (fpn_exception_lcore != -1)
		fpn_job_run_oncpu(fpn_exception_lcore, start_rx_excep_lcore, NULL);
#endif
	if (fpn_cmdline_lcore != -1)
		fpn_job_run_oncpu(fpn_cmdline_lcore, start_cmdline_lcore, NULL);

	if (fpn_anti_ddos_lcore != -1)
		fpn_job_run_oncpu(fpn_anti_ddos_lcore, fpn_anti_ddos_proc, NULL);

	/* start main loop on remaining lcores */
	fpn_job_run_oncpumask(&fpn_coremask, fpn_main_loop, NULL, FPN_JOB_SKIP_NONE);

	/* always foreground if started with cmdline */
	if (foreground || fpn_cmdline_lcore != -1)
		fp_fork_finalize(FP_FORKMSG_WAIT);
	else
		fp_fork_finalize(FP_FORKMSG_SUCCESS);

	fpn_job_poll();

	return 0;
}
