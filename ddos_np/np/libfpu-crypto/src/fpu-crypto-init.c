/*
 * Copyright 2013 6WIND S.A.
 * fpu-crypto - Fast Path Userland Crypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>

#include "libfpu-crypto.h"

#define FPU_CRYPTO "fpu-crypto"

extern int fpu_crypto_rpc_init();

static void fpu_crypto_usage(void)
{
	printf("\nUsage:\n"
	       "\tFPU_CRYPTO_OPT=\"-h -v\"\n"
	       "\n"
	       "\t-h (--help): display this help message\n"
	       "\t-v (--version): display the version\n"
	       "\n");
}

/*
 * Convert a string in a argc/argv format
 * Usage:
 *   argc = fpu_crypto_tokenize(&argv, command_line);
 */
static int fpu_crypto_tokenize(char **pargv[], char *cmd)
{
	char *s, *token, *saveptr;
	char **ret_argv = NULL;
	int i;

	ret_argv = malloc(sizeof(char *));
	ret_argv[0] = strdup("fpu-crypto");
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

static void
fpu_crypto_optparse(char* fpu_crypto_opt)
{
	int argc;
	char **argv;
	int fpu_crypto_nopt = 0; /* next option */

	argc = fpu_crypto_tokenize(&argv, fpu_crypto_opt);

	do {
		static const struct option fpu_crypto_lopt[] = {
			{ .name = "help", .has_arg = 0, .val = 'h'},
			{ .name = "version", .has_arg = 0, .val = 'v'},
			{ NULL, 0, NULL, 0}
		};

		fpu_crypto_nopt = getopt_long(argc, argv,
					 "h"  /* help */
					 "v"  /* version */
					 , fpu_crypto_lopt, NULL);

		switch (fpu_crypto_nopt) {
			case -1:
				break;

			case 'v':
				printf(FPU_CRYPTO" version " FPU_CRYPTO_VERSION "\n");
				exit(0);
				break;

			case 'h':
			case '?': /* getopt_long() fallback */
				fpu_crypto_usage();
				exit(0);
				break;

			default:
				fprintf(stderr, FPU_CRYPTO" getopt_long error %c\n",
					fpu_crypto_nopt);
				break;
		}
	} while (fpu_crypto_nopt != -1);

	/* reset arg vectors for the following main() */
	optarg = NULL;
	optind = 0;
	optopt = 0; /* in case of any errors */

	while (argc--) {
		free(argv[argc]);
	}
	free(argv);
}

void __attribute__((constructor))
_fpu_crypto_init(void)
{
	char *fpu_crypto_opt;

	fpu_crypto_opt = getenv("FPU_CRYPTO_OPT");
	if (fpu_crypto_opt != NULL) {
		fpu_crypto_optparse(fpu_crypto_opt);
	}
	
	/* Initialize the library */
	fpu_crypto_rpc_init();
}
