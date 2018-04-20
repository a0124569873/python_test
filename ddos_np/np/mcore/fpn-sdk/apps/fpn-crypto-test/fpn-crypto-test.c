/*
 * Copyright(c) 2013 6WIND
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>

#include <fpn-crypto-test.h>

/* Various supported test modes */

#define TEST_SYM            0x01
#define TEST_ASYM           0x02
#define TEST_UNIT           0x04
#define TEST_PERF           0x08
#define TEST_ALL            0x0F

/* Maximum number of supported cores */
// TODO may come from FPN SDK?

#define FPN_MAX_CORE        64

uint32_t iv_len[FPN_CRYPTO(ALGO_NUM)] = {
	[FPN_CRYPTO(ALGO_DES_CBC)]   = 8,
	[FPN_CRYPTO(ALGO_3DES_CBC)]  = 8,
	[FPN_CRYPTO(ALGO_AES_CBC)]   = 16,
	[FPN_CRYPTO(ALGO_DES_ECB)]   = 0,
	[FPN_CRYPTO(ALGO_3DES_ECB)]  = 0,
	[FPN_CRYPTO(ALGO_AES_ECB)]   = 0,
	[FPN_CRYPTO(ALGO_AES_CTR)]   = 16,
	[FPN_CRYPTO(ALGO_AES_GCM)]   = 12,
	[FPN_CRYPTO(ALGO_RC4)]       = 0,
};

static struct core_conf_s core_conf[FPN_MAX_CORE];

fpn_spinlock_t mutex;
fpn_atomic_t   done;
int test_mask = 0;
int unit_index;
int master;

static void dummy(__attribute__((unused)) struct mbuf *m)
{
}

static void fpn_crypto_master(void) {
	uint32_t index;
	uint64_t nb_packets, total_time, duration;
	volatile sym_unit_test_desc_t  * sym_unit_test;
	volatile asym_unit_test_desc_t * asym_unit_test;
	sym_perf_test_desc_t  * sym_perf_test;
	asym_perf_test_desc_t * asym_perf_test;
	struct core_conf_s * conf;

	if ((test_mask & (TEST_SYM | TEST_UNIT)) == (TEST_SYM | TEST_UNIT)) {
		/* Reset unit test index */
		unit_index = 0;

		/* Set up test pointer on all running cores */
		for (index=0 ; index<fpn_get_online_core_count() ; index++) {
			core_conf[fpn_get_online_core_num(index)].init_func = fpn_crypto_init_sym_unit_per_core;
		}

		/* Wait for last test to be finished */
		sym_unit_test = &sym_unit_tests[sym_unit_tests_num-1];

		while (!sym_unit_test->done);

		/* Wait a bit to ensure that all previous tests are really done */
		/* 1 sec should be large enough for 1 operation tests */
		sleep(1);

		/* Print out results */
		printf("\n\nSymmetric unit tests results :");
		printf("\n******************************\n");
		int index = 0;
		while (index != sym_unit_tests_num) {
			const char *s;

			sym_unit_test = &sym_unit_tests[index++];

			switch (sym_unit_test->done) {
			case 0:
				s="";
				break;
			case 1:
				s=" : OK";
				break;
			case -E_INVAL:
				s=" : INVALID";
				break;
			case -E_UNSUP:
				s=" : UNSUPPORTED";
				break;
			case -E_ERR:
				s=" : CALL ERROR";
				break;
			case -E_UNDEF:
				s=" : UNDEFINED ERROR";
				break;
			default :
				s=" : UNKNOWN PROBLEM";
				break;
			}

			printf("%s%s\n", sym_unit_test->desc, s);
		}
	}

	if ((test_mask & (TEST_SYM | TEST_PERF)) == (TEST_SYM | TEST_PERF) ) {
		/* Get first test */
		sym_perf_test = &sym_perf_tests[0];

		printf("\n\nSymmetric perf tests results : Mbps [kpps]");
		printf("\n******************************************\n");
		while (sym_perf_test->desc) {
			int core;

			nb_packets = 0;
			total_time = 0;

			printf("%s", sym_perf_test->desc);

			/* No test associated to output, continue */
			if (sym_perf_test->tx_burst != 0) {
				/* Initialize sync locks */
				fpn_atomic_set(&done, 0);

				/* Set up test pointer on all running cores */
				for (index=0 ; index<fpn_get_online_core_count() ; index++) {
					core = fpn_get_online_core_num(index);

					core_conf[core].test = sym_perf_test;
					core_conf[core].init_func = fpn_crypto_init_sym_perf_per_core;
				}

				/* Wait enough time */
				sleep(TEST_DURATION);

				/* End processing on all running cores */
				for (index=0 ; index<fpn_get_online_core_count() ; index++) {
					core_conf[fpn_get_online_core_num(index)].ending = 1;
				}

				/* Wait all cores */
				while (fpn_atomic_read(&done) != (int32_t) fpn_get_online_core_count() - 1);

				/* Do statistics post processing on all running cores */
				for (index=0 ; index<fpn_get_online_core_count() ; index++) {
					if (fpn_get_online_core_num(index) == master) continue;

					conf = &core_conf[fpn_get_online_core_num(index)];

					/* Store number of packets processed */
					nb_packets  += conf->loop_count;
					total_time += conf->end_time - conf->start_time;

#ifdef PER_CORE
					printf("\nCore %d -> %5ld [%5ld]", fpn_get_online_core_num(index),
					       conf->loop_count, conf->end_time - conf->start_time);
#endif
				}

				duration = total_time / (fpn_get_online_core_count() - 1);
				if (total_time) {
					/* Display result */
					printf(" : %5"PRIu64" [%5"PRIu64"]\n",
					       nb_packets / duration * sym_perf_test->data_size * 8 / 1000,
					       nb_packets / duration);
				} else {
					printf(" : N/A\n");
				}
			} else {
				printf("\n");
			}

			/* Next test */
			fflush(stdout);
			sym_perf_test++;
		}
	}

	if ((test_mask & (TEST_ASYM | TEST_UNIT)) == (TEST_ASYM | TEST_UNIT) ) {
		/* Reset unit test index */
		unit_index = 0;

		/* Set up test pointer on all running cores */
		for (index=0 ; index<fpn_get_online_core_count() ; index++) {
			core_conf[fpn_get_online_core_num(index)].init_func = fpn_crypto_init_asym_unit_per_core;
		}

		/* Wait for last test to be finished */
		asym_unit_test = &asym_unit_tests[asym_unit_tests_num-1];

		while (!asym_unit_test->done);

		/* Wait a bit to ensure that all previous tests are really done */
		/* 1 sec should be large enough for 1 operation tests */
		sleep(1);

		/* Print out results */
		printf("\n\nAsymmetric unit tests results :");
		printf("\n*******************************\n");
		int index = 0;
		while (index != asym_unit_tests_num) {
			const char *s;

			asym_unit_test = &asym_unit_tests[index++];

			switch (asym_unit_test->done) {
			case 0:
				s="";
				break;
			case 1:
				s=" : OK";
				break;
			case -E_INVAL:
				s=" : INVALID";
				break;
			case -E_UNSUP:
				s=" : UNSUPPORTED";
				break;
			case -E_ERR:
				s=" : CALL ERROR";
				break;
			case -E_UNDEF:
				s=" : UNDEFINED ERROR";
				break;
			default :
				s=" : UNKNOWN PROBLEM";
				break;
			}

			printf("%s%s\n", asym_unit_test->desc, s);
		}
	}

	if ((test_mask & (TEST_ASYM | TEST_PERF)) == (TEST_ASYM | TEST_PERF) ) {
		/* Get first test */
		asym_perf_test = &asym_perf_tests[0];

		printf("\n\nAsymmetric perf tests results : ops");
		printf("\n***********************************\n");
		while (asym_perf_test->desc) {
			int core;

			nb_packets = 0;
			total_time = 0;

			printf("%s", asym_perf_test->desc);

			/* No test associated to output, continue */
			if (asym_perf_test->tx_burst != 0) {
				/* Initialize sync locks */
				fpn_atomic_set(&done, 0);

				/* Set up test pointer on all running cores */
				for (index=0 ; index<fpn_get_online_core_count() ; index++) {
					core = fpn_get_online_core_num(index);

					core_conf[core].test = asym_perf_test;
					core_conf[core].init_func = fpn_crypto_init_asym_perf_per_core;
				}

				/* Wait enough time */
				sleep(TEST_DURATION);

				/* End processing on all running cores */
				for (index=0 ; index<fpn_get_online_core_count() ; index++) {
					core_conf[fpn_get_online_core_num(index)].ending = 1;
				}

				/* Wait all cores */
				while (fpn_atomic_read(&done) != (int32_t) fpn_get_online_core_count() - 1);

				/* Do statistics post processing on all running cores */
				for (index=0 ; index<fpn_get_online_core_count() ; index++) {
					if (fpn_get_online_core_num(index) == master) continue;

					conf = &core_conf[fpn_get_online_core_num(index)];

					/* Store number of packets processed */
					nb_packets  += conf->loop_count;
					total_time += conf->end_time - conf->start_time;

#ifdef PER_CORE
					printf("\nCore %d -> %5ld [%5ld]", fpn_get_online_core_num(index),
					       conf->loop_count, conf->end_time - conf->start_time);
#endif
				}

				duration = total_time / (fpn_get_online_core_count() - 1);
				if (total_time) {
					/* Display result */
					printf(" : %7"PRIu64"\n", nb_packets * 1000 / duration);
				} else {
					printf(" : N/A\n");
				}
			} else {
				printf("\n");
			}

			/* Next test */
			fflush(stdout);
			asym_perf_test++;
		}
	}
}

static int fpn_crypto_loop(void)
{
	int cpu = fpn_get_core_num();
	struct core_conf_s * conf = &core_conf[cpu];

	/* Master CPU is only here for polling */
	if (cpu == master) {
		/* Run master loop */
		fpn_crypto_master();
		
		/* Exit from test program */
		exit(0);
	}

	/* If a new test need to be initialized */
	if (conf->init_func != NULL) {
		/* Call new test initialization function */
		conf->init_func(conf);

		/* Reset function pointer */
		conf->init_func = NULL;

		return(1);
	}

	return(0);
}


static const fpn_mainloop_ops_t mainloop_ops = {
	.input      = dummy,
	.soft_input = dummy,
	.hook       = fpn_crypto_loop,
};


int main(int argc, char **argv)
{
	/* Initialize mutex locks */
	fpn_spinlock_init(&mutex);

	/* Parse sample parameters (end of params list) */
	while (argc) {
		if (!strcmp(argv[argc-1], "--all")) {
			test_mask = TEST_ALL;
		} else if (!strcmp(argv[argc-1], "--sym")) {
			test_mask |= TEST_SYM;
		} else if (!strcmp(argv[argc-1], "--asym")) {
			test_mask |= TEST_ASYM;
		} else if (!strcmp(argv[argc-1], "--unit")) {
			test_mask |= TEST_UNIT;
		} else if (!strcmp(argv[argc-1], "--perf")) {
			test_mask |= TEST_PERF;
		} else break;

		/* Go to previous argument */
		argc--;
	}

	/* Default tests : all */
	if (test_mask == 0) test_mask = TEST_ALL;
	if ((test_mask & (TEST_SYM  | TEST_ASYM)) == 0) test_mask |= (TEST_SYM  | TEST_ASYM);
	if ((test_mask & (TEST_UNIT | TEST_PERF)) == 0) test_mask |= (TEST_UNIT | TEST_PERF);

	/* Register loop ops */
	fpn_register_mainloop_ops(&mainloop_ops);

	/* Initialize SDK */
	if (fpn_sdk_init(argc, argv) < 0) {
		printf("Can not initialize FPN SDK\n");
		return(-1);
	}

	/* Get master cpu */
	master = fpn_get_core_num();
	printf("Master CPU %d\n", master);

	/* start main loop */
	fpn_job_run_oncpumask(&fpn_coremask, fpn_main_loop, NULL, FPN_JOB_SKIP_NONE);
	fpn_job_poll();

	return(0);
}
