/*
 * Copyright(c) 2013 6WIND
 */

#include <sys/time.h>

#include <fpn-crypto-test.h>

extern fpn_crparam_t dh_mod_exp_768[];
extern fpn_crparam_t dh_mod_exp_1024[];
extern fpn_crparam_t dh_mod_exp_1536[];
extern fpn_crparam_t dh_mod_exp_2048[];

extern fpn_crparam_t dsa_mod_exp_1024[];
extern fpn_crparam_t dsa_mod_exp_2048[];


asym_perf_test_desc_t asym_perf_tests[] = {
	{"\nNumber of queued ops (DSA MODEXP 1024)", 0, 0, 0, NULL, 0},
	{"======================================  ", 0, 0, 0, NULL, 0},
	{"1                     ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_1024, 1},
	{"4                     ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_1024, 4},
	{"16                    ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_1024, 16},
	{"64                    ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_1024, 64},
	{"256                   ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_1024, 256},

	{"\nDH Mod Exp sizes    ", 0, 0, 0, NULL, 0},
	{"================      ", 0, 0, 0, NULL, 0},
	{"DH MODEXP 768         ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dh_mod_exp_768,   DEF_OP},
	{"DH MODEXP 1024        ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dh_mod_exp_1024,  DEF_OP},
	{"DH MODEXP 1536        ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dh_mod_exp_1536,  DEF_OP},
	{"DH MODEXP 2048        ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dh_mod_exp_2048,  DEF_OP},

	{"\nDSA Mod Exp sizes   ", 0, 0, 0, NULL, 0},
	{"=================     ", 0, 0, 0, NULL, 0},
	{"DSA MODEXP 1024       ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_1024, DEF_OP},
	{"DSA MODEXP 2048       ", FPN_CRYPTO(KOPER_MOD_EXP),   3, 1, dsa_mod_exp_2048, DEF_OP},

	/* No more tests */
	{NULL, 0, 0, 0, NULL, 0},
};

int fpn_crypto_init_asym_perf_per_core(void * param);

static void asym_perf_free(
    asym_perf_test_desc_t * test,
    fpn_crparam_t         * params
)
{
	int p;

	/* Free allocated buffers */
	for (p=test->iparams ; p<test->iparams+test->oparams ; p++) {
		if (params[p].ptr) free(params[p].ptr);
	}
}

void asym_perf_callback(void * param, void * buf, int result)
{
	struct core_conf_s * conf = param;
	asym_perf_test_desc_t * test = conf->test;
	fpn_crparam_t  * params = (fpn_crparam_t *) buf;
	int res;
	int p;

	/* An error occured */
	if (result == FPN_CRYPTO(SUCCESS)) {
		/* One more packet processed */
		conf->loop_count++;

		/* Check end of test */
		if (unlikely(conf->ending)) {
			/* Free allocated buffers */
			asym_perf_free(test, params);

			conf->in_process--;

			if (conf->in_process == 0) {
				struct timeval ts;

				gettimeofday(&ts, 0);
				conf->end_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

				/* Signal master thread */
				fpn_atomic_inc(&done);
			}
		} else {
			fpn_crypto_kop_t operation;

			/* Initialize operation */
			operation.op      = test->op;
			operation.iparams = test->iparams;
			operation.oparams = test->oparams;

			/* Populate intput buffers */
			for (p=0 ; p<test->iparams ; p++) {
				operation.param[p].nbits = test->param[p].nbits;
				operation.param[p].ptr   = test->param[p].ptr;
			}

			/* Reuse previous output parameter */
			for (p=test->iparams ; p<test->iparams+test->oparams ; p++) {
				operation.param[p].nbits = test->param[p].nbits;
				operation.param[p].ptr   = params[p].ptr;
			}

			operation.opaque  = conf;
			operation.cb      = asym_perf_callback;

			/* Redo operation */
			while ((res = fpn_crypto_kinvoke(&operation)) == FPN_CRYPTO(BUSY));
			if (res != FPN_CRYPTO(SUCCESS)) {
				printf("Can not re-start asymmetric operation\n");

				/* Free allocated buffers */
				asym_perf_free(test, params);
			}
		}
	} else {
		printf("Error during asymmetric operation\n");

		/* Free allocated buffers */
		asym_perf_free(test, params);
	}
}


/* main processing loop */
int fpn_crypto_init_asym_perf_per_core(void * param)
{
	struct core_conf_s * conf = (struct core_conf_s *) param;
	asym_perf_test_desc_t * test;
	fpn_crypto_kop_t operation;
	uint32_t count;
	struct timeval ts;
	int res;
	int p;

	/* Get test from conf */
	test = conf->test;

	/* Initialize structure */
	conf->end_time    = 0;
	conf->loop_count  = 0;
	conf->ending      = 0;

	/* Initialize startup time */
	gettimeofday(&ts, 0);
	conf->start_time  = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

	/* Initialize operation */
	operation.op      = test->op;
	operation.iparams = test->iparams;
	operation.oparams = test->oparams;

	/* Copy intput buffers */
	for (p=0 ; p<test->iparams ; p++) {
		operation.param[p].nbits = test->param[p].nbits;
		operation.param[p].ptr   = test->param[p].ptr;
	}

	operation.opaque  = conf;
	operation.cb      = asym_perf_callback;

	/* Start test */
	for (count = 0 ; count<test->tx_burst; count++) {

		/* Allocate memory for output */
		for (p=test->iparams ; p<test->iparams+test->oparams ; p++) {
			operation.param[p].nbits = test->param[p].nbits;
			operation.param[p].ptr   = malloc((test->param[p].nbits + 7) / 8);
			if (operation.param[p].ptr == NULL) {
				printf("Can not allocate memory for perf test\n");

				/* Free allocated buffers */
				asym_perf_free(test, operation.param);
				return(0);
			}
		}

		/* One more buffer to process */
		conf->in_process++;

		/* Process buffer */
		while ((res = fpn_crypto_kinvoke(&operation)) == FPN_CRYPTO(BUSY));
		if (res != FPN_CRYPTO(SUCCESS)) {
			printf("Can not start asymmetric cryptography\n");

			/* Free allocated buffers */
			asym_perf_free(test, operation.param);
		}
	}

	return(0);
}

