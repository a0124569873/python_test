/*
 * Copyright 2013 6WIND S.A.
 */

#define _GNU_SOURCE /* for getopt_long */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <inttypes.h>


#include "libfpu-crypto.h"


#define MODE_ASYM       1
#define MODE_SYM        2
#define MODE_UNIT       4
#define MODE_PERF       8

#define MODE_SYM_UNIT   (MODE_SYM|MODE_UNIT)
#define MODE_SYM_PERF   (MODE_SYM|MODE_PERF)
#define MODE_ASYM_UNIT  (MODE_ASYM|MODE_UNIT)
#define MODE_ASYM_PERF  (MODE_ASYM|MODE_PERF)

uint8_t mode;

static void
usage(const char *prog, int code)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Simple crypto API test\n\n");
	fprintf(stderr, "Usage : \n");
	fprintf(stderr, "  %s [options]\n", prog);
	fprintf(stderr,
		" -h, --help\n"
		"            show help\n");
	fprintf(stderr,
		" -A, --all\n"
		"            Do all tests\n");
	fprintf(stderr,
		" -a, --asym\n"
		"            Do asymmetric crypto test\n");
	fprintf(stderr,
		" -s, --sym\n"
		"            Do symmetric crypto test\n");
	fprintf(stderr,
		" -u, --unit\n"
		"            Do unitary crypto test\n");
	fprintf(stderr,
		" -p, --perf\n"
		"            Do performance crypto test\n");
	fprintf(stderr, "\n");
	exit(code);
}

static void
parse_args(int argc, char **argv)
{
	int ch;
	const char * prog = argv[0];
	int option_index;

	static struct option lgopts[] = {
		{"help", 0, 0, 'h'},
		{"all", 0, 0, 'A'},
		{"asym", 0, 0, 'a'},
		{"sym", 0, 0, 's'},
		{"unit", 0, 0, 'u'},
		{"perf", 0, 0, 'p'},
		{NULL, 0, 0, 0}
	};

	while ((ch = getopt_long(argc, argv,
				 "h"  /* help */
				 "A"  /* all */
				 "a"  /* asym */
				 "s"  /* sym */
				 "u"  /* unit */
				 "p"  /* perf */
				 , lgopts, &option_index)) != -1) {

		switch (ch) {
		case 'h':
			usage(prog, 0);
			break;
		case 'A':
			mode  = 0xFF;
			break;
		case 'a':
			mode |= MODE_ASYM;
			break;
		case 's':
			mode |= MODE_SYM;
			break;
		case 'u':
			mode |= MODE_UNIT;
			break;
		case 'p':
			mode |= MODE_PERF;
			break;
		default:
			fprintf(stderr, "invalid option\n");
			usage(prog, 1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		fprintf(stderr, "invalid option\n");
		usage(prog, 1);
	}
}

/* Defines */

#define TEST_CRYPTO_NB_SYM_OPS      500000
#define TEST_CRYPTO_NB_ASYM_OPS     100000

/* Symmetric AES SHA1 test data */

char key128_1[]     = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
char key_sha1[]     = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                        0x10, 0x11, 0x12, 0x13};

char iv_1[]         = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
char plain_text_3[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
char aes128_cbc_3[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};
char hmac_sha1_3[]  = { 0x2f, 0xd2, 0x88, 0xeb, 0xc8, 0xfd, 0xdb, 0xd6, 0xd9, 0x61, 0xc7, 0xf0, 0x73, 0x0f, 0x9d, 0x96,
                        0xb8, 0xae, 0xd6, 0x60};

/* Asymmetric Mod Exp test data */

char dsa_base1024[] = { 0x4d, 0xdf, 0x4c, 0x03, 0xa6, 0x91, 0x8a, 0xf5, 0x19, 0x6f, 0x50, 0x46, 0x25, 0x99, 0xe5, 0x68,
                        0x6f, 0x30, 0xe3, 0x69, 0xe1, 0xe5, 0xb3, 0x5d, 0x98, 0xbb, 0x28, 0x86, 0x48, 0xfc, 0xde, 0x99,
                        0x04, 0x3f, 0x5f, 0x88, 0x0c, 0x9c, 0x73, 0x24, 0x0d, 0x20, 0x5d, 0xb9, 0x2a, 0x9a, 0x3f, 0x18,
                        0x96, 0x27, 0xe4, 0x62, 0x87, 0xc1, 0x7b, 0x74, 0x62, 0x53, 0xfc, 0x61, 0x27, 0xa8, 0x7a, 0x91,
                        0x09, 0x9d, 0xb6, 0xf1, 0x4d, 0x9c, 0x54, 0x0f, 0x58, 0x06, 0xee, 0x49, 0x74, 0x07, 0xce, 0x55,
                        0x7e, 0x23, 0xce, 0x16, 0xf6, 0xca, 0xdc, 0x5a, 0x61, 0x01, 0x7e, 0xc9, 0x71, 0xb5, 0x4d, 0xf6,
                        0xdc, 0x34, 0x29, 0x87, 0x68, 0xf6, 0x5e, 0x20, 0x93, 0xb3, 0xdb, 0xf5, 0xe4, 0x09, 0x6c, 0x41,
                        0x17, 0x95, 0x92, 0xeb, 0x01, 0xb5, 0x73, 0xa5, 0x6a, 0x7e, 0xd8, 0x32, 0xed, 0x0e, 0x02, 0xb8};
char dsa_exp1024[]  = { 0x00, 0x00, 0x00, 0x01, 0xbd, 0x7c, 0x27, 0x0b, 0x79, 0x12, 0xfe, 0x7f, 0x10, 0x2d, 0xc1, 0x05,
                        0xe2, 0x91, 0x67, 0xdf, 0xec, 0xff, 0x4e, 0x5d};
char dsa_mod1024[]  = { 0xa7, 0x3f, 0x6e, 0x85, 0xbf, 0x41, 0x6a, 0x29, 0x7d, 0xf0, 0x9f, 0x47, 0x19, 0x30, 0x90, 0x9a,
                        0x09, 0x1d, 0xda, 0x6a, 0x33, 0x1e, 0xc5, 0x3d, 0x86, 0x96, 0xb3, 0x15, 0xe0, 0x53, 0x2e, 0x8f,
                        0xe0, 0x59, 0x82, 0x73, 0x90, 0x3e, 0x75, 0x31, 0x99, 0x47, 0x7a, 0x52, 0xfb, 0x85, 0xe4, 0xd9,
                        0xa6, 0x7b, 0x38, 0x9b, 0x68, 0x8a, 0x84, 0x9b, 0x87, 0xc6, 0x1e, 0xb5, 0x7e, 0x86, 0x4b, 0x53,
                        0x5b, 0x59, 0xcf, 0x71, 0x65, 0x19, 0x88, 0x6e, 0xce, 0x66, 0xae, 0x6b, 0x88, 0x36, 0xfb, 0xec,
                        0x28, 0xdc, 0xc2, 0xd7, 0xa5, 0xbb, 0xe5, 0x2c, 0x39, 0x26, 0x4b, 0xda, 0x9a, 0x70, 0x18, 0x95,
                        0x37, 0x95, 0x10, 0x56, 0x23, 0xf6, 0x15, 0xed, 0xba, 0x04, 0x5e, 0xde, 0x39, 0x4f, 0xfd, 0xb7,
                        0x43, 0x1f, 0xb5, 0xa4, 0x65, 0x6f, 0xcd, 0x80, 0x11, 0xe4, 0x70, 0x95, 0x5b, 0x50, 0xcd, 0x49};
char dsa_res1024[]  = { 0x05, 0xf2, 0xa0, 0x06, 0xa3, 0x5c, 0x75, 0xa2, 0xcf, 0x1b, 0xb0, 0xf7, 0xb1, 0x08, 0x4a, 0x69,
                        0x76, 0x0d, 0x1c, 0xd4, 0x8f, 0x97, 0x81, 0xe9, 0x8c, 0xa3, 0xb5, 0xfc, 0x41, 0xa1, 0xe6, 0x7d,
                        0x88, 0x91, 0x62, 0x44, 0xf2, 0x0a, 0xcd, 0x11, 0x6d, 0xd3, 0xbf, 0x0f, 0x9f, 0x2e, 0x58, 0xc1,
                        0xbe, 0x29, 0x46, 0x01, 0x3b, 0x5e, 0x1d, 0x3c, 0xa4, 0xe3, 0xb9, 0x7b, 0x8b, 0x59, 0xda, 0x6f,
                        0x50, 0x51, 0xb1, 0xae, 0x0d, 0xeb, 0x69, 0xab, 0xa3, 0x1a, 0x74, 0xf1, 0x78, 0xca, 0x3a, 0x9b,
                        0xc8, 0xf7, 0xe4, 0xe0, 0xe7, 0xb1, 0x83, 0xc0, 0x8c, 0xc3, 0x6a, 0x8a, 0x88, 0x08, 0x89, 0x97,
                        0xef, 0x85, 0x2d, 0x59, 0x86, 0xf1, 0x39, 0xbd, 0x60, 0x88, 0x9b, 0xf0, 0x4e, 0xf3, 0x13, 0xfe,
                        0xe1, 0xd2, 0x2c, 0x96, 0xe3, 0x6e, 0x1c, 0xb6, 0x08, 0x2d, 0xfe, 0x20, 0xbf, 0x84, 0xfd, 0xd8};

fpu_crparam_t dsa_mod_exp_1024[] = {
	{ .nbits=1024, .ptr=dsa_base1024},
	{ .nbits=192,  .ptr=dsa_exp1024},
	{ .nbits=1024, .ptr=dsa_mod1024},
	{ .nbits=1024, .ptr=dsa_res1024},
};

struct {
	char * name;
	uint32_t op;
	uint32_t iparams;
	uint32_t oparams;
	fpu_crparam_t * params;
} asym_perf_tests[] = {
	{ "DSA Modexp 1024				", FPU_CRYPTO_KOPER_MOD_EXP, 3, 1, dsa_mod_exp_1024 },
};

struct {
	char * name;
	uint32_t data_size;
	char * iv;
	uint32_t iv_len;
	fpu_crypto_init_t init;
} sym_perf_tests[] = {
	{ "Encryption",   0, NULL, 0, {0, 0, NULL, 0, 0, 0, NULL, 0} },
	{ "----------",   0, NULL, 0, {0, 0, NULL, 0, 0, 0, NULL, 0} },
	{ "AES128-NULL          64 bytes",   64, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_NULL, 	  0,   0, NULL,     FPU_CRYPTO_F_ENCRYPT} },
	{ "AES128-NULL         512 bytes",  512, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_NULL, 	  0,   0, NULL,     FPU_CRYPTO_F_ENCRYPT} },
	{ "AES128-NULL        1408 bytes", 1408, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_NULL, 	  0,   0, NULL,     FPU_CRYPTO_F_ENCRYPT} },
	{ "NULL-HMACSHA1-96     64 bytes",   64, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_NULL,      0, NULL,     FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, FPU_CRYPTO_F_ENCRYPT} },
	{ "NULL-HMACSHA1-96    512 bytes",  512, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_NULL,      0, NULL,     FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, FPU_CRYPTO_F_ENCRYPT} },
	{ "NULL-HMACSHA1-96   1408 bytes", 1408, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_NULL,      0, NULL,     FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, FPU_CRYPTO_F_ENCRYPT} },
	{ "AES128-HMACSHA1-96   64 bytes",   64, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, FPU_CRYPTO_F_ENCRYPT} },
	{ "AES128-HMACSHA1-96  512 bytes",  512, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, FPU_CRYPTO_F_ENCRYPT} },
	{ "AES128-HMACSHA1-96 1408 bytes", 1408, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, FPU_CRYPTO_F_ENCRYPT} },
	{ "Decryption",   0, NULL, 0, {0, 0, NULL, 0, 0, 0, NULL, 0} },
	{ "----------",   0, NULL, 0, {0, 0, NULL, 0, 0, 0, NULL, 0} },
	{ "AES128-NULL          64 bytes",   64, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_NULL, 	  0,   0, NULL,     0} },
	{ "AES128-NULL         512 bytes",  512, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_NULL, 	  0,   0, NULL,     0} },
	{ "AES128-NULL        1408 bytes", 1408, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_NULL, 	  0,   0, NULL,     0} },
	{ "NULL-HMACSHA1-96     64 bytes",   64, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_NULL,      0, NULL,     FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, 0} },
	{ "NULL-HMACSHA1-96    512 bytes",  512, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_NULL,      0, NULL,     FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, 0} },
	{ "NULL-HMACSHA1-96   1408 bytes", 1408, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_NULL,      0, NULL,     FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, 0} },
	{ "AES128-HMACSHA1-96   64 bytes",   64, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, 0} },
	{ "AES128-HMACSHA1-96  512 bytes",  512, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, 0} },
	{ "AES128-HMACSHA1-96 1408 bytes", 1408, iv_1, sizeof(iv_1), {FPU_CRYPTO_ALGO_AES_CBC, 128, key128_1, FPU_CRYPTO_AUTH_HMACSHA1, 160,  96, key_sha1, 0} },
};


static void do_sym_unit()
{
	fpu_crypto_init_t   init;
	fpu_crypto_op_t     operation;
	uint64_t            session;
	char                digest[256];
	char                result[64];
	fpu_vec_t           src_vec[1], dst_vec[1];
	fpu_buf_t           src_buf, dst_buf;
	int                 res;

	printf("\nSymmetric unit test\n");
	printf("===================\n\n");

	/* Initialize an encrypt session */
	init.enc_alg   = FPU_CRYPTO_ALGO_AES_CBC;
	init.enc_klen  = sizeof(key128_1) * 8;
	init.enc_key   = key128_1;
	init.auth_alg  = FPU_CRYPTO_AUTH_HMACSHA1;
	init.auth_klen = sizeof(key_sha1) * 8;
	init.auth_dlen = sizeof(hmac_sha1_3) * 8;
	init.auth_key  = key_sha1;
	init.flags     = FPU_CRYPTO_F_ENCRYPT;

	/* Create session */
	if ((session = fpu_crypto_session_new(&init)) == 0) {
		printf("Can not initialize session\n");
		return;
	}

	/* Setup bufs */
	src_vec[0].base         = plain_text_3;
	src_vec[0].len          = sizeof(plain_text_3);
	src_buf.vec             = src_vec;
	src_buf.veccnt          = 1;
	dst_vec[0].base         = result;
	dst_vec[0].len          = sizeof(plain_text_3);
	dst_buf.vec             = dst_vec;
	dst_buf.veccnt          = 1;

	/* Setup encrypt operation */
	operation.session       = session;
	operation.enc_iv        = iv_1;
	operation.iv_len        = sizeof(iv_1);
	operation.auth_dst      = digest;
	operation.src           = &src_buf;
	operation.enc_dst       = &dst_buf;
	operation.enc_skip      = 16;
	operation.enc_len       = sizeof(plain_text_3) - 16;
	operation.enc_inject    = 16;
	operation.auth_skip     = 0;
	operation.auth_len      = sizeof(plain_text_3);
	operation.flags         = 0;

	/* Do crypto */
	res = fpu_crypto_invoke(&operation);
	if (res < 0) {
		printf("Can not encrypt buffer\n");
		return;
	}

	/* Check result */
	if (memcmp(result, aes128_cbc_3, sizeof(aes128_cbc_3))) {
		printf("Invalid AES encryption result\n");
		return;
	}
	if (memcmp(digest, hmac_sha1_3, sizeof(hmac_sha1_3))) {
		printf("Invalid SHA1 hash result\n");
		return;
	}

	/* Close session */
	if (fpu_crypto_session_free(session) < 0) {
		printf("Can not close session\n");
		return;
	}

	printf("Encryption done\n");

	/* Initialize a decrypt session */
	init.flags = 0;

	/* Create session */
	if ((session = fpu_crypto_session_new(&init)) == 0) {
		printf("Can not initialize session\n");
		return;
	}

	/* Do in place decryption */
	operation.session       = session;
	operation.enc_iv        = iv_1;
	operation.iv_len        = sizeof(iv_1);
	operation.auth_dst      = digest;
	operation.src           = &dst_buf;
	operation.enc_dst       = &dst_buf;
	operation.enc_skip      = 16;
	operation.enc_len       = sizeof(aes128_cbc_3) - 16;
	operation.enc_inject    = 0;
	operation.auth_skip     = 0;
	operation.auth_len      = sizeof(aes128_cbc_3);
	operation.flags         = 0;

	/* Do crypto */
	res = fpu_crypto_invoke(&operation);
	if (res < 0) {
		printf("Can not decrypt buffer\n");
		return;
	}

	/* Check result */
	if (memcmp(digest, hmac_sha1_3, sizeof(hmac_sha1_3))) {
		printf("Invalid SHA1 hash result\n");
		return;
	}
	if (memcmp(result, plain_text_3, sizeof(plain_text_3))) {
		printf("Invalid AES decryption result\n");
		return;
	}

	/* Close session */
	if (fpu_crypto_session_free(session) < 0) {
		printf("Can not close session\n");
		return;
	}

	printf("Decryption done\n");
}

static void do_sym_perf(void)
{
	fpu_crypto_op_t     operation;
	fpu_vec_t           src_vec[1], dst_vec[1];
	fpu_buf_t           src_buf, dst_buf;
	struct timeval 	    ts;
	uint64_t            start_time, end_time;
	uint64_t            session;
	char                digest[256];
	char                data[65535];
	char                result[65535];
	uint32_t            test;
	int                 res;
	int                 op;

	printf("\nSymmetric performances test (op/s)\n");
	printf("==================================\n\n");

	/* Loop on tests */
	for (test=0 ; test<sizeof(sym_perf_tests)/sizeof(sym_perf_tests[0]) ; test++) {

		printf("%s", sym_perf_tests[test].name);

		/* Not a real test */
		if (sym_perf_tests[test].data_size == 0) {
			printf("\n");
			continue;
		}

		/* Create session */
		if ((session = fpu_crypto_session_new(&sym_perf_tests[test].init)) == 0) {
			printf(" : N/A\n");
			continue;
		}

		/* Get start time */
		gettimeofday(&ts, 0);
		start_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

		for (op=0 ; op<TEST_CRYPTO_NB_SYM_OPS ; op++) {
			/* Setup bufs */
			src_vec[0].base         = data;
			src_vec[0].len          = sym_perf_tests[test].data_size;
			src_buf.vec             = src_vec;
			src_buf.veccnt          = 1;
			dst_vec[0].base         = result;
			dst_vec[0].len          = sym_perf_tests[test].data_size;
			dst_buf.vec             = dst_vec;
			dst_buf.veccnt          = 1;

			/* Setup encrypt operation */
			operation.session       = session;
			operation.enc_iv        = sym_perf_tests[test].iv;
			operation.iv_len        = sym_perf_tests[test].iv_len;
			operation.auth_dst      = digest;
			operation.src           = &src_buf;
			operation.enc_dst       = &dst_buf;
			operation.enc_skip      = 0;
			operation.enc_len       = sym_perf_tests[test].data_size;
			operation.enc_inject    = 0;
			operation.auth_skip     = 0;
			operation.auth_len      = sym_perf_tests[test].data_size;
			operation.flags         = 0;

			/* Do crypto */
			res = fpu_crypto_invoke(&operation);
			if (res < 0) {
				printf(" ERROR ");
				break;
			}
		}

		/* Get end time */
		gettimeofday(&ts, 0);
		end_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

		/* Compute result */
		if (end_time - start_time) {
			printf(" : %7"PRIu64"\n", TEST_CRYPTO_NB_SYM_OPS * 1000 / (end_time - start_time));
		} else {
			printf("\n");
		}

		/* Close session */
		fpu_crypto_session_free(session);
	}
}

static void do_asym_unit()
{
	fpu_crypto_kop_t    operation;
	int                 p;
	int                 len;
	int                 res;

	printf("\nAsymmetric unit test\n");
	printf("====================\n\n");

	len = (dsa_mod_exp_1024[3].nbits + 7) / 8;

	/* Initialize operation */
	operation.op      = FPU_CRYPTO_KOPER_MOD_EXP;
	operation.flags   = 0;
	operation.iparams = 3;
	operation.oparams = 1;
	for (p=0 ; p<3 ; p++) {
		operation.param[p].nbits = dsa_mod_exp_1024[p].nbits;
		operation.param[p].ptr   = dsa_mod_exp_1024[p].ptr;
	}
	operation.param[3].nbits = dsa_mod_exp_1024[3].nbits;
	operation.param[3].ptr   = malloc(len);

	/* Do crypto operation */
	res = fpu_crypto_kinvoke(&operation);
	if (res < 0) {
		printf("Can not do mod exp\n");
		return;
	}

	/* Check result */
	if (memcmp(operation.param[3].ptr, dsa_mod_exp_1024[3].ptr, len)) {
		printf("Invalid mod exp result\n");
		return;
	}

	/* Free allocated memory */
	free(operation.param[3].ptr);

	printf("DSA modexp done\n");
}

static void do_asym_perf(void)
{
	struct timeval  ts;
	uint64_t        start_time, end_time;
	fpu_crypto_kop_t operation;
	uint32_t        test;
	uint16_t        p, q;
	int             res;
	int             op;

	printf("\nAsymmetric performances test (op/s)\n");
	printf("===================================\n\n");

	/* Loop on tests */
	for (test=0 ; test<sizeof(asym_perf_tests)/sizeof(asym_perf_tests[0]) ; test++) {

		printf("%s : ", asym_perf_tests[test].name);

		/* Setup input parameters */
		for (p=0 ; p<asym_perf_tests[test].iparams ; p++) {
			operation.param[p].nbits = asym_perf_tests[test].params[p].nbits;
			operation.param[p].ptr   = asym_perf_tests[test].params[p].ptr;
		}

		/* Allocate memory for output parameters */
		for (p=0 ; p<asym_perf_tests[test].oparams ; p++) {
			q = asym_perf_tests[test].iparams+p;
			operation.param[q].nbits = asym_perf_tests[test].params[q].nbits;
			operation.param[q].ptr   = malloc((operation.param[q].nbits + 7) / 8);
		}

		/* Get start time */
		gettimeofday(&ts, 0);
		start_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

		/* Loop on test */
		for (op=0 ; op<TEST_CRYPTO_NB_ASYM_OPS ; op++) {

			/* Initialize operation */
			operation.op      = asym_perf_tests[test].op;
			operation.iparams = asym_perf_tests[test].iparams;
			operation.oparams = asym_perf_tests[test].oparams;

			/* Do crypto operation */
			res = fpu_crypto_kinvoke(&operation);
			if (res < 0) {
				break;
			}
		}

		/* Get end time */
		gettimeofday(&ts, 0);
		end_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

		/* Compute result */
		if (end_time - start_time) {
			printf("%"PRIu64"\n", TEST_CRYPTO_NB_ASYM_OPS * 1000 / (end_time - start_time));
		} else {
			printf("N/A\n");
		}

		/* Free allocated memory */
		for (p=0 ; p<asym_perf_tests[test].oparams ; p++) {
			q = asym_perf_tests[test].iparams+p;
			free(operation.param[q].ptr);
		}
	}
}

static void do_stats()
{
	fpu_crypto_statistics_t statistics;
	int res;

	/* Get statistics */
	res = fpu_crypto_statistics(NULL, FPU_CRYPTO_ALL_CORES, &statistics);
	if (res < 0) {
		printf("Can not recover statistics\n");
		return;
	}

	printf("Crypto module statistics:\n");
	printf("\tCreated sessions                : %"PRIu64"\n", statistics.nb_session);
	printf("\tNumber of symmetric operations  : %"PRIu64"\n", statistics.nb_crypto);
	printf("\tNumber of asymmetric operations : %"PRIu64"\n", statistics.nb_kop);
	printf("\tNumber of random operations     : %"PRIu64"\n", statistics.nb_rand);
	printf("\tOut of session errors           : %"PRIu64"\n", statistics.out_of_session);
	printf("\tOut of space errors             : %"PRIu64"\n", statistics.out_of_space);
	printf("\tOut of buffer errors            : %"PRIu64"\n", statistics.out_of_buffer);
	printf("\tInternal errors                 : %"PRIu64"\n", statistics.internal_error);
	printf("\tNb polls                        : %"PRIu64"\n", statistics.nb_poll);
	printf("\tDummy polls                     : %"PRIu64"\n", statistics.dummy_poll);
	printf("\tTimed flushs                    : %"PRIu64"\n", statistics.timeout_flush);
	printf("\tBulked flushs                   : %"PRIu64"\n", statistics.bulk_flush);
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);

	if ((mode & MODE_SYM_UNIT) == MODE_SYM_UNIT) {
		do_sym_unit();
	}
	if ((mode & MODE_SYM_PERF) == MODE_SYM_PERF) {
		do_sym_perf();
	}
	if ((mode & MODE_ASYM_UNIT) == MODE_ASYM_UNIT) {
		do_asym_unit();
	}
	if ((mode & MODE_ASYM_PERF) == MODE_ASYM_PERF) {
		do_asym_perf();
	}

	do_stats();

	return 0;
}

