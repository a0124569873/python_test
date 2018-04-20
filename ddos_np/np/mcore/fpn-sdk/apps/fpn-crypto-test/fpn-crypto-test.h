/*
 * Copyright(c) 2013 6WIND
 */

#include <fpn.h>
#include <fpn-crypto.h>

/* Number of sessions to open per test */
/* and number of requests to send per session */
#define DEF_SESS         4
#define DEF_REQ         16
#define DEF_OP          64

#define TEST_DURATION   10     /* 10s tests */

#define NB_MAX_INST     32
#define NB_MAX_CRYPTO   16

#define E_INVAL         1
#define E_UNSUP         2
#define E_ERR           3
#define E_UNDEF         4

typedef int (* test_init_per_core_t) (void *);

struct keys_s {
	char * cipher_key;
	char * auth_key;
	char * iv;
};

struct core_conf_s {
	void   * session[NB_MAX_INST];

	void   * test;

	test_init_per_core_t volatile init_func;

	uint64_t start_time;
	uint64_t end_time;
	uint64_t loop_count;

	uint32_t nb_inst;

	uint16_t in_process;
	uint16_t ending;
} __fpn_cache_aligned;

typedef struct sym_unit_test_desc_s {
	const char * desc;

	uint32_t cipher;
	uint32_t cipher_key_len;
	uint32_t auth;
	uint32_t auth_key_len;
	uint32_t digest_len;
	uint32_t encrypt;

	struct keys_s * keys;

	char   * source;
	char   * result;
	char   * hash;

	uint16_t data_size;
	uint16_t auth_only;

	void   * session;
	int      retval;
	int      done;

	uint8_t  flags;
} sym_unit_test_desc_t;


typedef struct sym_perf_test_desc_s {
	const char * desc;

	uint32_t cipher;
	uint32_t cipher_key_len;
	uint32_t auth;
	uint32_t auth_key_len;
	uint32_t digest_len;
	uint32_t encrypt;

	uint16_t data_size;
	uint16_t crypto_offset;
	uint16_t auth_offset;
	uint16_t iv_offset;
	uint16_t tx_burst;

	uint16_t expected_hash;
} sym_perf_test_desc_t;


typedef struct asym_unit_test_desc_s {
	const char * desc;

	int      op;
	int      iparams;
	int      oparams;

	fpn_crparam_t * param;

	int      retval;
	int      done;

	uint8_t  flags;
} asym_unit_test_desc_t;


typedef struct asym_perf_test_desc_s {
	const char * desc;

	int      op;
	int      iparams;
	int      oparams;

	fpn_crparam_t * param;

	uint16_t tx_burst;
} asym_perf_test_desc_t;


/* Lock used to synchronize tests on all cores */

extern fpn_atomic_t   done;
extern fpn_spinlock_t mutex;

/* Test index use by cores */

extern int sym_unit_tests_num;
extern int asym_unit_tests_num;
extern int unit_index;

/* IV len of symmetric tests */

extern uint32_t iv_len[];

/* Various tests descriptors */

extern  sym_unit_test_desc_t  sym_unit_tests[];
extern  sym_perf_test_desc_t  sym_perf_tests[];
extern asym_unit_test_desc_t asym_unit_tests[];
extern asym_perf_test_desc_t asym_perf_tests[];

/* Callback functions for each test type */

extern void  sym_unit_callback(void * param, void * buf, int result);
extern void  sym_perf_callback(void * param, void * buf, int result);
extern void asym_unit_callback(void * param, void * buf, int result);
extern void asym_perf_callback(void * param, void * buf, int result);

/* Initialization functions for each test type */

extern int fpn_crypto_init_sym_unit_per_core(void * param);
extern int fpn_crypto_init_sym_perf_per_core(void * param);
extern int fpn_crypto_init_asym_unit_per_core(void * param);
extern int fpn_crypto_init_asym_perf_per_core(void * param);


