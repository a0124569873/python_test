/*
 * Copyright(c) 2008 6WIND
 */
#include "fpn.h"
#include "fp-test-fpn0.h"
#include "fp-includes.h"
#include "netinet/fp-icmp.h"
#include "netipsec/fp-esp.h"
#include "fpn-cksum.h"
#ifdef CONFIG_MCORE_IP_REASS
#include "fp-reass.h"
#endif
#if (defined CONFIG_MCORE_FPN_CRYPTO) && (! defined CONFIG_MCORE_FPN_CRYPTO_ASYNC)
#define FP_TEST_FPN0_CRYPTO_SUPPORT 1
#endif
#ifdef CONFIG_MCORE_FPN_CRYPTO
#include "fpn-crypto.h"
#endif

#include "fpn-ring.h"
#include "fpn-mempool.h"
#include "fpn-ringpool.h"
#include "fpn-ringqueue.h"
#ifdef CONFIG_MCORE_AATREE
#include "fpn-aatree.h"
#endif
#ifdef CONFIG_MCORE_TIMER_GENERIC
#include "timer/fpn-timer-test.h"
#endif

#define TEST_FPN0_MBUF_SIZE     8192 /* BUFSIZ may be too small */
static char glb_buf[FPN_MAX_CORES][TEST_FPN0_MBUF_SIZE];

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

#ifndef DES_BLOCK_SIZE
#define DES_BLOCK_SIZE 8
#endif

static FPN_DEFINE_SHARED(fp_test_fpn0_handler_t *,
                         fp_test_fpn0_handlers[TEST_FPN0_MAX]);

struct t_fpn0_usage {
	int val;               /* number of test */
	const char *comment;   /* description of the test */
};

static const struct t_fpn0_usage fpn0_usage[] = {
	{ .val = 0, .comment = "Unknown", },
	{ .val = TEST_FPN0_REPLY_ONLY,            .comment = "Check fpn0 replies", },
	{ .val = TEST_FPN0_MBUF_AUDIT,            .comment = "MBUF Audit", },
	{ .val = TEST_FPN0_DO_MEMTEST,            .comment = "MemTest", },
	{ .val = TEST_FPN0_CKSUM_AUDIT,           .comment = "Cksum Audit", },
	{ .val = TEST_FPN0_EQOS_STATS,            .comment = "OCTEON: EQoS Stats", },
	{ .val = TEST_FPN0_REASS_INFO,            .comment = "Reassembly Info", },
	{ .val = TEST_FPN0_CHECK_SIZE,            .comment = "Check Shared Mem Size", },
	{ .val = TEST_FPN0_CRYPTO_AUDIT,          .comment = "Check Synchronous Crypto", },
	{ .val = TEST_FPN0_MTAG_AUDIT,            .comment = "Check MTAG API", },
	{ .val = TEST_FPN0_TIMERS_ACCURACY,       .comment = "Check Timer Accuracy", },
	{ .val = TEST_FPN0_TIMERS_CALLOUT,        .comment = "Check Timer Callout (Cavium)", },
	{ .val = TEST_FPN0_TIMERS_STRESS_RESET,   .comment = "Reset timers", },
	{ .val = TEST_FPN0_TIMER_CALLOUTS_CHECK,  .comment = "Timer callouts check", },
	{ .val = TEST_FPN0_LOCK_AUDIT,            .comment = "Check Lock API", },
	{ .val = TEST_FPN0_POOL_DUMP,             .comment = "Dump Pool", },
	{ .val = TEST_FPN0_TIMERS_FREE_CALLLOUT,  .comment = "Check Timers Free Callout", },
	{ .val = TEST_FPN0_GET_LOCAL_CYCLES,      .comment = "Test FP Get Local Cycle", },
	{ .val = TEST_FPN0_MEMPOOL,               .comment = "Show Mempool", },
	{ .val = TEST_FPN0_RING,                  .comment = "Test Ring", },
	{ .val = TEST_FPN0_RINGPOOL,              .comment = "Test RingPool", },
	{ .val = TEST_FPN0_RINGQUEUE,             .comment = "Test RingQueue", },
	{ .val = TEST_FPN0_TIMERS_BIND,           .comment = "Test callout_bind function", },
	{ .val = TEST_FPN0_SHMEM_CONF,            .comment = "Show FP shared memory", },
	{ .val = TEST_FPN0_AATREE,                .comment = "Test AA Tree", },
	{ .val = TEST_FPN0_TIMERS_SCALABILITY,    .comment = "Test Timers scalability", },
	{ .val = TEST_FPN0_DEBUG_LOCK_LOG_DUMP,   .comment = "Dump last lock debug logs", },
	{ .val = TEST_FPN0_FPNMALLOC,             .comment = "Display memory available by fpn-malloc", },
	{ .val = TEST_FPN0_SPINLOCK,              .comment = "Estimate cost of spinlocks", },
	{ .val = TEST_FPN0_XLP_DEBUG_MBUF,        .comment = "XLP: Debug MBUF", },
	{ .val = TEST_FPN0_XLP_MAX_MBUF,          .comment = "XLP: Test to allocate maximum of mbufs", },
	{ .val = TEST_FPN0_CRYPTO_STAT,           .comment = "DPDK: Crypto engine statistics", },
	{ .val = TEST_FPN0_NIC_STATS,             .comment = "XLP: dump freein descriptor counters", },
	{ .val = TEST_FPN0_CPUMASK,               .comment = "Test Cpumask", },
	{ .val = 0, .comment = "Unknown", },
};

int fp_test_fpn0_register(uint8_t id, fp_test_fpn0_handler_t *handler)
{
	if (id < 2 || fp_test_fpn0_handlers[id] || !handler ||
	    !handler->func || !handler->comment)
		return 1;

	fp_test_fpn0_handlers[id] = handler;

	return 0;
}

static void
show_fpn0_usage(void)
{
	int i = 1;

	fpn_printf("\nUsage: autotest <num test>\n");
	while (fpn0_usage[i].val != 0) {
		fpn_printf("%3d => %s\n", fpn0_usage[i].val, fpn0_usage[i].comment);
		i++;
	}

	for (i=1; i < TEST_FPN0_MAX; i++)
		if (fp_test_fpn0_handlers[i])
			fpn_printf("%3d => %s\n",
			           i,
			           fp_test_fpn0_handlers[i]->comment?
			           fp_test_fpn0_handlers[i]->comment : "");
}

static int
get_fpn0_test_comment(int type)
{
	int i = 1;

	int val = fpn0_usage[i].val;
	while (val != 0) {
		if (val == type) {
			return i;
		} else {
			i++;
			val = fpn0_usage[i].val;
		}
	}
	return 0;
}

#ifdef CONFIG_MCORE_ARCH_OCTEON
/*
 * The code for the TEST_FPN0 that is specific to OCTEON
 *
 */
extern void octeon_test_fpn0_eqos_stats(void);

#endif  /* CONFIG_MCORE_ARCH_OCTEON */

#ifdef FP_TEST_FPN0_CRYPTO_SUPPORT
static void
hexdump(const char *title, const void *buf, unsigned int len)
{
	unsigned int i, out, ofs;
	const unsigned char *data = buf;
#define LINE_LEN 80
	char line[LINE_LEN];	/* space needed 8+16*3+3+16 == 75 */

	fpn_printf("%s at [%p], len=%d\n", title, data, len);
	ofs = 0;
	while (ofs < len) {
		FPN_TRACK();
		/* format 1 line in the buffer, then use printk to print them */
		out = snprintf(line, LINE_LEN, "%08X", ofs);
		for (i=0; ofs+i < len && i<16; i++)
			out += snprintf(line+out, LINE_LEN - out, " %02X", data[ofs+i]&0xff);
		for(;i<=16;i++)
			out += snprintf(line+out, LINE_LEN - out, "   ");
		for(i=0; ofs < len && i<16; i++, ofs++) {
			unsigned char c = data[ofs];
			if (!isascii(c) || !isprint(c))
				c = '.';
			out += snprintf(line+out, LINE_LEN - out, "%c", c);
		}
		fpn_printf("%s\n", line);
	}
}

/* A crypto test vector */
struct crypto_test_vector {
	const char *name;      /* name, displayed for each test vector */
	int cipher;            /* cipher algo */
	int cipher_key_size;   /* cipher key size */
	int auth;              /* auth algo */
	uint16_t len;          /* length of data to process */
	char result[FP_MAX_HASH_BLOCK_SIZE]; /* expected result */
};

/* These test vectors are auto-generated with a script. The source of
 * the script is available in PR 19613. */
static const struct crypto_test_vector crypto_test_vectors[] = {
        /* HMAC test vectors */
        {
                .name = "HMAC-MD5",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACMD5,
                .len = 13,
                .result = {
                        0x26, 0xDC, 0x96, 0x37, 0x91, 0x0A, 0x96, 0x31, 
                        0x39, 0x3B, 0x47, 0x6D, 0xB5, 0x9C, 0xEF, 0xFC, 
                },
        },
        {
                .name = "HMAC-SHA1",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA1,
                .len = 13,
                .result = {
                        0xA0, 0xF9, 0x3D, 0x9B, 0xA0, 0xD1, 0x39, 0x71, 
                        0x3C, 0x25, 0x24, 0x20, 0x73, 0xE9, 0xD5, 0xE9, 
                        0xAC, 0x6C, 0x70, 0x17, 
                },
        },
        {
                .name = "HMAC-SHA256",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA256,
                .len = 13,
                .result = {
                        0x49, 0x7E, 0xF2, 0xEC, 0x32, 0x4B, 0x9F, 0xAF, 
                        0xD2, 0x9E, 0x6D, 0xCD, 0x15, 0x24, 0xA3, 0xFE, 
                        0x4D, 0x4D, 0xE5, 0xD6, 0x15, 0xD2, 0xAA, 0x59, 
                        0x19, 0x41, 0x7F, 0xBD, 0xFC, 0x57, 0x0D, 0x44, 
                },
        },
        {
                .name = "HMAC-SHA384",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA384,
                .len = 13,
                .result = {
                        0x7D, 0xBD, 0xCF, 0x08, 0x89, 0x1F, 0xE4, 0x62, 
                        0xB9, 0x47, 0x77, 0x69, 0x5E, 0x8F, 0x0B, 0xB5, 
                        0xBC, 0xF1, 0x2B, 0x56, 0x61, 0x55, 0x13, 0xAF, 
                        0x93, 0x9F, 0x3F, 0xD7, 0x5E, 0x62, 0x6F, 0xCD, 
                        0x4B, 0x99, 0x2D, 0x06, 0x44, 0xFB, 0xC4, 0xD3, 
                        0x2D, 0x98, 0x4B, 0x68, 0xDB, 0x40, 0x0F, 0x52, 
                },
        },
        {
                .name = "HMAC-SHA512",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA512,
                .len = 13,
                .result = {
                        0x82, 0x01, 0x0D, 0x0D, 0xC8, 0x1E, 0x76, 0x8A, 
                        0x5C, 0xC8, 0x83, 0x24, 0x2A, 0x58, 0x7D, 0x74, 
                        0x1E, 0xFF, 0x67, 0x6E, 0x58, 0x1B, 0x7B, 0xBF, 
                        0xE9, 0x08, 0xF3, 0xEE, 0x9A, 0xCA, 0x38, 0x4D, 
                        0xFD, 0x1E, 0xE2, 0xAB, 0xD3, 0xD3, 0x90, 0x3A, 
                        0xF3, 0x0C, 0xD6, 0x5E, 0xB8, 0x96, 0x8B, 0x5B, 
                        0x91, 0x26, 0x68, 0x33, 0xA7, 0x09, 0xE9, 0x90, 
                        0x94, 0x4C, 0x5C, 0xFF, 0x22, 0xDD, 0xA3, 0x99, 
                },
        },
        {
                .name = "AES-XCBC",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_AESXCBC,
                .len = 13,
                .result = {
                        0x9A, 0x73, 0x27, 0x53, 0x24, 0x81, 0x22, 0x97, 
                        0x25, 0x63, 0x9F, 0x1D, 0x27, 0x21, 0xBA, 0x45, 
                },
        },
        {
                .name = "HMAC-MD5",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACMD5,
                .len = 1053,
                .result = {
                        0x7A, 0x5D, 0xD8, 0xB1, 0x7C, 0xEE, 0x04, 0xCA, 
                        0x58, 0x80, 0x20, 0x80, 0x17, 0x19, 0x35, 0x65, 
                },
        },
        {
                .name = "HMAC-SHA1",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA1,
                .len = 1053,
                .result = {
                        0x99, 0x73, 0xB1, 0x31, 0xC5, 0x38, 0x94, 0x14, 
                        0x78, 0x4E, 0x38, 0xEB, 0x7E, 0x75, 0xEA, 0x5F, 
                        0x18, 0x8D, 0x5B, 0x00, 
                },
        },
        {
                .name = "HMAC-SHA256",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA256,
                .len = 1053,
                .result = {
                        0xAC, 0x12, 0x6B, 0xD7, 0xA0, 0x29, 0x3A, 0x32, 
                        0x47, 0xF2, 0x15, 0xEB, 0xB5, 0x6F, 0x1F, 0xE5, 
                        0x33, 0x96, 0x3D, 0x14, 0x74, 0x7B, 0x34, 0xCA, 
                        0x56, 0xBB, 0x9A, 0xC4, 0xE9, 0x6A, 0x2B, 0xC3, 
                },
        },
        {
                .name = "HMAC-SHA384",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA384,
                .len = 1053,
                .result = {
                        0x4D, 0x61, 0xC6, 0xA2, 0xAC, 0x14, 0xDB, 0x14, 
                        0xE8, 0x70, 0x4B, 0x30, 0xD9, 0x11, 0x2C, 0x66, 
                        0xFF, 0xF6, 0x7B, 0xD5, 0x04, 0x89, 0xDA, 0xD2, 
                        0xD3, 0x9A, 0xA1, 0x4A, 0x90, 0x28, 0xC3, 0x38, 
                        0xB3, 0x4F, 0xF5, 0x37, 0xDD, 0x64, 0x16, 0x01, 
                        0x34, 0xFF, 0x52, 0x50, 0x9C, 0x84, 0x62, 0xC4, 
                },
        },
        {
                .name = "HMAC-SHA512",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA512,
                .len = 1053,
                .result = {
                        0xD3, 0xC5, 0x75, 0xA7, 0x9F, 0x47, 0x04, 0x99, 
                        0x3D, 0xF6, 0x91, 0xB4, 0x18, 0xDE, 0x6A, 0x71, 
                        0x48, 0x06, 0x4D, 0xA2, 0x4D, 0x7D, 0xF9, 0x33, 
                        0x24, 0xA4, 0x8C, 0xB0, 0xA7, 0xBA, 0xE3, 0x82, 
                        0x4C, 0x99, 0xE2, 0xDD, 0xA4, 0x2F, 0x6B, 0x53, 
                        0x8A, 0xC9, 0x57, 0x90, 0xC8, 0x9D, 0x5B, 0x47, 
                        0x36, 0xAF, 0xA4, 0xBD, 0x7E, 0x3C, 0xE8, 0x17, 
                        0x03, 0x10, 0x81, 0xB8, 0xEA, 0x0C, 0x2A, 0x63, 
                },
        },
        {
                .name = "AES-XCBC",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_AESXCBC,
                .len = 1053,
                .result = {
                        0x3A, 0xBB, 0x03, 0xB6, 0x46, 0xA2, 0xB3, 0xB4, 
                        0x12, 0x53, 0x08, 0xD2, 0x2F, 0x29, 0xE1, 0x3A, 
                },
        },
        {
                .name = "HMAC-MD5",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACMD5,
                .len = 1280,
                .result = {
                        0x33, 0xA4, 0xB8, 0x37, 0x19, 0x5C, 0xE8, 0xEF, 
                        0x0C, 0x24, 0x62, 0x15, 0x96, 0xD3, 0xE8, 0xEF, 
                },
        },
        {
                .name = "HMAC-SHA1",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA1,
                .len = 1280,
                .result = {
                        0x87, 0x30, 0xEF, 0xAF, 0x8F, 0x22, 0x24, 0x30, 
                        0x38, 0xDF, 0xC0, 0xDD, 0xDC, 0x0D, 0xCE, 0x5A, 
                        0xD4, 0xF3, 0xEB, 0x3D, 
                },
        },
        {
                .name = "HMAC-SHA256",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA256,
                .len = 1280,
                .result = {
                        0x02, 0x24, 0x23, 0xFE, 0xB1, 0x80, 0x1A, 0x89, 
                        0x7C, 0x57, 0x85, 0x12, 0xBF, 0xA0, 0x2A, 0x11, 
                        0xF8, 0xD1, 0xEE, 0x03, 0x36, 0x08, 0xC9, 0x31, 
                        0xFB, 0x72, 0x94, 0xCE, 0x7C, 0x07, 0x26, 0x26, 
                },
        },
        {
                .name = "HMAC-SHA384",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA384,
                .len = 1280,
                .result = {
                        0x46, 0x47, 0xEA, 0xF6, 0xBA, 0x24, 0x35, 0xB2, 
                        0x3E, 0x76, 0x68, 0x30, 0x6F, 0x17, 0xCA, 0xDE, 
                        0xD0, 0x6E, 0xCC, 0x2A, 0x4C, 0x61, 0xCF, 0x4F, 
                        0x9F, 0xC0, 0x6A, 0x44, 0x3C, 0x59, 0x9B, 0x0D, 
                        0xCF, 0xE5, 0x3C, 0x87, 0x53, 0x5F, 0x32, 0xA8, 
                        0xDE, 0x5A, 0x41, 0x25, 0x06, 0xF3, 0x35, 0x7E, 
                },
        },
        {
                .name = "HMAC-SHA512",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_HMACSHA512,
                .len = 1280,
                .result = {
                        0x25, 0x85, 0x35, 0x7D, 0xFA, 0x86, 0x3C, 0xA3, 
                        0x67, 0xA3, 0xBC, 0xE8, 0x18, 0x3E, 0xAC, 0xEE, 
                        0x55, 0xED, 0x3E, 0x55, 0x40, 0xD1, 0x7F, 0x47, 
                        0x0B, 0x16, 0xA8, 0x1E, 0xAE, 0x8C, 0xB5, 0x6B, 
                        0xFC, 0xB1, 0x33, 0xF8, 0x27, 0x20, 0xE2, 0xD0, 
                        0xCF, 0xC6, 0xF5, 0x08, 0xE1, 0xCA, 0x25, 0x73, 
                        0x83, 0x9D, 0xBA, 0x3E, 0x43, 0xAE, 0xFC, 0x19, 
                        0x4A, 0xC9, 0x15, 0xA9, 0x1D, 0xA6, 0x89, 0x2B, 
                },
        },
        {
                .name = "AES-XCBC",
                .cipher = FP_EALGO_NULL,
                .cipher_key_size = 0,
                .auth = FP_AALGO_AESXCBC,
                .len = 1280,
                .result = {
                        0x28, 0x80, 0xBE, 0x9A, 0xE3, 0x67, 0x27, 0xAA, 
                        0xB9, 0x02, 0x21, 0xE4, 0x95, 0x27, 0x4F, 0x7B, 
                },
        },

        /* Cipher + HMAC test vectors */
        {
                .name = "AES128-CBC / HMAC-SHA1",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 16,
                .auth = FP_AALGO_HMACSHA1,
                .len = 32,
                .result = {
                        0x37, 0x57, 0x13, 0x29, 0x95, 0x3F, 0x03, 0xFF, 
                        0xEB, 0x4E, 0xD1, 0x52, 0x71, 0x99, 0xCE, 0xCA, 
                        0x4F, 0x93, 0x58, 0x80, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA1",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA1,
                .len = 32,
                .result = {
                        0x87, 0xD2, 0xEE, 0x7B, 0xBF, 0x37, 0x92, 0x03, 
                        0x6B, 0x92, 0xE3, 0x76, 0xE2, 0x63, 0x4E, 0xCD, 
                        0xDC, 0xC3, 0x93, 0x2C, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA256",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA256,
                .len = 32,
                .result = {
                        0xE9, 0x6C, 0xB7, 0x60, 0x11, 0x2F, 0x0A, 0xCB, 
                        0x48, 0x2F, 0x78, 0x8F, 0x06, 0x71, 0x5C, 0x9B, 
                        0xA8, 0x6F, 0x06, 0x8D, 0xB1, 0x68, 0x13, 0x3E, 
                        0xCA, 0x79, 0x2B, 0x81, 0x67, 0xA0, 0x45, 0x00, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA384",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA384,
                .len = 32,
                .result = {
                        0x87, 0x65, 0x0F, 0x29, 0x80, 0x77, 0x70, 0x91, 
                        0xDB, 0xB7, 0x07, 0x02, 0x6B, 0xFB, 0xF3, 0x3C, 
                        0x6F, 0x3C, 0xAA, 0x11, 0x7D, 0x50, 0x80, 0x4E, 
                        0xFC, 0xDC, 0xB5, 0x2A, 0xE1, 0xDC, 0x24, 0xD4, 
                        0xEC, 0xFB, 0x10, 0xBB, 0x04, 0x33, 0xB6, 0x89, 
                        0xFF, 0xF2, 0x28, 0xBD, 0x15, 0xF4, 0xC8, 0xEB, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA512",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA512,
                .len = 32,
                .result = {
                        0xD9, 0xEE, 0x1A, 0x62, 0xF7, 0xAB, 0x62, 0x74, 
                        0x85, 0x3D, 0x84, 0x9C, 0x52, 0x97, 0x6B, 0xCF, 
                        0xD7, 0x6E, 0x0E, 0x2D, 0x49, 0xAD, 0xB6, 0x95, 
                        0x08, 0x35, 0x58, 0x8F, 0xCF, 0x0C, 0x64, 0xEE, 
                        0xEF, 0x29, 0xBE, 0xBA, 0xE6, 0x1D, 0xB6, 0x74, 
                        0x5E, 0x2F, 0xF2, 0x7C, 0x1C, 0x73, 0xF6, 0x32, 
                        0xBC, 0x3D, 0xB0, 0x39, 0xC7, 0xAA, 0x61, 0xDB, 
                        0x7E, 0x8E, 0x55, 0xA5, 0xC7, 0x24, 0xFA, 0xA7, 
                },
        },
        {
                .name = "DES-CBC / HMAC-MD5",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACMD5,
                .len = 32,
                .result = {
                        0xE2, 0xF6, 0x4A, 0x47, 0xE5, 0x00, 0x23, 0xC4, 
                        0x40, 0x49, 0x84, 0xC4, 0x7E, 0x21, 0x2E, 0xCA, 
                },
        },
        {
                .name = "DES3-CBC HMAC-SHA256",
                .cipher = FP_EALGO_3DESCBC,
                .cipher_key_size = 24,
                .auth = FP_AALGO_HMACSHA256,
                .len = 32,
                .result = {
                        0x85, 0xDA, 0x6F, 0xAA, 0x84, 0x5F, 0xCE, 0x37, 
                        0x74, 0x3C, 0x06, 0x6F, 0x6A, 0x05, 0x61, 0xD3, 
                        0x1B, 0x31, 0x75, 0x8E, 0xB6, 0x34, 0x91, 0x23, 
                        0x12, 0x50, 0x63, 0x83, 0xEC, 0x38, 0x1E, 0x6D, 
                },
        },
        {
                .name = "DES3-CBC HMAC-SHA384",
                .cipher = FP_EALGO_3DESCBC,
                .cipher_key_size = 24,
                .auth = FP_AALGO_HMACSHA384,
                .len = 32,
                .result = {
                        0x42, 0xAC, 0xDC, 0xA9, 0xF8, 0xE4, 0x27, 0xA8, 
                        0x00, 0x16, 0x48, 0xD9, 0x71, 0x45, 0xD3, 0x2A, 
                        0x73, 0x70, 0x23, 0xBD, 0x63, 0xCD, 0xDB, 0x0D, 
                        0x3A, 0xF2, 0x81, 0x70, 0xD4, 0xD1, 0xD0, 0x56, 
                        0x09, 0xCD, 0x65, 0x30, 0x05, 0xC8, 0x12, 0xEE, 
                        0x66, 0x87, 0x6E, 0x90, 0x2A, 0x5F, 0xEE, 0x10, 
                },
        },
        {
                .name = "DES3-CBC HMAC-SHA512",
                .cipher = FP_EALGO_3DESCBC,
                .cipher_key_size = 24,
                .auth = FP_AALGO_HMACSHA512,
                .len = 32,
                .result = {
                        0xAC, 0x13, 0xF2, 0x29, 0xE2, 0x35, 0x94, 0x01, 
                        0xBE, 0x85, 0x18, 0xB8, 0xD7, 0x0B, 0x9C, 0x32, 
                        0x7D, 0xA0, 0xF7, 0xEE, 0x93, 0x45, 0x19, 0x36, 
                        0xF7, 0x90, 0xEF, 0x2F, 0xA5, 0xE5, 0xF2, 0x32, 
                        0x6E, 0x42, 0xC7, 0x0A, 0xB4, 0x88, 0x9F, 0xE9, 
                        0x8A, 0xA9, 0x8A, 0x12, 0xF1, 0x74, 0x0B, 0xBA, 
                        0x71, 0x54, 0x79, 0x5E, 0x00, 0x0F, 0xE3, 0x4B, 
                        0x72, 0xC1, 0x04, 0xF3, 0x1E, 0xFF, 0xC3, 0x33, 
                },
        },
        {
                .name = "DES-CBC / HMAC-SHA256",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACSHA256,
                .len = 32,
                .result = {
                        0x90, 0x45, 0x65, 0x5A, 0xBE, 0x4B, 0x5B, 0x00, 
                        0x36, 0x8A, 0xE7, 0x39, 0xE4, 0x19, 0xEB, 0x26, 
                        0xFF, 0x56, 0xD0, 0xA0, 0x6F, 0x7F, 0x13, 0x00, 
                        0x94, 0x50, 0x08, 0x45, 0xA3, 0x70, 0x97, 0x9C, 
                },
        },
        {
                .name = "DES-CBC / HMAC-SHA384",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACSHA384,
                .len = 32,
                .result = {
                        0xAB, 0xC1, 0x3A, 0x4F, 0x23, 0x2E, 0xF7, 0x7E, 
                        0xD3, 0xE5, 0xF6, 0x85, 0xF6, 0x4A, 0xA1, 0x16, 
                        0x7A, 0xB0, 0xC4, 0x0B, 0xDA, 0xEC, 0xA2, 0xDE, 
                        0x1B, 0xB0, 0x93, 0x8A, 0x8D, 0x40, 0x1A, 0x4D, 
                        0xD8, 0x4D, 0x99, 0xB6, 0x90, 0x9A, 0xFC, 0x54, 
                        0x2E, 0x52, 0x0C, 0xCB, 0x4F, 0xEC, 0x87, 0xA1, 
                },
        },
        {
                .name = "DES-CBC / HMAC-SHA512",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACSHA512,
                .len = 32,
                .result = {
                        0x71, 0x1D, 0xC4, 0xA4, 0x91, 0x36, 0xA9, 0x28, 
                        0xFF, 0xFA, 0xCF, 0x4A, 0x9B, 0x26, 0x2C, 0x3B, 
                        0x78, 0x38, 0xF0, 0xCA, 0xBE, 0xE6, 0xE0, 0x4E, 
                        0x43, 0x48, 0x53, 0x6E, 0xCE, 0x4C, 0x20, 0x8E, 
                        0x19, 0xC9, 0x4B, 0xE5, 0x2F, 0x9B, 0x8F, 0xCA, 
                        0x07, 0xB5, 0xF6, 0x19, 0x11, 0x9A, 0x0F, 0x11, 
                        0xD3, 0xD7, 0x3F, 0xE4, 0x45, 0xDB, 0x96, 0x1A, 
                        0x1C, 0x21, 0xF1, 0x56, 0x12, 0x9A, 0xD2, 0x6D, 
                },
        },
        {
                .name = "AES128-CBC / HMAC-SHA1",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 16,
                .auth = FP_AALGO_HMACSHA1,
                .len = 1280,
                .result = {
                        0x79, 0x0E, 0x57, 0xAD, 0x51, 0x56, 0x75, 0xB8, 
                        0x7E, 0x05, 0xD7, 0xC8, 0xC0, 0xE8, 0xA0, 0xB7, 
                        0x62, 0x8C, 0xBA, 0xDC, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA1",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA1,
                .len = 1280,
                .result = {
                        0xC3, 0x8D, 0xAB, 0x49, 0x38, 0xD6, 0xAF, 0x39, 
                        0x69, 0x12, 0xF9, 0xA4, 0xEE, 0x29, 0x59, 0x51, 
                        0x66, 0x39, 0xC8, 0x11, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA256",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA256,
                .len = 1280,
                .result = {
                        0x14, 0xB6, 0x70, 0x42, 0x4B, 0x7A, 0xF6, 0x28, 
                        0xFD, 0x6C, 0xFE, 0xD8, 0xE5, 0x7B, 0xF1, 0x7B, 
                        0x22, 0x18, 0xD3, 0x4C, 0x70, 0x2A, 0x39, 0x39, 
                        0xBD, 0x47, 0xEB, 0xE0, 0x22, 0xDE, 0x5F, 0x6B, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA384",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA384,
                .len = 1280,
                .result = {
                        0xEE, 0x61, 0x62, 0x7F, 0xB9, 0xB4, 0x81, 0xFD, 
                        0xE3, 0x93, 0x61, 0x46, 0x4F, 0xFD, 0x84, 0x14, 
                        0xA3, 0x8E, 0xA7, 0x96, 0x48, 0x77, 0x37, 0xA4, 
                        0x55, 0x16, 0x71, 0xB9, 0x43, 0x7C, 0xA9, 0x57, 
                        0xB1, 0x49, 0x03, 0xE8, 0xAF, 0x24, 0x5B, 0x91, 
                        0xB9, 0x8F, 0x31, 0x10, 0xB6, 0xE6, 0x7F, 0xB3, 
                },
        },
        {
                .name = "AES256-CBC / HMAC-SHA512",
                .cipher = FP_EALGO_AESCBC,
                .cipher_key_size = 32,
                .auth = FP_AALGO_HMACSHA512,
                .len = 1280,
                .result = {
                        0xF7, 0x7C, 0xB9, 0xBE, 0x0A, 0x1E, 0x98, 0x35, 
                        0xF1, 0x35, 0x15, 0x5A, 0x16, 0xAB, 0x90, 0x2A, 
                        0xF0, 0x60, 0x6E, 0xDD, 0x56, 0xC3, 0x6C, 0xF9, 
                        0xD7, 0x82, 0x22, 0x45, 0xB2, 0x24, 0xDC, 0xA6, 
                        0x91, 0x83, 0x27, 0xA9, 0x76, 0xF0, 0xBC, 0xA2, 
                        0xCD, 0xC9, 0x5F, 0x24, 0x59, 0x57, 0x0D, 0x94, 
                        0xAD, 0xEF, 0x4D, 0x7C, 0x20, 0x9A, 0x00, 0xE4, 
                        0x18, 0xF2, 0x8E, 0x21, 0x7D, 0x6E, 0xE5, 0x38, 
                },
        },
        {
                .name = "DES-CBC / HMAC-MD5",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACMD5,
                .len = 1280,
                .result = {
                        0xA7, 0x06, 0x1C, 0x71, 0x72, 0x04, 0x16, 0xEE, 
                        0xF4, 0xD9, 0x22, 0x65, 0x12, 0xE4, 0x88, 0x95, 
                },
        },
        {
                .name = "DES3-CBC HMAC-SHA256",
                .cipher = FP_EALGO_3DESCBC,
                .cipher_key_size = 24,
                .auth = FP_AALGO_HMACSHA256,
                .len = 1280,
                .result = {
                        0x4C, 0xE7, 0x36, 0xAB, 0xF7, 0xB3, 0x3B, 0x69, 
                        0x5C, 0xA7, 0x5D, 0x38, 0x52, 0x72, 0x81, 0x34, 
                        0x34, 0x8C, 0xA9, 0x3F, 0x4A, 0xF1, 0x0C, 0x6E, 
                        0x8C, 0xE5, 0x1B, 0x50, 0xA8, 0x81, 0x79, 0x52, 
                },
        },
        {
                .name = "DES3-CBC HMAC-SHA384",
                .cipher = FP_EALGO_3DESCBC,
                .cipher_key_size = 24,
                .auth = FP_AALGO_HMACSHA384,
                .len = 1280,
                .result = {
                        0xF9, 0xEB, 0x08, 0x63, 0xC4, 0x0A, 0xFE, 0x79, 
                        0x9B, 0xFD, 0x38, 0x89, 0x50, 0xE2, 0xC7, 0x1C, 
                        0x71, 0x02, 0x47, 0xB0, 0x98, 0xBF, 0x66, 0xD3, 
                        0x58, 0xF0, 0x17, 0xE6, 0xD1, 0x49, 0xA0, 0x75, 
                        0x25, 0xC5, 0xAA, 0x4A, 0x8D, 0x32, 0x0F, 0x3E, 
                        0x6F, 0xF6, 0xFE, 0x05, 0xA7, 0xC7, 0x81, 0x63, 
                },
        },
        {
                .name = "DES3-CBC HMAC-SHA512",
                .cipher = FP_EALGO_3DESCBC,
                .cipher_key_size = 24,
                .auth = FP_AALGO_HMACSHA512,
                .len = 1280,
                .result = {
                        0x79, 0xDB, 0x54, 0xED, 0xE0, 0x1A, 0x51, 0x9D, 
                        0x46, 0xAC, 0xBE, 0x1B, 0x8C, 0x20, 0xEC, 0x91, 
                        0xFE, 0x8A, 0x38, 0x54, 0xF3, 0xD8, 0x97, 0x49, 
                        0x0B, 0x4B, 0x00, 0x3A, 0xE1, 0x17, 0x07, 0xF4, 
                        0x6F, 0x38, 0x46, 0xAD, 0xB4, 0xF4, 0xFA, 0x50, 
                        0x63, 0xF2, 0x19, 0x5C, 0xC8, 0x78, 0xAF, 0xA7, 
                        0xD0, 0x68, 0xDA, 0x63, 0xDF, 0x50, 0x48, 0x49, 
                        0xA0, 0xD9, 0x0A, 0xCB, 0x8F, 0x8F, 0x96, 0x46, 
                },
        },
        {
                .name = "DES-CBC / HMAC-SHA256",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACSHA256,
                .len = 1280,
                .result = {
                        0xA7, 0x10, 0x75, 0x57, 0xC3, 0x50, 0x8A, 0x6C, 
                        0x36, 0x1B, 0xE7, 0xF5, 0xE2, 0x2E, 0x29, 0xA3, 
                        0x20, 0x88, 0xD1, 0x4D, 0x48, 0x64, 0xCA, 0xAC, 
                        0xFE, 0x7F, 0x75, 0xE4, 0x95, 0x77, 0xE2, 0x6B, 
                },
        },
        {
                .name = "DES-CBC / HMAC-SHA384",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACSHA384,
                .len = 1280,
                .result = {
                        0x0B, 0x4D, 0x30, 0xCF, 0xC0, 0x24, 0x11, 0xA1, 
                        0xB3, 0x49, 0x2D, 0xE3, 0x54, 0x64, 0xAC, 0x29, 
                        0xEB, 0x55, 0xF6, 0xA2, 0x82, 0x4C, 0x5C, 0xA3, 
                        0xD3, 0xA2, 0x42, 0x04, 0x88, 0x41, 0x98, 0x65, 
                        0x0A, 0x0E, 0x97, 0x99, 0xD1, 0x67, 0xC8, 0x93, 
                        0x89, 0x5D, 0x7B, 0xF2, 0xE4, 0xC6, 0xDE, 0xA6, 
                },
        },
        {
                .name = "DES-CBC / HMAC-SHA512",
                .cipher = FP_EALGO_DESCBC,
                .cipher_key_size = 8,
                .auth = FP_AALGO_HMACSHA512,
                .len = 1280,
                .result = {
                        0xD0, 0x1C, 0x02, 0x36, 0x15, 0x1C, 0x08, 0x84, 
                        0x3C, 0x66, 0xDA, 0xB2, 0x68, 0xE9, 0xBA, 0xE9, 
                        0xBC, 0x31, 0x92, 0x3C, 0x75, 0x69, 0x8E, 0x6B, 
                        0xE8, 0x53, 0x1A, 0x35, 0xD3, 0x83, 0x1C, 0x00, 
                        0x72, 0xB4, 0x07, 0x99, 0xBE, 0xBF, 0xEE, 0x10, 
                        0x6A, 0x0E, 0x45, 0xA3, 0xD8, 0x83, 0x61, 0xE4, 
                        0x34, 0x21, 0x1D, 0x13, 0xE6, 0xA8, 0xBB, 0x41, 
                        0x6E, 0x69, 0x27, 0xFF, 0xDB, 0xA0, 0x31, 0x1F, 
                },
        },	
	{
		.name = NULL,
	},
};

struct crypto_mbuf_param {
	unsigned int m_len;        /* len of mbuf */
	unsigned int split_size;   /* len of the first segment */
	uint16_t off;              /* offset where data starts in
				      packet */
};

static const struct crypto_mbuf_param crypto_mbuf_params[] = {

	/* single-segment mbufs */
	{ .m_len = 1500, .split_size = 0, .off = 0 },
	{ .m_len = 1500, .split_size = 0, .off = 97 },
	{ .m_len = 1500, .split_size = 0, .off = 1500 - 1280 },

	/* multi-segment */
	{ .m_len = 1500, .split_size = 13, .off = 2 },
	{ .m_len = 1500, .split_size = 800, .off = 0 },
	{ .m_len = 1500, .split_size = 800, .off = 97 },
	{ .m_len = 1500, .split_size = 800, .off = 1500 - 1280 },
	{ .m_len = 3000, .split_size = 1500, .off = 1400 },
	{ .m_len = 3000, .split_size = 1500, .off = 1500 },

	/* dummy */
	{ .m_len = 0, .split_size = 0, .off = 0 },
};

static int test_fpn0_do_auth(char *dst, const struct mbuf *m, uint16_t off,
			     uint16_t len, int algo, const char *key);


/* Decrypt and check auth of a mbuf. The mbuf must be contiguous and
 * the datalen must be a multiple of block size. Return 0 on success,
 * and -1 if the algorithm is not supported. */
static int
test_fpn0_do_decrypt_and_auth(struct mbuf *m, uint16_t off, uint16_t len,
			      int ealgo, const char *ekey, int ekey_len,
			      const char *iv, int aalgo, const char *akey,
			      uint16_t auth_off, uint16_t alen)
{
#if   (defined HAVE_3DESHMACMD5)  \
   || (defined HAVE_AESHMACSHA1)  \
   || (defined HAVE_DESHMACSHA2)  \
   || (defined HAVE_3DESHMACSHA2) \
   || (defined HAVE_AESHMACSHA2)
        const uint64_t *ekey64 = (const uint64_t *) ekey;
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
	const uint64_t *iv64 = (const uint64_t *) iv;
#endif
	char dst_auth[FP_MAX_HASH_BLOCK_SIZE];
	char opad[FP_MAX_HASH_BLOCK_SIZE];
	char ipad[FP_MAX_HASH_BLOCK_SIZE];

	/* Init ipad and opad to 0. This step is only useful for
	 * targets using this optimization (only octeon at this
	 * time). */
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
#endif

#ifdef HAVE_CRYPTO_PREHANDLE
#if defined(HAVE_AESHMACSHA1) || defined(HAVE_AESHMACSHA2)
	if (ealgo == FP_EALGO_AESCBC) {
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_aes_set_iv(iv64);
#endif
		fpn_aes_cbc_decrypt_pre(mtod(m, char *) + off, len,
				ekey64, ekey_len);
	}
#endif
#if defined(HAVE_DESHMACMD5) || defined(HAVE_DESHMACSHA2)
	if (ealgo == FP_EALGO_DESCBC) {
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_des_set_iv(iv64);
#endif
		fpn_des_cbc_decrypt_pre(mtod(m, char *) + off, len, ekey64);
	}
#endif
#if defined(HAVE_3DESHMACMD5) || defined(HAVE_3DESHMACSHA2)
	if (ealgo == FP_EALGO_3DESCBC) {
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_3des_set_iv(iv64);
#endif
		fpn_3des_cbc_decrypt_pre(mtod(m, char *) + off, len, ekey64);
	}
#endif
#endif

#ifdef HAVE_DESHMACMD5
        if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACMD5) {
                fpn_des_cbc_decrypt_hmd5(mtod(m, char *) + off, len,
                                         ekey64, dst_auth,
                                         akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_md5_complete_pass1();
                fpn_hmac_md5_complete_pass2();
                fpn_hmac_md5_complete_pass3();
#endif
                goto check_auth;
        }
#endif
	
#ifdef HAVE_3DESHMACMD5
	if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACMD5) {
		fpn_3des_cbc_decrypt_hmd5(mtod(m, char *) + off, len,
					 ekey64, dst_auth,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_md5_complete_pass1();
		fpn_hmac_md5_complete_pass2();
		fpn_hmac_md5_complete_pass3();
#endif
		goto check_auth;
	}
#endif

#ifdef HAVE_AESHMACSHA1
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA1) {
		fpn_aes_cbc_decrypt_hsha1(mtod(m, char *) + off, len,
					 ekey64, ekey_len, dst_auth,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha1_complete_pass1();
		fpn_hmac_sha1_complete_pass2();
#endif
		goto check_auth;
	}
#endif

#ifdef HAVE_AESHMACSHA2
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA256) {
		fpn_aes_cbc_decrypt_hsha256(mtod(m, char *) + off, len,
				            ekey64, ekey_len, dst_auth,
					    akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha256_complete_pass1();
		fpn_hmac_sha256_complete_pass2();
#endif
		goto check_auth;
	}
	
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA384) {
		fpn_aes_cbc_decrypt_hsha384(mtod(m, char *) + off, len,
				            ekey64, ekey_len, dst_auth,
					    akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha384_complete_pass1();
		fpn_hmac_sha384_complete_pass2();
#endif
		goto check_auth;
	}
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA512) {
		fpn_aes_cbc_decrypt_hsha512(mtod(m, char *) + off, len,
				            ekey64, ekey_len, dst_auth,
					    akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha512_complete_pass1();
		fpn_hmac_sha512_complete_pass2();
#endif
		goto check_auth;
	}
#endif
	
#ifdef HAVE_DESHMACSHA2
	if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACSHA256) {
		fpn_des_cbc_decrypt_hsha256(mtod(m, char *) + off, len,
				            ekey64, dst_auth,
				            akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha256_complete_pass1();
		fpn_hmac_sha256_complete_pass2();
#endif
		goto check_auth;
	}
	        
        if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACSHA384) {
                fpn_des_cbc_decrypt_hsha384(mtod(m, char *) + off, len,
                                             ekey64, dst_auth,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha384_complete_pass1();
                fpn_hmac_sha384_complete_pass2();
#endif
                goto check_auth;
        }
        
        if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACSHA512) {
                fpn_des_cbc_decrypt_hsha512(mtod(m, char *) + off, len,
                                             ekey64, dst_auth,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha512_complete_pass1();
                fpn_hmac_sha512_complete_pass2();
#endif
                goto check_auth;
        }
#endif
	
#ifdef HAVE_3DESHMACSHA2
        if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACSHA256) {
                fpn_3des_cbc_decrypt_hsha256(mtod(m, char *) + off, len,
                                             ekey64, dst_auth,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha256_complete_pass1();
                fpn_hmac_sha256_complete_pass2();
#endif
                goto check_auth;
        }
        
        if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACSHA384) {
                fpn_3des_cbc_decrypt_hsha384(mtod(m, char *) + off, len,
                                             ekey64, dst_auth,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha384_complete_pass1();
                fpn_hmac_sha384_complete_pass2();
#endif
                goto check_auth;
        }
        
        if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACSHA512) {
                fpn_3des_cbc_decrypt_hsha512(mtod(m, char *) + off, len,
                                             ekey64, dst_auth,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha512_complete_pass1();
                fpn_hmac_sha512_complete_pass2();
#endif
                goto check_auth;
        }
#endif
	fpn_printf("%s, unknown algo\n", __FUNCTION__);
	return -1;

#if   (defined HAVE_3DESHMACMD5)  \
   || (defined HAVE_AESHMACSHA1)  \
   || (defined HAVE_DESHMACSHA2)  \
   || (defined HAVE_3DESHMACSHA2) \
   || (defined HAVE_AESHMACSHA2)
 check_auth:

	if (memcmp(dst_auth, mtod(m, char *) + auth_off, alen)) {
		fpn_printf("FAILED in %s:\n", __FUNCTION__);
		hexdump("result", dst_auth, alen);
		hexdump("expected", mtod(m, char *) + auth_off, alen);
		return -1;
	}
	
	return 0;
#endif
}

/* Encrypt + authenticate a mbuf. The mbuf must be contiguous and the
 * len must be a multiple of block size. Return 0 on success, and -1
 * if the algorithm is not supported. */
static int
test_fpn0_do_encrypt_and_auth(struct mbuf *m, uint16_t off, uint16_t len,
			      int ealgo, const char *ekey, int ekey_len,
			      const char *iv, int aalgo, const char *akey,
			      uint16_t auth_off, uint16_t alen)
{
#if   (defined HAVE_3DESHMACMD5)  \
   || (defined HAVE_AESHMACSHA1)  \
   || (defined HAVE_DESHMACSHA2)  \
   || (defined HAVE_3DESHMACSHA2) \
   || (defined HAVE_AESHMACSHA2)
	const uint64_t *ekey64 = (const uint64_t *) ekey;
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
	const uint64_t *iv64 = (const uint64_t *) iv;
#endif
#endif

	char opad[FP_MAX_HASH_BLOCK_SIZE];
	char ipad[FP_MAX_HASH_BLOCK_SIZE];

	/* Init ipad and opad to 0. This step is only useful for
	 * targets using this optimization (only octeon at this
	 * time). */
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));

#ifdef HAVE_CRYPTO_PREHANDLE
#if defined(HAVE_AESHMACSHA1) || defined(HAVE_AESHMACSHA2)
	if (ealgo == FP_EALGO_AESCBC) {
		uint64_t *src = (uint64_t *)(mtod(m, char *) + off + FPN_ESP_HEADER_LEN + AES_IVLEN);
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_aes_set_iv(iv64);
#endif
		fp_test_fpn0_aes_encrypt(src, len, ekey64, ekey_len);
	}
#endif
#if defined(HAVE_DESHMACMD5) || defined(HAVE_DESHMACSHA2)
	if (ealgo == FP_EALGO_DESCBC) {
		uint64_t *src = (uint64_t *)(mtod(m, char *) + off + FPN_ESP_HEADER_LEN + DES_IVLEN);
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_des_set_iv(iv64);
#endif
		fp_test_fpn0_des_encrypt(src, len, ekey64);
	}
#endif
#if defined(HAVE_3DESHMACMD5) || defined(HAVE_3DESHMACSHA2)
	if (ealgo == FP_EALGO_3DESCBC) {
		uint64_t *src = (uint64_t *)(mtod(m, char *) + off + FPN_ESP_HEADER_LEN + DES_IVLEN);
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_3des_set_iv(iv64);
#endif
		fp_test_fpn0_3des_encrypt(src, len, ekey64);
	}
#endif
#endif

#ifdef HAVE_DESHMACMD5
        if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACMD5) {
                fpn_des_cbc_encrypt_hmd5(mtod(m, char *) + off, len,
                                         ekey64, mtod(m, char *) + auth_off,
                                         akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_md5_complete_pass1();
                fpn_hmac_md5_complete_pass2();
                fpn_hmac_md5_complete_pass3();
#endif
                return 0;
        }
#endif

#ifdef HAVE_3DESHMACMD5
	if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACMD5) {
		fpn_3des_cbc_encrypt_hmd5(mtod(m, char *) + off, len,
					 ekey64, mtod(m, char *) + auth_off,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_md5_complete_pass1();
		fpn_hmac_md5_complete_pass2();
		fpn_hmac_md5_complete_pass3();
#endif
		return 0;
	}
#endif

#ifdef HAVE_AESHMACSHA1
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA1) {

		fpn_aes_cbc_encrypt_hsha1(mtod(m, char *) + off, len, ekey64,
					 ekey_len, mtod(m, char *) + auth_off,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha1_complete_pass1();
		fpn_hmac_sha1_complete_pass2();
#endif
		return 0;
	}
#endif
	
#ifdef HAVE_AESHMACSHA2
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA256) {

		fpn_aes_cbc_encrypt_hsha256(mtod(m, char *) + off, len, ekey64,
					 ekey_len, mtod(m, char *) + auth_off,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha256_complete_pass1();
		fpn_hmac_sha256_complete_pass2();
#endif
		return 0;
	}
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA384) {

		fpn_aes_cbc_encrypt_hsha384(mtod(m, char *) + off, len, ekey64,
					 ekey_len, mtod(m, char *) + auth_off,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha384_complete_pass1();
		fpn_hmac_sha384_complete_pass2();
#endif
		return 0;
	}
	if (ealgo == FP_EALGO_AESCBC && aalgo == FP_AALGO_HMACSHA512) {

		fpn_aes_cbc_encrypt_hsha512(mtod(m, char *) + off, len, ekey64,
					 ekey_len, mtod(m, char *) + auth_off,
					 akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha512_complete_pass1();
		fpn_hmac_sha512_complete_pass2();
#endif
		return 0;
	}
#endif
	
#ifdef HAVE_DESHMACSHA2
	if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACSHA256) {
		fpn_des_cbc_encrypt_hsha256(mtod(m, char *) + off, len, ekey64,
				            mtod(m, char *) + auth_off,
				            akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha256_complete_pass1();
		fpn_hmac_sha256_complete_pass2();
#endif
		return 0;
	}
	
	if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACSHA384) {
                fpn_des_cbc_encrypt_hsha384(mtod(m, char *) + off, len, ekey64,
                                            mtod(m, char *) + auth_off,
                                            akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha384_complete_pass1();
                fpn_hmac_sha384_complete_pass2();
#endif
                return 0;
        }
	
	if (ealgo == FP_EALGO_DESCBC && aalgo == FP_AALGO_HMACSHA512) {
                fpn_des_cbc_encrypt_hsha512(mtod(m, char *) + off, len, ekey64,
                                            mtod(m, char *) + auth_off,
                                            akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha512_complete_pass1();
                fpn_hmac_sha512_complete_pass2();
#endif
                return 0;
        }
#endif
	
#ifdef HAVE_3DESHMACSHA2
        if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACSHA256) {
                fpn_3des_cbc_encrypt_hsha256(mtod(m, char *) + off, len, ekey64,
                                             mtod(m, char *) + auth_off,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha256_complete_pass1();
                fpn_hmac_sha256_complete_pass2();
#endif
                return 0;
        }
        
        if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACSHA384) {
                fpn_3des_cbc_encrypt_hsha384(mtod(m, char *) + off, len, ekey64,
                                             mtod(m, char *) + auth_off,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha384_complete_pass1();
                fpn_hmac_sha384_complete_pass2();
#endif
                return 0;
        }
        
        if (ealgo == FP_EALGO_3DESCBC && aalgo == FP_AALGO_HMACSHA512) {
                fpn_3des_cbc_encrypt_hsha512(mtod(m, char *) + off, len, ekey64,
                                             mtod(m, char *) + auth_off,
                                             akey, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
                fpn_hmac_sha512_complete_pass1();
                fpn_hmac_sha512_complete_pass2();
#endif
                return 0;
        }
#endif
	fpn_printf("%s, unknown algo\n", __FUNCTION__);
	return -1;
}

/*
 * Create a mbuf containing a dummy ESP header at offset 'esp_off', an
 * IV, then { 0x00, 0x01, 0x02, ... } of 'data_len' bytes, padding,
 * then a placeholder for the auth. Return NULL on error, and the
 * new mbuf on success. The mbuf is contiguous.
 */
static struct mbuf *test_fpn0_crypto_gen_esp_mbuf(uint16_t esp_off,
						  uint16_t data_len,
						  const char *iv,
						  unsigned block_size,
						  unsigned alen)
{
	struct mbuf *m = NULL;
	char *data = NULL;
	unsigned int i = 0;
	uint16_t m_len;
	uint16_t pktlen; /* esp hdr + iv + datalen + pad + auth */

	/* align data_len */
	data_len += (block_size - 1);
	data_len &= ~(block_size - 1);

	pktlen = sizeof(struct fp_esp) + block_size;
	pktlen += data_len;
	pktlen += alen;

	m_len = esp_off + pktlen;

	m = m_alloc();
	if (m == NULL) {
		fpn_printf("%s, Cannot allocate mbuf\n", __FUNCTION__);
		return NULL;
	}

	/* append data in segment */
	data = m_append(m, m_len);
	if (data == NULL) {
		fpn_printf("%s, Not enough space in segment\n", __FUNCTION__);
		m_freem(m);
		return NULL;
	}
	memset(data, 0, m_len);
	data += esp_off;
	data += sizeof(struct fp_esp);
	memcpy(data, iv, block_size);
	data += block_size;

	/* fill data in mbuf */
	for (i=0; i<data_len; i++)
		data[i] = i & 0xff;

	return m;
}

/* Check that a test vector behaves correctly using the optimized API
 * (for IPsec): it consist in encrypt and authenticate in one
 * operation, check auth result, decrypt and authenticate in one
 * operation, then check decrypted buffer. It's not provided on all
 * targets (octeon only at this time) and it only supports contiguous
 * buffer*/
static int test_fpn0_crypto_do_vect_optimized(const struct crypto_mbuf_param *mbuf_type,
					      const struct crypto_test_vector *vect)
{
	struct mbuf *m;
	int block_size = 0, alen = 0;
	/* key and iv are used for all algorithms, key is the same for
	 * hmac and cipher */
	const char *key = "keykeykeykeykeykeykeykeykeykeykekeykeykeykeykeykeykeykeykeykeyke";
	const char *iv  = "iviviviviviviviviviviviviviviviv";
	char dst_auth[FP_MAX_HASH_BLOCK_SIZE];
	char *buf = glb_buf[fpn_get_core_num()];
	unsigned int i = 0;
	uint16_t esp_off = mbuf_type->off;
	uint16_t auth_off;

	/* don't do the test on non-contiguous buffers */
	if (mbuf_type->split_size != 0){
		fpn_printf("   split_size not supported, exit\n");
		return 0;
	}
#ifdef HAVE_3DESHMACMD5
	if (vect->cipher == FP_EALGO_3DESCBC &&
	    vect->auth == FP_AALGO_HMACMD5) {
		block_size = DES_BLOCK_SIZE;
		alen = 16;
	}
#endif

#ifdef HAVE_AESHMACSHA1
	if (vect->cipher == FP_EALGO_AESCBC &&
	    vect->auth == FP_AALGO_HMACSHA1) {
		block_size = AES_BLOCK_SIZE;
		alen = 20;

		/* XXX fp_aes_cbc_decrypt_hsha1() requires at least 3
		 * AES blocks. */
		if (vect->len <= AES_BLOCK_SIZE * 2)
			return 0;
	}
#endif

#ifdef HAVE_AESHMACSHA2
	if (vect->cipher == FP_EALGO_AESCBC)
	{
		block_size = AES_BLOCK_SIZE;
		/* XXX fp_aes_cbc_decrypt_hsha256() requires at least 3
		 * AES blocks. */
		if (vect->len <= AES_BLOCK_SIZE * 2)
			return 0;

		if(vect->auth == FP_AALGO_HMACSHA256) {
			alen = 32;
		}
		if(vect->auth == FP_AALGO_HMACSHA384) {
			alen = 48;
		}
		if(vect->auth == FP_AALGO_HMACSHA512) {
			alen = 64;
		}
	}  

	if (vect->cipher == FP_EALGO_DESCBC){
	        block_size = DES_BLOCK_SIZE;
	        if(vect->auth == FP_AALGO_HMACSHA256) {
                        alen = 32;
                }
                if(vect->auth == FP_AALGO_HMACSHA384) {
                        alen = 48;
                }
                if(vect->auth == FP_AALGO_HMACSHA512) {
                        alen = 64;
                }
	}
	
	if (vect->cipher == FP_EALGO_3DESCBC){
                block_size = DES_BLOCK_SIZE;
                if(vect->auth == FP_AALGO_HMACSHA256) {
                        alen = 32;
                }
                if(vect->auth == FP_AALGO_HMACSHA384) {
                        alen = 48;
                }
                if(vect->auth == FP_AALGO_HMACSHA512) {
                        alen = 64;
                }
        }
#endif
	/* not supported on this target, skip it */
	if (block_size == 0){
	        fpn_printf("block size 0, exit %s\n", __FUNCTION__);	
	        return 0;
	}
	/* process the offset of the auth in the packet: obviously,
	 * block_size has to be a power of 2 */
	auth_off = esp_off + sizeof(struct fp_esp) + block_size;
	auth_off += ((vect->len + block_size - 1) & ~(block_size - 1));

	fpn_printf("%s (optimized)\n", vect->name);

	m = test_fpn0_crypto_gen_esp_mbuf(mbuf_type->off, vect->len,
					  iv, block_size, alen);
	if (m == NULL) {
		fpn_printf("Cannot alloc buffer\n");
		return -1;
	}

	/* encrypt + auth (the auth includes the esp header and the IV) */
	if (test_fpn0_do_encrypt_and_auth(m, esp_off, vect->len, vect->cipher,
					  key, vect->cipher_key_size, iv,
					  vect->auth, key, auth_off, alen))
		goto err;

	/* do auth and store the result, we cannot use vect->result
	 * because the signature includes esp header and the IV */
	memset(dst_auth, 0, sizeof(dst_auth));
	
	if (test_fpn0_do_auth(dst_auth, m, esp_off,
			      vect->len + sizeof(struct fp_esp) + block_size,
			      vect->auth, key))
		goto err;

	/* check auth result (memcmp is ok because mbuf is linear) */
	if (memcmp(mtod(m, char *) + auth_off, dst_auth, alen)) {
		fpn_printf("%s: auth check FAILED, it may be related to non-optimzed\n"
			   "auth if it also fails.\n", __FUNCTION__);
		hexdump("expected", dst_auth, alen);
		hexdump("result", mtod(m, char *) + auth_off, alen);
		goto err;
	}

	/* decrypt + auth + check auth */
	if (test_fpn0_do_decrypt_and_auth(m, esp_off, vect->len, vect->cipher,
					  key, vect->cipher_key_size, iv,
					  vect->auth, key, auth_off, alen))
		goto err;

	/* check decrypted data */
	m_copytobuf(buf, m, esp_off + sizeof(struct fp_esp) + block_size, vect->len);
	for (i=0; i<vect->len; i++) {
		char tmp = i & 0xff;
		if (buf[i] != tmp) {
			fpn_printf("%s: bad decrypted data at offset %d\n",
				   __FUNCTION__, i);
			hexdump("result", buf, vect->len);
			goto err;
		}
	}

	m_freem(m);
	return 0;
 err:
 	m_dump(m, m_len(m));
	m_freem(m);
	return -1;
}

/* Decrypt a mbuf. The len must be a multiple of block size. Return 0
 * on success, and -1 if the algorithm is not supported. */
/* XXX this function is marked noinline to workaround a compilation
 * issue with Cavium gcc 4.3.3.
 */
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE) && \
    defined(__GNUC__) && (__GNUC__ == 4) && (__GNUC_MINOR__ == 3)
__attribute__((noinline))
#endif
static int test_fpn0_do_decrypt(struct mbuf *m, uint16_t off, uint16_t len,
				int algo, const char *key, int key_len,
				const char *iv)
{
	const uint64_t *K64 = (uint64_t *)key;
	const uint64_t *iv64 = (uint64_t *)iv;

	switch (algo) {

	case FP_EALGO_NULL:
		return 0;

	case FP_EALGO_DESCBC:
		fpn_des_cbc_decrypt(m, off, len, iv64, K64);
		break;

	case FP_EALGO_3DESCBC:
		fpn_3des_cbc_decrypt(m, off, len, iv64, K64);
		break;

	case FP_EALGO_AESCBC:
		fpn_aes_cbc_decrypt(m, off, len, iv64, K64, key_len);
		break;

	default:
		fpn_printf("%s, unknown cipher algo\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

/* Encrypt a mbuf. The len must be a multiple of block size. Return 0
 * on success, and -1 if the algorithm is not supported. */
static int test_fpn0_do_encrypt(struct mbuf *m, uint16_t off, uint16_t len,
				int algo, const char *key, int key_len, 
				const char *iv)
{
	const uint64_t *K64 = (uint64_t *)key;
	const uint64_t *iv64 = (uint64_t *)iv;

	switch (algo) {

	case FP_EALGO_NULL:
		return 0;

	case FP_EALGO_DESCBC:
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_des_set_iv(iv64);
#endif
		fpn_des_cbc_encrypt(m, off, len, iv64, K64);
		break;

	case FP_EALGO_3DESCBC:
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_3des_set_iv(iv64);
#endif
		fpn_3des_cbc_encrypt(m, off, len, iv64, K64);
		break;

	case FP_EALGO_AESCBC:
#if defined(CONFIG_MCORE_ARCH_OCTEON) && defined(CONFIG_MCORE_FPE_MCEE)
		/* only for octeon: store IV in crypto registers */
		fpn_aes_set_iv(iv64);
#endif
		fpn_aes_cbc_encrypt(m, off, len, iv64, K64, key_len);
		break;

	default:
		fpn_printf("%s, unknown cipher algo\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

/* Do one auth algorithm */
static int test_fpn0_do_auth(char *dst, const struct mbuf *m, uint16_t off,
			     uint16_t len, int algo, const char *key)
{
	char opad[FP_MAX_HASH_BLOCK_SIZE];
	char ipad[FP_MAX_HASH_BLOCK_SIZE];
	char key_copy[FP_MAX_KEY_AUTH_LENGTH];

	/* This is not proper, but the linux hmac API does not have
	 * the 'const' attribute on the key argument... */
	memcpy(key_copy, key, FP_MAX_KEY_AUTH_LENGTH);

	/* Init ipad and opad to 0. This step is only useful for
	 * targets using this optimization (only octeon at this time).
	 * If we give a zero'ed buffer, these values are processed
	 * (derivated from the key) in fp_hmac_xxx() and can be kept
	 * for further use with the same key. */
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));

	switch (algo) {

	case FP_AALGO_NULL:
		break;

	case FP_AALGO_HMACMD5:
		fpn_hmac_md5(dst, key_copy, m, off, len, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_md5_complete_pass1();
		fpn_hmac_md5_complete_pass2();
		fpn_hmac_md5_complete_pass3();
#endif
		break;

	case FP_AALGO_HMACSHA1:
		fpn_hmac_sha1(dst, key_copy, m, off, len, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha1_complete_pass1();
		fpn_hmac_sha1_complete_pass2();
#endif
		break;

	case FP_AALGO_HMACSHA256:
		fpn_hmac_sha256(dst, key_copy, m, off, len, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha256_complete_pass1();
		fpn_hmac_sha256_complete_pass2();
#endif
		break;

	case FP_AALGO_HMACSHA384:
		fpn_hmac_sha384(dst, key_copy, m, off, len, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha384_complete_pass1();
		fpn_hmac_sha384_complete_pass2();
#endif
		break;

	case FP_AALGO_HMACSHA512:
		fpn_hmac_sha512(dst, key_copy, m, off, len, ipad, opad);
#ifdef HAVE_HMAC_COMPLETE
		fpn_hmac_sha512_complete_pass1();
		fpn_hmac_sha512_complete_pass2();
#endif
		break;

	case FP_AALGO_AESXCBC:
		fpn_aes_xcbc_mac(dst, key_copy, m, off, len);
		break;

	default:
		fpn_printf("%s, unknown auth algo\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

/*
 * Create a mbuf containing { 0x00, 0x01, 0x02, ... } of 'data_len'
 * bytes at offset 'data_off' and splitted in 2 segments at
 * 'split_size' if != 0. Return NULL on error, and the new mbuf on
 * success.
 */
static struct mbuf *test_fpn0_crypto_gen_mbuf(uint16_t m_len,
					      uint16_t split_size,
					      uint16_t data_off,
					      uint16_t data_len)
{
	char *buf = glb_buf[fpn_get_core_num()];
	struct mbuf *m = NULL, *m2 = NULL;
	char *data = NULL;
	unsigned int i = 0;

	if (data_off + data_len > m_len) {
		fpn_printf("%s, Data does not fit in mbuf\n", __FUNCTION__);
		return NULL;
	}

	m = m_alloc();
	if (m == NULL) {
		fpn_printf("%s, Cannot allocate mbuf\n", __FUNCTION__);
		return NULL;
	}

	/* only one segment */
	if (split_size == 0) {
		/* append data in segment */
		data = m_append(m, m_len);
		if (data == NULL) {
			fpn_printf("%s, Not enough space in segment\n", __FUNCTION__);
			m_freem(m);
			return NULL;
		}
		memset(data, 0, m_len);
	}

	/* if split_size != 0, create a new segment and append it
	 * after the first one. */
	else if (split_size != 0) {
		data = m_append(m, split_size);
		if (data == NULL) {
			fpn_printf("%s, Not enough space in first segment\n", __FUNCTION__);
			m_freem(m);
			return NULL;
		}

		memset(data, 0, split_size);
		m_len -= split_size;

		m2 = m_alloc();
		if (m2 == NULL) {
			fpn_printf("%s, Cannot allocate mbuf\n", __FUNCTION__);
			m_freem(m);
			return NULL;
		}

		/* append data in segment */
		data = m_append(m2, m_len);
		if (data == NULL) {
			fpn_printf("%s, Not enough space in segment\n", __FUNCTION__);
			m_freem(m);
			return NULL;
		}
		memset(data, 0, m_len);

		if (m_cat(m, m2)) {
			fpn_printf("%s, Cannot concatenate mbufs\n", __FUNCTION__);
			m_freem(m);
			m_freem(m2);
			return NULL;
		}

		/* m2 was freed by m_cat() */
		m2 = NULL;
	}

	/* fill data in mbuf */
	for (i=0; i<data_len; i++)
		buf[i] = i & 0xff;
	m_copyfrombuf(m, data_off, buf, data_len);

	return m;
}

/* Check that a test vector behaves correctly: it consist in encrypt,
 * authenticate, check auth result, decrypt, then check decrypted
 * buffer. */
static int test_fpn0_crypto_do_vect(const struct crypto_mbuf_param *mbuf_type,
				    const struct crypto_test_vector *vect)
{
	struct mbuf *m;
	/* key and iv are used for all algorithms */
	const char *key = "keykeykeykeykeykeykeykeykeykeykekeykeykeykeykeykeykeykeykeykeyke";
	const char *iv  = "iviviviviviviviviviviviviviviviv";
	char dst_auth[FP_MAX_HASH_BLOCK_SIZE];
	char *buf = glb_buf[fpn_get_core_num()];
	unsigned int i = 0;
	uint16_t off = mbuf_type->off;

	fpn_printf("%s\n", vect->name);

	/* create the mbuf */
	m = test_fpn0_crypto_gen_mbuf(mbuf_type->m_len,
				      mbuf_type->split_size,
				      mbuf_type->off, vect->len);
	if (m == NULL) {
		fpn_printf("Cannot alloc buffer\n");
		return -1;
	}

	/* encrypt  */
	if (test_fpn0_do_encrypt(m, off, vect->len, vect->cipher,
				 key, vect->cipher_key_size, iv))
		goto err;

	/* auth */
	memset(dst_auth, 0, sizeof(dst_auth));
	if (test_fpn0_do_auth(dst_auth, m, off, vect->len, vect->auth, key))
		goto err;

	if (memcmp(dst_auth, vect->result, FP_MAX_HASH_BLOCK_SIZE)) {
		fpn_printf("FAILED in %s:\n", __FUNCTION__);
		hexdump("expected", vect->result, FP_MAX_HASH_BLOCK_SIZE);
		hexdump("result", dst_auth, FP_MAX_HASH_BLOCK_SIZE);
		goto err;
	}

	/* decrypt  */
	if (test_fpn0_do_decrypt(m, off, vect->len, vect->cipher,
				 key, vect->cipher_key_size, iv))
		goto err;
	
	/* check decrypted data */
	m_copytobuf(buf, m, off, vect->len);
	for (i=0; i<vect->len; i++) {
		char tmp = i & 0xff;
		if (buf[i] != tmp) {
			fpn_printf("%s: bad decrypted data at offset %d\n",
				   __FUNCTION__, i);
			hexdump("result", buf, vect->len);
			goto err;
		}
	}

	m_freem(m);
	return 0;
 err:
	m_freem(m);
	return -1;
}
#endif /* FP_TEST_FPN0_CRYPTO_SUPPORT */

/*
 * Test synchronous crypto API.
 *
 * This test consist of applying several crypto/auth algorithms to the
 * same input buffer, using the same key (truncated if needed), the
 * same IV if any (truncated if needed). To check that the
 * multi-segment crypto is also working, we do the same test on
 * different mbuf topologies, changing the offset of data and the
 * segment size.
 *
 * To avoid to store in the code the whole encrypted buffer, we only
 * store its HMAC.
 */
static void test_fpn0_crypto_audit(void)
{
#ifndef FP_TEST_FPN0_CRYPTO_SUPPORT
	fpn_printf("==== mbuf crypto API test : not supported ====\n");
#else
	const struct crypto_mbuf_param *mbuf_type;
	const struct crypto_test_vector *vect;
	int ret = 0;

	fpn_printf("==== Start mbuf crypto API test ====\n");

	/* for each mbuf topology, launch the test */
	for (mbuf_type = &crypto_mbuf_params[0];
	     mbuf_type->m_len != 0; mbuf_type++) {

		fpn_printf("== Mbuf is: m_len = %d, split_size = %d, off = %d ==\n",
			   mbuf_type->m_len, mbuf_type->split_size, mbuf_type->off);

		/* for each test vector */
		for (vect = &crypto_test_vectors[0]; vect->name; vect++) {

			if (test_fpn0_crypto_do_vect(mbuf_type, vect))
				ret = -1;

			if (test_fpn0_crypto_do_vect_optimized(mbuf_type, vect))
				ret = -1;
		}
	}

	if (ret == 0)
		fpn_printf("==== mbuf crypto API test : SUCCESS ====\n");
	else
		fpn_printf("==== mbuf crypto API test : FAILED ====\n");
#endif /* !FP_TEST_FPN0_CRYPTO_SUPPORT */
}


/*
 * Send an icmp echo reply to m, assuming m is an echo request packet
 * starting at ethernet layer (test_fpn0_icmp_echo(m) != 0).
 */
uint8_t fp_test_fpn0_is_icmp_echo(struct mbuf *m)
{
	struct fp_ip *ip = (struct fp_ip *)(mtod(m, char *) + sizeof(struct fp_ether_header));
	struct fp_icmphdr *icmph;
	int len = m_len(m) - sizeof(struct fp_ether_header);
	
	if (ip->ip_v != FP_IPVERSION)
		return 0;
	if (len < (int)(sizeof(struct fp_ip) + sizeof(struct fp_icmphdr)))
		return 0;
	if (ip->ip_hl != (sizeof(struct fp_ip) >> 2)) /* IP opt and malformed header */
		return 0;
	if (ip->ip_p != FP_IPPROTO_ICMP)
		return 0;

	icmph = (struct fp_icmphdr *)(ip+1);
	if (icmph->icmp_type != 8)
		return 0;
	
	/* return last byte of dst IP address */
	return ntohl(ip->ip_dst.s_addr) & 0xFF;
}

static void test_fpn0_answer_icmp_echo(struct mbuf *m)
{
	struct fp_ip *ip = (struct fp_ip *)(mtod(m, char *) + sizeof(struct fp_ether_header));
	struct fp_icmphdr *icmph;
	uint32_t addr;
	char tmp[FP_ETHER_ADDR_LEN];

	/*
	 * Swap ethernet addresses. This will update destination mac address
	 * which is unspecified in the first icmp request sent by Linux.
	 * XXX assume ethernet.
	 */
	memcpy(tmp, mtod(m, char *), FP_ETHER_ADDR_LEN);
	memcpy(mtod(m, char *), mtod(m, char *) + FP_ETHER_ADDR_LEN, FP_ETHER_ADDR_LEN);
	memcpy(mtod(m, char *) + FP_ETHER_ADDR_LEN, tmp, FP_ETHER_ADDR_LEN);

	/* swap IP src and dst */
	addr = ip->ip_src.s_addr;
	ip->ip_src.s_addr = ip->ip_dst.s_addr;
	ip->ip_dst.s_addr = addr;
	/*
	 * The checksum of the IP header does not need to be computed [again],
	 * because swapping the source and the destination addresses within it
	 * does not change the value of its checksum.
	 */
	
	/* reflect an echo reply */
	icmph = (struct fp_icmphdr *)(ip+1);
	icmph->icmp_type = 0;
	icmph->icmp_cksum = 0;
	icmph->icmp_cksum =
		fpn_cksum(m, sizeof(struct fp_ether_header) +
			  sizeof(struct fp_ip));

	/* send it */
	fpn_send_exception(m, m_input_port(m));
	FP_EXCEP_STATS_INC(fp_shared->exception_stats, LocalBasicExceptions);
}


struct test_params {
	unsigned int m1_len;
	unsigned int m2_len;
	unsigned int split_offset;
};

#define GOTO_FAIL(str, ...) do {					\
       fpn_printf("== mbuf API test FAILED at line %d: <" str "> ==\n", \
		  __LINE__,  ##__VA_ARGS__);				\
       goto fail;							\
} while(0)

/*
 * Test mbuf API
 */
static void test_fpn0_mbuf_audit(void)
{
	struct mbuf *m = NULL, *m2 = NULL, *m3 = NULL;
	struct sbuf *s = NULL, *s_prev = NULL;
	char *data;
	char *hdr;
	unsigned int i, j;
	uint16_t len;
	uint32_t max_segment_len = 0;
	char *buf = glb_buf[fpn_get_core_num()];

	struct test_params test_params[] = { 
		{ .m1_len = 2000, .m2_len = 2000, .split_offset=3000 },
		{ .m1_len = 1000, .m2_len = 2000, .split_offset=500 },
		{ .m1_len = 1000, .m2_len = 2000, .split_offset=1000 },
		{ .m1_len = 2000, .m2_len = 1000, .split_offset=500 },
		{ .m1_len = 4000, .m2_len = 1000, .split_offset=1900 },
		{ .m1_len = 20,   .m2_len = 1000, .split_offset=1000 },
		{ .m1_len = 100,  .m2_len = 100,  .split_offset=110 },
		{ .m1_len = 5000, .m2_len = 3000, .split_offset=3000 },
	};
	
	fpn_printf("Testing mbuf API\n");
	
#define MBUF_TEST_DATA_LEN 1464
	fpn_printf("1/ alloc %d bytes data, prepend headers and free it\n", MBUF_TEST_DATA_LEN);
	m = m_alloc();
	if (m == NULL)
		GOTO_FAIL("Cannot allocate mbuf");
	data = (char *) m_append(m, (unsigned int)MBUF_TEST_DATA_LEN);
	if (data == NULL)
		GOTO_FAIL("Cannot append data");
	if (m_len(m) != MBUF_TEST_DATA_LEN)
		GOTO_FAIL("Bad length");
	if (((void *)m_tail(m) - mtod(m, void *)) != MBUF_TEST_DATA_LEN)
		GOTO_FAIL("Bad tail pointer");
	memset(data, 0x66, m_len(m));
	if (! m_is_contiguous(m))
		GOTO_FAIL("Buffer should be continuous");
#define MBUF_TEST_INPUT_PORT 3
	m_set_input_port(m, MBUF_TEST_INPUT_PORT);
	if (m_input_port(m) != MBUF_TEST_INPUT_PORT)
		GOTO_FAIL("Bad input port");
#define MBUF_TEST_HDR1_LEN 20
	hdr = m_prepend(m, MBUF_TEST_HDR1_LEN);
	if (hdr == NULL)
		GOTO_FAIL("Cannot prepend");
	if (m_len(m) != MBUF_TEST_DATA_LEN + MBUF_TEST_HDR1_LEN)
		GOTO_FAIL("Bad length");
	if (data - hdr != MBUF_TEST_HDR1_LEN)
		GOTO_FAIL("Prepend failed");
	memset(hdr, 0x55, MBUF_TEST_HDR1_LEN);
#define MBUF_TEST_HDR2_LEN 30
	hdr = m_prepend(m, MBUF_TEST_HDR2_LEN);
	if (hdr == NULL)
		GOTO_FAIL("Cannot prepend");
#define MBUF_TEST_ALL_HDRS_LEN (MBUF_TEST_HDR1_LEN+MBUF_TEST_HDR2_LEN)
	if (m_len(m) != MBUF_TEST_DATA_LEN + MBUF_TEST_ALL_HDRS_LEN)
		GOTO_FAIL("Bad length");
	if (data - hdr != MBUF_TEST_ALL_HDRS_LEN)
		GOTO_FAIL("Prepend failed");
	memset(hdr, 0x55, MBUF_TEST_HDR2_LEN);
	if (data != m_adj(m, MBUF_TEST_ALL_HDRS_LEN))
		GOTO_FAIL("m_adj failed");
	if (m_len(m) != MBUF_TEST_DATA_LEN)
		GOTO_FAIL("Bad length");
	for (i=0; i<MBUF_TEST_DATA_LEN; i++) {
		if (data[i] != 0x66)
			GOTO_FAIL("Data corrupted at %d", i);
	}
	m_freem(m);
	m = NULL;
	
	fpn_printf("* test m_trim\n");
	m = m_alloc();
	if (m == NULL)
		GOTO_FAIL("Cannot allocate mbuf");
	for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
		buf[j] = j;
	M_FOREACH_SEGMENT(m, s) {
		max_segment_len = s_len(s) + s_headroom(s) + s_tailroom(s);
		fpn_printf("The original sbuf at [%p]: len=%d, headroom=%d, tailroom=%d\n",
			s, s_len(s), s_headroom(s), s_tailroom(s));
	}
	if (max_segment_len < 500) {
		GOTO_FAIL("The max segment len is too small !\n");
	}
	fpn_printf("\nm_trim on single segment mbuf\n");
	if (m_copyfrombuf(m, 0, buf, (max_segment_len - 500)) != max_segment_len - 500)
		GOTO_FAIL("copyfrombuf failed");
	m_dump(m, 0);
	m_trim(m, 100);
	fpn_printf("after m_trim len %d\n", 100);
	m_dump(m, 0);

	fpn_printf("\nm_trim on double segment mbuf\n");
	if (m_copyfrombuf(m, 0, buf, (max_segment_len + 500)) != max_segment_len + 500)
		GOTO_FAIL("copyfrombuf failed");
	m_dump(m, 0);
	m_trim(m, 100);
	fpn_printf("after m_trim len %d\n", 100);
	m_dump(m, 0);

	fpn_printf("\nm_trim on multiple segment mbuf, and trim one sgment\n");
	if (m_copyfrombuf(m, 0, buf, (2 * max_segment_len + 500)) != 2 * max_segment_len + 500)
		GOTO_FAIL("copyfrombuf failed");
	fpn_printf("before m_trim\n");
	m_dump(m, 0);
	m_trim(m, max_segment_len + 100);
	fpn_printf("after m_trim len %d\n", max_segment_len + 100);
	m_dump(m, 0);

	fpn_printf("\nm_trim on multiple segment mbuf, and trim more than one sgment\n");
	if (m_copyfrombuf(m, 0, buf, (2 * max_segment_len + 500)) != 2 * max_segment_len + 500)
		GOTO_FAIL("copyfrombuf failed");
	fpn_printf("before m_trim\n");
	m_dump(m, 0);
	m_trim(m, 2 * max_segment_len + 100);
	fpn_printf("after m_trim len %d\n", 2 * max_segment_len + 100);
	m_dump(m, 0);

	m_freem(m);
	m = NULL;

	for (i=0; i < (sizeof(test_params)/sizeof(struct test_params)); i++) {

		fpn_printf("TEST %d\n", i);

		fpn_printf("* test m_copyfrombuf, m_copytobuf\n");
		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		fpn_printf("Copy buffer in mbuf (using 2 calls of m_copyfrombuf)\n");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		if (m_copyfrombuf(m, test_params[i].m1_len, buf+test_params[i].m1_len, 
				  test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copyfrombuf failed");
		m_dump(m, 0);
		fpn_printf("Copy mbuf to buffer (using 2 calls of m_copytobuf)\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf, m, 0, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copytobuf failed");
		if (m_copytobuf(buf+test_params[i].m1_len, m, test_params[i].m1_len, 
				test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len+test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m);
		m = NULL;

		/* same, but reverse copy order */
		fpn_printf("* test m_copyfrombuf, m_copytobuf (reversed copy)\n");
		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		fpn_printf("Copy buffer in mbuf (using 2 calls of m_copyfrombuf)\n");
		if (m_copyfrombuf(m, test_params[i].m1_len, buf+test_params[i].m1_len, 
				  test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copyfrombuf failed");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		m_dump(m, 0);
		fpn_printf("Copy mbuf to buffer (using 2 calls of m_copytobuf)\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf+test_params[i].m1_len, m, test_params[i].m1_len, 
				test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copytobuf failed");
		if (m_copytobuf(buf, m, 0, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len+test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m);
		m = NULL;

		/* m_copytobuf(), m_copyfrombuf() */

		fpn_printf("* test m_copyfrombuf, m_copytobuf (overwrite data)\n");

		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		fpn_printf("Copy buffer in mbuf (using 3 calls of m_copyfrombuf)\n");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		len = test_params[i].m1_len + test_params[i].m2_len - test_params[i].split_offset;
		if (m_copyfrombuf(m, test_params[i].split_offset, 
				  buf+test_params[i].split_offset, len) != len)
			GOTO_FAIL("copyfrombuf failed");
		if (m_copyfrombuf(m, test_params[i].m1_len, buf+test_params[i].m1_len, 
				  test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copyfrombuf failed");
		m_dump(m, 0);
		fpn_printf("Copy mbuf to buffer (using 2 calls of m_copytobuf)\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf, m, 0, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copytobuf failed");
		if (m_copytobuf(buf+test_params[i].m1_len, m, test_params[i].m1_len, 
				test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len+test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m);
		m = NULL;

		/* m_cat() */

		fpn_printf("* test m_cat\n");
		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		fpn_printf("Create 2 mbufs from buffer using m_copyfrombuf\n");
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		m2 = m_alloc();
		if (m2 == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m2, 0, buf+test_params[i].m1_len, 
				  test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copyfrombuf failed");
		fpn_printf("m dump\n");
		m_dump(m, 0);
		fpn_printf("m2 dump\n");
		m_dump(m2, 0);
		fpn_printf("Concat mbufs using m_cat\n");
		if (m_cat(m, m2) < 0)
			GOTO_FAIL("Cannot concat buffers");
		m2 = NULL; /* m2 is freed by m_cat */
		fpn_printf("m dump, after m_cat\n");
		m_dump(m, 0);
		fpn_printf("Copy reassembled mbuf in buffer using m_copytobuf\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf, m, 0, m_len(m)) != m_len(m))
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len+test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");

		/* m_split() */

		fpn_printf("* test m_split\n");
		fpn_printf("Split the reassembled mbuf at %d\n", test_params[i].split_offset);
		m2 = m_split(m, test_params[i].split_offset);
		if (m2 == NULL)
			GOTO_FAIL("m_split failed");
		fpn_printf("m dump, after m_split\n");
		m_dump(m, 0);
		fpn_printf("m2 dump, after m_split\n");
		m_dump(m2, 0);
		if(memcmp(mtopriv(m2,void *), mtopriv(m,void *), FPN_MBUF_PRIV_COPY_SIZE))
			GOTO_FAIL("copy mbuf_priv failed");
		fpn_printf("Copy the 2 mbufs in the buffer\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf, m, 0, m_len(m)) != m_len(m))
			GOTO_FAIL("copytobuf failed");
		if (m_copytobuf(buf+m_len(m), m2, 0, m_len(m2)) != m_len(m2))
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len+test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");

		/* m_dup() */

		fpn_printf("* test m_dup\n");
		fpn_printf("Try to duplicate m in m2, and check data\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf+m_len(m), m2, 0, m_len(m2)) != m_len(m2))
			GOTO_FAIL("copytobuf failed");
		m_freem(m2);
		m2 = m_dup(m);
		if (m2 == NULL)
			GOTO_FAIL("Cannot duplicate mbuf");
		if(memcmp(mtopriv(m2,void *), mtopriv(m,void *), FPN_MBUF_PRIV_COPY_SIZE))
			GOTO_FAIL("copy mbuf_priv failed");
		if (m_copytobuf(buf, m2, 0, m_len(m2)) != m_len(m2))
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len+test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m2);
		m2 = NULL;

		m_freem(m);
		m = NULL;

		fpn_printf("Test the special failure branch for m_dup.\n");
		m = m_alloc();
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");

		fpn_printf("Extend the mbuf first segment.\n");
		__s_append(m_first_seg(m), s_headroom(m_first_seg(m))+s_tailroom(m_first_seg(m))+1);
		m2 = m_dup(m);
		if (NULL != m2)
			GOTO_FAIL("When copylen > headroom + tailroom, m_dup should return NULL.");
		fpn_printf("m_dup() return a NULL pointer as expected.\n");
		m_freem(m);
		m = NULL;

		/* m_shrink() */

		fpn_printf("* test m_shrink\n");
		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		fpn_printf("Create 1 mbuf from buffer using m_copyfrombuf\n");
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		fpn_printf("before m_shrink()\n");
		m_dump(m, 0);
		fpn_printf("try to m_shrink()\n");
		m = m_shrink(m);
		if (m == NULL)
			GOTO_FAIL("m_shrink() failed");
		m_dump(m, 0);
		s_prev = NULL;
		M_FOREACH_SEGMENT(m, s) {
			/* check that all segments has zero tailroom (except last one) */
			if (s_prev && s_tailroom(s_prev) != 0) {
				GOTO_FAIL("one segment has non-zero tailroom (%u)", s_tailroom(s_prev));
			}
			s_prev = s;
		}
		if (m_copytobuf(buf, m, 0, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copytobuf failed");
		for (j=0; j<test_params[i].m1_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m);
		m = NULL;

		/* m_copypack() */

		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		fpn_printf("Create 2 mbufs from buffer using m_copyfrombuf\n");
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		m2 = m_alloc();
		if (m2 == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m2, 0, buf+test_params[i].m1_len,
				  test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copyfrombuf failed");
		fpn_printf("m dump\n");
		m_dump(m, 0);
		fpn_printf("m2 dump\n");
		m_dump(m2, 0);
		fpn_printf("Concat mbufs using m_cat\n");
		if (m_cat(m, m2) < 0)
			GOTO_FAIL("Cannot concat buffers");
		fpn_printf("m dump, after m_cat\n");
		m_dump(m, 0);
		m2 = NULL; /* m2 is freed by m_cat */

		fpn_printf("* test m_copypack\n");
		fpn_printf("Copy the beginning of m in m2\n");
		m2 = m_copypack(m, 0, test_params[i].split_offset);
		if (m2 == NULL)
			GOTO_FAIL("m_copypack failed");
		fpn_printf("Copy the end of m in m3\n");
		m3 = m_copypack(m, test_params[i].split_offset,
				m_len(m) - test_params[i].split_offset);
		if (m3 == NULL)
			GOTO_FAIL("m_copypack failed");
		fpn_printf("Concat m2 and m3 using m_cat\n");
		if (m_cat(m2, m3) < 0)
			GOTO_FAIL("Cannot concat buffers");
		m3 = NULL; /* m3 is freed by m_cat */
		fpn_printf("Free initial m\n");
		m_freem(m);
		m = NULL;
		fpn_printf("m2 dump\n");
		m_dump(m2, 0);
		fpn_printf("Copy the mbuf in the buffer\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf, m2, 0, m_len(m2)) != m_len(m2))
			GOTO_FAIL("copytobuf failed");
		for (j = 0; j < test_params[i].m1_len + test_params[i].m2_len; j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m2);
		m2 = NULL;

		/* m_adj2() */

		for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
			buf[j] = j;
		m = m_alloc();
		fpn_printf("Create 2 mbufs from buffer using m_copyfrombuf\n");
		if (m == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m, 0, buf, test_params[i].m1_len) != test_params[i].m1_len)
			GOTO_FAIL("copyfrombuf failed");
		m2 = m_alloc();
		if (m2 == NULL)
			GOTO_FAIL("Cannot allocate mbuf");
		if (m_copyfrombuf(m2, 0, buf+test_params[i].m1_len,
				  test_params[i].m2_len) != test_params[i].m2_len)
			GOTO_FAIL("copyfrombuf failed");
		fpn_printf("m dump\n");
		m_dump(m, 0);
		fpn_printf("m2 dump\n");
		m_dump(m2, 0);
		fpn_printf("Concat mbufs using m_cat\n");
		if (m_cat(m, m2) < 0)
			GOTO_FAIL("Cannot concat buffers");
		fpn_printf("m dump, after m_cat\n");
		m_dump(m, 0);
		m2 = NULL; /* m2 is freed by m_cat */

		fpn_printf("* test m_adj2\n");
		fpn_printf("Remove %d data at beginning of mbuf\n", test_params[i].split_offset);
		if (m_adj2(m, test_params[i].split_offset) == NULL)
			GOTO_FAIL("m_adj2 failed");
		fpn_printf("m dump, after m_adj2\n");
		m_dump(m, 0);
		fpn_printf("Copy the mbuf in the buffer\n");
		memset(buf, 0, TEST_FPN0_MBUF_SIZE);
		if (m_copytobuf(buf+test_params[i].split_offset, m, 0,
				m_len(m)) != m_len(m))
			GOTO_FAIL("copytobuf failed");
		for (j = test_params[i].split_offset;
		     j < test_params[i].m1_len + test_params[i].m2_len -
			     test_params[i].split_offset;
		     j++)
			if (buf[j] != (char)j)
				GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
		fpn_printf("Data ok\n");
		m_freem(m);
		m = NULL;

#ifdef CONFIG_MCORE_FPN_MBUF_CLONE
#define CLONE_PREPEND_LEN 10
		{
			struct mbuf *c, *c1, *c2;
			/* m_clone() */

			fpn_printf("* test m_clone\n");

			/* alloc a new mbuf m and fill it */
			for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
				buf[j] = j;
			m = m_alloc();
			fpn_printf("Create 1 mbuf from buffer using m_copyfrombuf\n");
			len = test_params[i].m1_len;
			if (m == NULL)
				GOTO_FAIL("Cannot allocate mbuf");
			if (m_copyfrombuf(m, 0, buf, len) != len)
				GOTO_FAIL("copyfrombuf failed");

			/* clone m, store the pointer in c, then free m */
			fpn_printf("mbuf m:\n");
			m_dump(m, 0);
			c = m_clone(m);
			if (c == NULL)
				GOTO_FAIL("m_clone failed");
			fpn_printf("mbuf c:\n");
			m_dump(c, 0);
			m_freem(m);
			m = NULL;

			/* do 2 clones of c: c1 and c2 */
			c1 = m_clone(c);
			if (c1 == NULL) {
				m_freem(c);
				GOTO_FAIL("m_clone failed");
			}
			c2 = m_clone(c);
			if (c2 == NULL) {
				m_freem(c);
				m_freem(c1);
				GOTO_FAIL("m_clone failed");
			}
			fpn_printf("mbuf c1:\n");
			m_dump(c1, 0);
			fpn_printf("mbuf c2:\n");
			m_dump(c2, 0);

			fpn_printf("prepend data to c1 and c2\n");

			/* prepend data to c1 */
			hdr = m_prepend(c1, CLONE_PREPEND_LEN);
			if (hdr == NULL) {
				m_freem(c);
				m_freem(c1);
				m_freem(c2);
				GOTO_FAIL("Cannot prepend in c1");
			}
			memset(hdr, 0x1, CLONE_PREPEND_LEN);

			/* prepend different data to c2 */
			hdr = m_prepend(c2, CLONE_PREPEND_LEN);
			if (hdr == NULL) {
				m_freem(c);
				m_freem(c1);
				m_freem(c2);
				GOTO_FAIL("Cannot prepend in c2");
			}
			memset(hdr, 0x2, CLONE_PREPEND_LEN);

			/* dump c1, c2 */
			fpn_printf("mbuf c:\n");
			m_dump(c, 0);
			fpn_printf("mbuf c1:\n");
			m_dump(c1, 0);
			fpn_printf("mbuf c2:\n");
			m_dump(c2, 0);

			/* check data of c, and free it */
			if (m_copytobuf(buf, c, 0, len) != len) {
				m_freem(c);
				m_freem(c1);
				m_freem(c2);
				GOTO_FAIL("copytobuf failed");
			}
			for (j=0; j<len; j++) {
				if (buf[j] != (char)j) {
				m_freem(c);
				m_freem(c1);
				m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}
			m_freem(c);

			/* check data of c1, and free it */
			if (m_copytobuf(buf, c1, 0, CLONE_PREPEND_LEN + len) !=
			    (size_t)(CLONE_PREPEND_LEN + len)) {
				m_freem(c1);
				m_freem(c2);
				GOTO_FAIL("copytobuf failed");
			}
			for (j=0; j<len; j++) {
				if (buf[j+CLONE_PREPEND_LEN] != (char)j) {
					m_freem(c1);
					m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}
			for (j=0; j<CLONE_PREPEND_LEN; j++) {
				if (buf[j] != 0x01) {
					m_freem(c1);
					m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}
			m_freem(c1);

			/* check data of c2, and free it */
			if (m_copytobuf(buf, c2, 0, CLONE_PREPEND_LEN + len) !=
			    (size_t)(CLONE_PREPEND_LEN + len)) {
				m_freem(c2);
				GOTO_FAIL("copytobuf failed");
			}
			for (j=0; j<len; j++) {
				if (buf[j+CLONE_PREPEND_LEN] != (char)j) {
					m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}
			for (j=0; j<CLONE_PREPEND_LEN; j++) {
				if (buf[j] != 0x02) {
					m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}

			/* unclone (it will duplicate data) and re-check*/
			fpn_printf("unclone c2\n");
			c2 = m_unclone(c2);
			if (c2 == NULL)
				GOTO_FAIL("m_unclone failed");

			fpn_printf("mbuf c2:\n");
			m_dump(c2, 0);
			if (m_copytobuf(buf, c2, 0, CLONE_PREPEND_LEN + len) !=
			    (size_t)(CLONE_PREPEND_LEN + len)) {
				m_freem(c2);
				GOTO_FAIL("copytobuf failed");
			}
			for (j=0; j<len; j++) {
				if (buf[j+CLONE_PREPEND_LEN] != (char)j) {
					m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}
			for (j=0; j<CLONE_PREPEND_LEN; j++) {
				if (buf[j] != 0x02) {
					m_freem(c2);
					GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
				}
			}

			m_freem(c2);



			fpn_printf("* test m_cat on cloned mbufs\n");

			/* alloc a new mbuf m and fill it */
			for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
				buf[j] = j;
			m = m_alloc();
			fpn_printf("Create 1 mbuf from buffer using m_copyfrombuf\n");
			len = test_params[i].m1_len+test_params[i].m2_len;
			if (m == NULL)
				GOTO_FAIL("Cannot allocate mbuf");
			if (m_copyfrombuf(m, 0, buf, len) != len)
				GOTO_FAIL("copyfrombuf failed");

			m2 = m_split(m, test_params[i].split_offset);
			if (m2 == NULL)
				GOTO_FAIL("m_split failed");
			fpn_printf("m dump, after m_split\n");
			m_dump(m, 0);
			fpn_printf("m2 dump, after m_split\n");
			m_dump(m2, 0);

			/* clone m and m2: c1 and c2 */
			c1 = m_clone(m);
			if (c1 == NULL)
				GOTO_FAIL("m_clone failed");
			c2 = m_clone(m2);
			if (c2 == NULL) {
				m_freem(c1);
				GOTO_FAIL("m_clone failed");
			}
			fpn_printf("mbuf c1:\n");
			m_dump(c1, 0);
			fpn_printf("mbuf c2:\n");
			m_dump(c2, 0);

			/* m_cat(c1, c2) */
			if (m_cat(c1, c2) != 0) {
				m_freem(c1);
				m_freem(c2);
				GOTO_FAIL("m_cat failed");
			}

			/* check data in c1 */
			len = test_params[i].m1_len + test_params[i].m2_len;
			if (m_len(c1) != len) {
				m_freem(c1);
				GOTO_FAIL("bad len");
			}
			if (m_copytobuf(buf, c1, 0, len) != len)
				GOTO_FAIL("copytobuf failed");
			for (j=0; j<len; j++) {
				if (buf[j] != (char)j)
					GOTO_FAIL("corrupted data at %d (%x != %x)",
						  j, j&0xff, buf[j]&0xff);
			}

			/* check data in m */
			len = test_params[i].split_offset;
			if (m_len(m) != len) {
				m_freem(c1);
				GOTO_FAIL("bad len");
			}
			if (m_copytobuf(buf, m, 0, len) != len)
				GOTO_FAIL("copytobuf failed");
			for (j=0; j<len; j++) {
				if (buf[j] != (char)j)
					GOTO_FAIL("corrupted data at %d (%x != %x)",
						  j, j&0xff, buf[j]&0xff);
			}
			m_freem(m);
			m = NULL;

			/* check data in m2 */
			len = test_params[i].m1_len + test_params[i].m2_len -
				test_params[i].split_offset;
			if (m_len(m2) != len) {
				m_freem(c1);
				GOTO_FAIL("bad len");
			}
			if (m_copytobuf(buf, m2, 0, len) != len)
				GOTO_FAIL("copytobuf failed");
			for (j=0; j<len; j++) {
				if (buf[j] != (char)(j+test_params[i].split_offset))
					GOTO_FAIL("corrupted data at %d (%x != %x)",
						  j, (j+test_params[i].split_offset) & 0xff,
						  buf[j]&0xff);
			}
			m_freem(m2);
			m2 = NULL;

			/* re-check data in c1 after m and m2 are freed */
			len = test_params[i].m1_len + test_params[i].m2_len;
			if (m_len(c1) != len) {
				m_freem(c1);
				GOTO_FAIL("bad len");
			}
			if (m_copytobuf(buf, c1, 0, len) != len)
				GOTO_FAIL("copytobuf failed");
			for (j=0; j<len; j++) {
				if (buf[j] != (char)j)
					GOTO_FAIL("corrupted data at %d (%x != %x)",
						  j, j&0xff, buf[j]&0xff);
			}
			m_freem(c1);


			fpn_printf("Data ok\n");

		}

#endif /* CONFIG_MCORE_CLONE */

		fpn_printf("== TEST %d OK ==\n", i);
	}

	fpn_printf("* test m_pullup\n");
	m = m_alloc();
	if (m == NULL)
		GOTO_FAIL("Cannot allocate mbuf");
	m2 = m_alloc();
	if (m2 == NULL)
		GOTO_FAIL("Cannot allocate mbuf");
	for (j=0; j<TEST_FPN0_MBUF_SIZE; j++)
		buf[j] = j;
	fpn_printf("\nm_pullup on double segment mbuf\n");
	if (m_copyfrombuf(m, 0, buf, (max_segment_len - 400)) != max_segment_len - 400)
		GOTO_FAIL("copyfrombuf failed");
	if (m_copyfrombuf(m2, 0, buf+(max_segment_len - 400), 200) != 200)
		GOTO_FAIL("copyfrombuf failed");
	if (m_cat(m, m2) < 0)
		GOTO_FAIL("Cannot concat buffers");
	m2 = NULL; /* m2 is freed by m_cat */
	fpn_printf("m dump before m_pullup\n");
	m_dump(m,0);

	m = m_pullup(m,max_segment_len - 300);
	if (m == NULL)
		GOTO_FAIL("Cannot pullup");

	fpn_printf("m dump after m_pullup len %d\n",max_segment_len - 300);
	m_dump(m,0);

	m = m_pullup(m,max_segment_len - 250);
	if (m == NULL)
		GOTO_FAIL("Cannot pullup");

	fpn_printf("m dump after m_pullup len %d\n",max_segment_len - 250);
	m_dump(m,0);

	m = m_pullup(m,max_segment_len - 200);
	if (m == NULL)
		GOTO_FAIL("Cannot pullup");

	fpn_printf("m dump after m_pullup len %d\n",max_segment_len - 200);
	m_dump(m,0);

	if (m_copytobuf(buf, m, 0, max_segment_len - 200) != max_segment_len - 200)
			GOTO_FAIL("copytobuf failed");
	for (j=0; j<max_segment_len - 200; j++)
		if (buf[j] != (char)j)
			GOTO_FAIL("corrupted data at %d (%x != %x)", j, j&0xff, buf[j]&0xff);
	fpn_printf("Data ok\n");
	m_freem(m);
	m = NULL;

	/* TODO:
	 *  - check mtags 
	 *  - use cases:
	 *    o multibuffer checksum
	 *    o copy mbuf to mbuf
	 */

	fpn_printf("== mbuf API test OK ==\n");

 fail:
	if (m)
		m_freem(m);
	if (m2)
		m_freem(m2);
	if (m3)
		m_freem(m2);
}
#undef GOTO_FAIL

/*
 * Test checksum computation.
 * Use valid checksums pre-computed with the "scapy" tool using the
 * following python function:
 *
 *   >>> def get_cksum(len):
 *   ...   s=""
 *   ...   for i in range(0, len):
 *   ...     s+=chr(i%256)
 *   ...   print hex(checksum(s))
 *   ... 
 *   >>> get_cksum(1)
 *   0xffff
 *   >>> get_cksum(8)
 *   0xf3ef
 *   >>> get_cksum(4000)
 *   0xf32a
 *   >>> get_cksum(4001)
 *   0x532a
 */

struct checksum_test {
	uint32_t length; /* length of packet data starting with '\x00' */
	uint16_t ok_checksum; /* pre-computed valid checksum. */
};

/*
 * The following range of data lengths allows to test all memory layouts
 * of packets.
 */
static struct checksum_test cksum_tests[] = {
	{.length=1,    .ok_checksum=0xffff},
	{.length=2,    .ok_checksum=0xfffe},
	{.length=3,    .ok_checksum=0xfdfe},
	{.length=4,    .ok_checksum=0xfdfb},
	{.length=5,    .ok_checksum=0xf9fb},
	{.length=6,    .ok_checksum=0xf9f6},
	{.length=7,    .ok_checksum=0xf3f6},
	{.length=8,    .ok_checksum=0xf3ef},
	{.length=100,  .ok_checksum=0x6432},
	{.length=101,  .ok_checksum=0x0032},
	{.length=500,  .ok_checksum=0x5b62},
	{.length=501,  .ok_checksum=0x6761},
	{.length=1000, .ok_checksum=0x6e7c},
	{.length=1001, .ok_checksum=0x867b},
	{.length=1513, .ok_checksum=0x05fc},
	{.length=1514, .ok_checksum=0x0513},
	{.length=1515, .ok_checksum=0x1b12},
	{.length=2500, .ok_checksum=0xf618},
	{.length=2501, .ok_checksum=0x3218},
	{.length=4000, .ok_checksum=0xf32a},
	{.length=4001, .ok_checksum=0x532a},
	{.length=8000, .ok_checksum=0xd443},
	{.length=8001, .ok_checksum=0x9443},
};

/* The maximum length of a "small" segment */
static uint32_t max_small_slen = 5;

/*
 * Test checksum computation.
 * - if max_seg1_len < cksum->length, force mbuf splitting in multiple segments
 * - seg1_odd_addr equal 0 or 1
 * - seg2_odd_addr equal 0 or 1
 *
 * Return 0 if successful.
 * Return 1 if invalid checksum.
 * Return -1 if m_alloc() failed.
 */
static int
test_checksum(struct checksum_test *cksum_test, uint32_t max_seg1_len,
	      int seg1_odd_addr, int seg2_odd_addr)
{
	struct mbuf *m1;
	struct mbuf *m2;
	char *buf;
	uint32_t len;
	uint32_t slen;
	uint32_t i;
	uint16_t cksum;

	m1 = m_alloc();
	if (m1 == NULL) {
		fpn_printf("%s: m_alloc failed\n", __FUNCTION__);
		return -1;
	}
	slen = cksum_test->length;
	if (slen > max_seg1_len)
		slen = max_seg1_len;
	if (slen + seg1_odd_addr > m_tailroom(m1))
		slen = m_tailroom(m1) - seg1_odd_addr;
	buf = m_append(m1, slen + seg1_odd_addr);
	if (seg1_odd_addr)
		buf = m_adj(m1, 1);
	for (i = 0; i < slen; i++)
		buf[i] = (char) i;

	/* Allocate as much additional mbuf as needed. */
	len = slen;
	while (len < cksum_test->length) {
		m2 = m_alloc();
		if (m2 == NULL) {
			m_freem(m1);
			fpn_printf("%s: m_alloc failed\n", __FUNCTION__);
			return -1;
		}
		slen = cksum_test->length - len;
		if ((slen + seg2_odd_addr) > m_tailroom(m2))
			slen = m_tailroom(m2) - seg2_odd_addr;
		buf = m_append(m2, slen + seg2_odd_addr);
		if (seg2_odd_addr)
			buf = m_adj(m2, 1);
		for (i = 0; i < slen; i++)
			buf[i] = (char) (len + i);
		(void) m_cat(m1, m2);
		len += slen;
	}
	cksum = fpn_cksum(m1, 0);
	m_freem(m1);
	if (cksum == htons(cksum_test->ok_checksum))
		return 0;
	fpn_printf(" fpn_cksum: 0x%04x != 0x%04x\n for len=%u"
		   "  max_seg1_len=%u seg1_odd_addr=%d seg2_odd_addr=%d\n",
		   cksum, htons(cksum_test->ok_checksum), len, max_seg1_len,
		   seg1_odd_addr, seg2_odd_addr);
	return 1;
}

static void
do_cksum_tests(int seg1_odd_addr, int seg2_odd_addr)
{
	struct checksum_test *cksum_test;
	uint32_t pktlen;
	uint32_t slen;
	uint32_t i;
	int nb_failed;
	int diag;
	static const char * even_odd[2] = {
		"even",
		"odd",
	};

	fpn_printf("Test ckecksum computation with:\n"
		   "     - the first segment starting at a %s boundary\n"
		   "     - other segments, if any, starting at a %s boundary\n",
		   even_odd[seg1_odd_addr & 1], even_odd[seg2_odd_addr & 1]);

	nb_failed = 0;
	for (i = 0; i < sizeof(cksum_tests) / sizeof(cksum_tests[0]); i++) {
		cksum_test = &cksum_tests[i];
		pktlen = cksum_test->length;
		for (slen = 1; slen <= max_small_slen; slen++) {
			/*
			 * Test checksum computation on packets with
			 * a "small" first segment.
			 */
			diag = test_checksum(cksum_test, slen,
					     seg1_odd_addr & 1,
					     seg2_odd_addr & 1);
			if (diag < 0)
				break;
			nb_failed += diag;
			if (slen >= pktlen)
				continue;

			/*
			 * Test checksum computation on a packet with
			 * a full first segment.
			 */
			diag = test_checksum(cksum_test, pktlen,
					     seg1_odd_addr & 1,
					     seg2_odd_addr & 1);
			if (diag < 0)
				break;
			nb_failed += diag;

			/*
			 * Test checksum computation on packets with
			 * a "small" last segment.
			 */
			diag = test_checksum(cksum_test, pktlen - slen,
					     seg1_odd_addr & 1,
					     seg2_odd_addr & 1);
			if (diag < 0)
				break;
			nb_failed += diag;
		}
	}
	if (nb_failed == 0)
		fpn_printf("   All tests OK\n");
	else
		fpn_printf("   %d tests failed\n", nb_failed);
}

static void test_fpn0_cksum_audit(void)
{
	do_cksum_tests(0, 0);
	do_cksum_tests(1, 0);
	do_cksum_tests(0, 1);
	do_cksum_tests(1, 1);
}

#define GOTO_FAIL(str, ...) do {					\
       fpn_printf("== mtag API test FAILED at line %d: <" str "> ==\n",	\
		  __LINE__,  ##__VA_ARGS__);				\
       goto fail;							\
} while(0)

/*
 * Test the MTAG API. This test is designed to work with:
 *    - CONFIG_MCORE_M_TAG_HASHTABLE_ORDER == 1
 *    - CONFIG_MCORE_M_TAG_EXTRA_COUNT == 2
 *
 * It will work if both values are greater or equel.
 *
 * If one config value is lower and the other is lower or equal, it
 * won't work.
 *
 * Else, it may work or not, depending on the config.
 */
static void test_fpn0_mtag_audit(void)
{
#ifdef CONFIG_MCORE_M_TAG
	struct mbuf *m = NULL;
	struct m_tag *mtag;
	int32_t mtag_type0, mtag_type1, mtag_type2, mtag_type3;
	int i, j, count, test;
	uint32_t val;

	fpn_printf("test mtag registration\n");

	/* Add mtag types */
	mtag_type0 = m_tag_type_register("test0");
	if (mtag_type0 < 0)
		GOTO_FAIL("Cannot register mtag test0");
	mtag_type1 = m_tag_type_register("test1");
	if (mtag_type1 < 0)
		GOTO_FAIL("Cannot register mtag test1");
	mtag_type2 = m_tag_type_register("test2");
	if (mtag_type2 < 0)
		GOTO_FAIL("Cannot register mtag test2");
	mtag_type3 = m_tag_type_register("test3");
	if (mtag_type3 < 0)
		GOTO_FAIL("Cannot register mtag test3");
	m_tag_type_dump();

	fpn_printf("test mtag initialization\n");

	m = m_alloc();
	if (m == NULL)
		GOTO_FAIL("Cannot allocate mbuf");

	m_tag_reset(m);

	for (test=0; test<3; test++) {
		if (!m_tag_is_empty(m))
			GOTO_FAIL("m_tag_is_empty(m) != 0");

		fpn_printf("test mtag add / modification / get\n");

		/* add a mtag */
		if (m_tag_add(m, mtag_type0, 0x1337beef))
			GOTO_FAIL("cannot add mtag");
		if (m_tag_get(m, mtag_type0, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0x1337beef)
			GOTO_FAIL("bad mtag value");
		if (m_tag_get_count(m) != 1)
			GOTO_FAIL("bad mtag count");

		/* add a mtag */
		if (m_tag_add(m, mtag_type1, 0xcafedeca))
			GOTO_FAIL("cannot add mtag");
		if (m_tag_get(m, mtag_type1, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0xcafedeca)
			GOTO_FAIL("bad mtag value");
		if (m_tag_get_count(m) != 2)
			GOTO_FAIL("bad mtag count");

		/* add a mtag */
		if (m_tag_add(m, mtag_type2, 0x0))
			GOTO_FAIL("cannot add mtag");
		if (m_tag_get(m, mtag_type2, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0x0)
			GOTO_FAIL("bad mtag value");
		if (m_tag_get_count(m) != 3)
			GOTO_FAIL("bad mtag count");

		/* add a mtag */
		if (m_tag_add(m, mtag_type3, 0x12345678))
			GOTO_FAIL("cannot add mtag");
		if (m_tag_get(m, mtag_type3, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0x12345678)
			GOTO_FAIL("bad mtag value");
		if (m_tag_get_count(m) != 4)
			GOTO_FAIL("bad mtag count");

		/* try to get the first mtag */
		if (m_tag_get(m, mtag_type0, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0x1337beef)
			GOTO_FAIL("bad mtag value");

		/* modify mtag */
		if (m_tag_add(m, mtag_type0, 0x666))
			GOTO_FAIL("cannot add mtag");
		if (m_tag_get(m, mtag_type0, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0x666)
			GOTO_FAIL("bad mtag value");
		if (m_tag_get_count(m) != 4)
			GOTO_FAIL("bad mtag count");

		/* modify mtag */
		if (m_tag_add(m, mtag_type2, 0x1))
			GOTO_FAIL("cannot add mtag");
		if (m_tag_get(m, mtag_type2, &val) < 0)
			GOTO_FAIL("cannot get mtag");
		if (val != 0x1)
			GOTO_FAIL("bad mtag value");
		if (m_tag_get_count(m) != 4)
			GOTO_FAIL("bad mtag count");

		fpn_printf("test mtag browse\n");

		/* browse mtag */
		count = 0;
		M_TAG_FOREACH(m, i, j, mtag) {
			if (mtag->id == mtag_type0 &&
			    mtag->val == 0x666)
				count ++;
			else if (mtag->id == mtag_type1 &&
				 mtag->val == 0xcafedeca)
				count ++;
			else if (mtag->id == mtag_type2 &&
				 mtag->val == 0x1)
				count ++;
			else if (mtag->id == mtag_type3 &&
				 mtag->val == 0x12345678)
				count ++;
			else
				GOTO_FAIL("invalid mtag");
		}
		if (count != 4)
			GOTO_FAIL("invalid mtag count");

		fpn_printf("test mtag deletion\n");

		/* delete mtag */
		if (m_tag_del(m, mtag_type0))
			GOTO_FAIL("cannot del mtag");
		if (m_tag_get_count(m) != 3)
			GOTO_FAIL("bad mtag count");

		if (m_tag_del(m, mtag_type1))
			GOTO_FAIL("cannot del mtag");
		if (m_tag_get_count(m) != 2)
			GOTO_FAIL("bad mtag count");

		if (m_tag_del(m, mtag_type3))
			GOTO_FAIL("cannot del mtag");
		if (m_tag_get_count(m) != 1)
			GOTO_FAIL("bad mtag count");

		if (m_tag_del(m, mtag_type2))
			GOTO_FAIL("cannot del mtag");
		if (m_tag_get_count(m) != 0)
			GOTO_FAIL("bad mtag count");
	}

	fpn_printf("== mtag test OK ==\n");
	m_freem(m);
	return;

 fail:
	if (m)
		m_freem(m);
	fpn_printf("== mtag test FAILED ==\n");
#else
	fpn_printf("== mtag support not compiled ==\n");
#endif
}
#undef GOTO_FAIL


/*
 * Display reassembly states
 */
static void test_fpn0_reass_info(void)
{
#ifdef CONFIG_MCORE_IP_REASS
	fp_ip_reass_display_info();
#else
	fpn_printf("undefined CONFIG_MCORE_IP_REASS\n");
#endif
}

static void test_fpn0_check_size(void)
{
	print_size();

#define p(x) fp_log_common(LOG_DEBUG, "sizeof(" #x ") is %d\n", (int)sizeof(x));
	p(struct mbuf);
	p(fp_mbuf_priv_t);
#undef p
}

/* structure and timer contexts shared between several timer tests */
struct test_fpn0_timers_ctx {
	struct callout callout;

	uint64_t launch_time;
	int      launch_cpu_id;
	unsigned target_ms;
	int      target_cpu_id;
	int      idx;
};
#define TEST_FPN0_TIMER_MAX 5
static FPN_DEFINE_SHARED(struct test_fpn0_timers_ctx, test_fpn0_timer[TEST_FPN0_TIMER_MAX]);

#define CYCLES_TO_SECONDS(cycles) (fpn_div64_64(cycles, fpn_get_clock_hz()))
#define CYCLES_TO_MS(cycles) (fpn_div64_64(cycles, fpn_get_clock_hz()/1000))
#define LOCAL_CYCLES_TO_SECONDS(cycles) (fpn_div64_64(cycles, fpn_get_local_clock_hz()))
#define LOCAL_CYCLES_TO_MS(cycles) (fpn_div64_64(cycles, fpn_get_local_clock_hz()/1000))

static void test_fpn0_timers_accuracy_handler(void *arg)
{
	struct test_fpn0_timers_ctx *timer = arg;
	int cpu_id;
	
	uint64_t timeout = fpn_get_clock_cycles() - timer->launch_time;

	cpu_id = fpn_get_core_num();

	fpn_printf("Timeout %d:"
	           " cycles=%"PRIu64" ms=%"PRIu64"[%d] core=%d->%d[%d]\n",
		   timer->idx, timeout,
		   CYCLES_TO_MS(timeout), timer->target_ms,
		   timer->launch_cpu_id, cpu_id, timer->target_cpu_id);
}

static void test_fpn0_timers_init(void)
{
	static FPN_DEFINE_SHARED(int, init_done) = 0;
	int i;

	for (i=0; i<TEST_FPN0_TIMER_MAX; i++) {
		if (init_done)
			callout_stop_sync(&test_fpn0_timer[i].callout);
		callout_init(&test_fpn0_timer[i].callout);
	}
	init_done = 1;
}

static void test_fpn0_timers_accuracy(void)
{
	int i;
	unsigned secs[TEST_FPN0_TIMER_MAX] = { 7, 7, 5, 1, 0 };
	int cpu_id = fpn_get_core_num();

	fpn_printf("Timers accuracy test (hz=%"PRIu64")\n", fpn_get_clock_hz());

	test_fpn0_timers_init();

	for (i=0; i<TEST_FPN0_TIMER_MAX; i++) {
		test_fpn0_timer[i].idx = i;
		test_fpn0_timer[i].launch_cpu_id = cpu_id;
		test_fpn0_timer[i].target_cpu_id = cpu_id;
		test_fpn0_timer[i].target_ms = secs[i] * 1000;

		fpn_printf("Scheduling timer %d in %u ms on core %d\n",
				i,
				test_fpn0_timer[i].target_ms,
				test_fpn0_timer[i].target_cpu_id);

		test_fpn0_timer[i].launch_time = fpn_get_clock_cycles();

		callout_reset(&test_fpn0_timer[i].callout,
		              secs[i],
			      test_fpn0_timers_accuracy_handler,
			      &test_fpn0_timer[i]);
	}
}

static FPN_DEFINE_SHARED(struct callout, test_fpn0_timer_callout);
static FPN_DEFINE_SHARED(volatile int, timer_scheduled);
static FPN_DEFINE_SHARED(volatile int, end_execution);

static void test_fpn0_timers_callout_handler(void *arg __fpn_maybe_unused)
{
	timer_scheduled = 1;

	while (!end_execution) ;

	end_execution = 0;
}

static void test_fpn0_timers_callout(void)
{
	uint64_t now;

	if (callout_init(&test_fpn0_timer_callout)) {
		fpn_printf("%s: Error: cannot allocate memory for timer\n",
			   __FUNCTION__);
		return ;
	}

	if (callout_reset(&test_fpn0_timer_callout, 1,
			  test_fpn0_timers_callout_handler, NULL)) {
		fpn_printf("%s: %d: Error: cannot reset timer\n",
			   __FUNCTION__, __LINE__);
		return ;
	}

	fpn_printf("Test 1: launch timer and stop it immediately: ");
	if (!callout_stop(&test_fpn0_timer_callout)) {
		fpn_printf("Error: cannot stop timer\n");
		return ;
	}
	else
		fpn_printf("Success: timer stopped\n");

	fpn_printf("Test 2: launch timer wait for him to be scheduled, then try to stop it: ");
	timer_scheduled = 0;
	end_execution = 0;
	if (callout_reset(&test_fpn0_timer_callout, 1, test_fpn0_timers_callout_handler, NULL)) {
		fpn_printf("%s: %d: Error: cannot reset timer\n",
			   __FUNCTION__, __LINE__);
		return ;
	}
	while (timer_scheduled == 0) ;
	if (callout_stop(&test_fpn0_timer_callout)) {
		end_execution = 1;
		fpn_printf("Error: timer was stopped while handler is being executed\n");
		return ;
	}
	else
		fpn_printf("Success: timer was not stopped\n");

	fpn_printf("Test 3: Wait for timer to be processed, then try to stop it: ");
	end_execution = 1;
	now = fpn_get_clock_cycles();
	while (CYCLES_TO_SECONDS(fpn_get_clock_cycles() - now) < 1) ;
	if (!callout_stop(&test_fpn0_timer_callout))
		fpn_printf("Error: cannot stop timer\n");
	else
		fpn_printf("Success: timer has been stopped\n");
}

static FPN_DEFINE_SHARED(int, stress_init_done) = 0;
static FPN_DEFINE_SHARED(struct callout, test_fpn0_timer_stress);

static void test_fpn0_timers_stress_handler(void *arg __fpn_maybe_unused)
{
	volatile int i;

	for (i = 0; i < 1000000; i++)
		;
}

static void test_fpn0_timers_stress_reset(void)
{
	if (stress_init_done == 0) {
		callout_init(&test_fpn0_timer_stress);
		stress_init_done = 1;
	}

	if (callout_reset(&test_fpn0_timer_stress, 1, test_fpn0_timers_stress_handler, NULL)) {
		fpn_printf("%s: %d: Error: cannot reset timer\n",
			   __FUNCTION__, __LINE__);
		return ;
	}
}

#ifdef CONFIG_MCORE_TIMER_GENERIC
static void test_fpn0_timers_bind_handler(void *arg)
{
	struct test_fpn0_timers_ctx *timer = arg;

	uint64_t timeout = fpn_get_clock_cycles() - timer->launch_time;

	int cpu_id = fpn_get_core_num();

	fpn_printf("Timeout %d:"
	           " cycles=%"PRIu64" ms=%"PRIu64"[%d] core=%d->%d[%d]\n",
		   timer->idx, timeout,
		   CYCLES_TO_MS(timeout), timer->target_ms,
		   timer->launch_cpu_id, cpu_id, timer->target_cpu_id);
}

static void test_fpn0_timers_bind(void)
{
	int i, mod;
	int cpu_id = fpn_get_core_num();

	fpn_printf("Timers callout_bind test (hz=%"PRIu64")\n", fpn_get_clock_hz());

	test_fpn0_timers_init();

	mod = fpn_get_online_core_count();

	for (i=0; i<TEST_FPN0_TIMER_MAX; i++) {
		test_fpn0_timer[i].idx = i;
		test_fpn0_timer[i].launch_cpu_id = cpu_id;
		test_fpn0_timer[i].target_cpu_id = fpn_get_online_core_num(i%mod);
		test_fpn0_timer[i].target_ms = 500*(TEST_FPN0_TIMER_MAX - 1 - i);

		fpn_printf("Scheduling timer %d in %u ms on core %d\n",
				i,
				test_fpn0_timer[i].target_ms,
				test_fpn0_timer[i].target_cpu_id);

		test_fpn0_timer[i].launch_time = fpn_get_clock_cycles();

		callout_bind(&test_fpn0_timer[i].callout,
				test_fpn0_timer[i].target_cpu_id);
		callout_reset_millisec(&test_fpn0_timer[i].callout,
				test_fpn0_timer[i].target_ms,
				test_fpn0_timers_bind_handler,
				&test_fpn0_timer[i]);
	}
}

/* context structure for timer scalability optimization test */
struct test_fpn0_timers_scalability_stats {
	uint32_t count;    /* expired timer counter */
	int64_t  drift_ms; /* drift between target and actual expiry */
};

struct test_fpn0_timers_scalability_ctx {
	struct callout callout;

	uint64_t launch_time;
	int      launch_cpu_id;
	unsigned target_ms;
	int      target_cpu_id;
	int      idx;
	struct test_fpn0_timers_scalability_stats *stats; /* ptr on per-cpu stats */
};

static void test_fpn0_timers_scalability_handler(void *arg)
{
	struct test_fpn0_timers_scalability_ctx *timer = arg;
	int cpu_id = fpn_get_core_num();
	uint64_t timeout = fpn_get_clock_cycles() - timer->launch_time;

	if (unlikely(cpu_id != timer->target_cpu_id))
		fpn_printf("Timer %d expired on wrong core:\n"
		   "\texpired on core %d (target %d)\n",
		   timer->idx, cpu_id, timer->target_cpu_id);

	timer->stats->drift_ms += (int64_t)CYCLES_TO_MS(timeout) - timer->target_ms;
	timer->stats->count++;

	callout_stop(&timer->callout);
}

static void test_fpn0_timers_scalability_end_handler(void *arg)
{
	int i, mod;
	struct test_fpn0_timers_scalability_ctx *timers = arg;
	struct test_fpn0_timers_scalability_stats *stats;
	uint32_t count = 0;
	int64_t drift_ms = 0;

	fpn_printf("Timers callout_scalability result:\n");

	mod = fpn_get_online_core_count();
	stats = timers->stats;

	for (i=0; i<mod; i++) {
		count    += stats[i].count;
		drift_ms += stats[i].drift_ms;
	}

	if (count)
		fpn_printf("Result: %"PRIu32" timers expired, spread among %d cores\n"
			"\texpiry drift %"PRId64" ms (average %"PRId64" ms)\n",
			count, mod, drift_ms,
			fpn_div64_32((uint64_t)drift_ms, count));
	else
		fpn_printf("Result: 0 timers expired\n");

	callout_stop(&timers->callout);

	fpn_free(stats);
	fpn_free(timers);
}

static void test_fpn0_timers_scalability(void)
{
	int i, mod;
	int cpu_id = fpn_get_core_num();

#define TEST_FPN0_TIMERS_SCALABILITY_MAX 200000
	struct test_fpn0_timers_scalability_ctx *timers, *t;
	struct test_fpn0_timers_scalability_stats *stats;

	fpn_printf("Timers callout_scalability test:\n");

	mod = fpn_get_online_core_count();
	fpn_printf("Launching %"PRIu32" timers spread on %d cores\n"
		"\trandom timeouts spread from 3000 ms to 5000 ms\n"
		"\tsummary in 5500 ms\n",
		TEST_FPN0_TIMERS_SCALABILITY_MAX, mod);

	timers = fpn_zalloc((TEST_FPN0_TIMERS_SCALABILITY_MAX+1) * sizeof(*timers), 32);
	if (timers == NULL) {
		fpn_printf("malloc failed - ABORTING\n");
		return;
	}

	stats = fpn_zalloc(mod * sizeof(*stats), 32);
	if (timers == NULL) {
		fpn_printf("malloc failed - ABORTING\n");
		fpn_free(timers);
		return;
	}

	for (i=0; i<TEST_FPN0_TIMERS_SCALABILITY_MAX; i++) {
		t = &timers[i+1];
		callout_init(&t->callout);
		t->idx = i;
		t->launch_cpu_id = cpu_id;
		t->target_cpu_id = fpn_get_online_core_num(i%mod);
		t->target_ms = 3000 + fpn_get_pseudo_rnd()%2000;
		t->stats = &stats[i%mod];
		t->launch_time = fpn_get_clock_cycles();

		callout_bind(&t->callout,
				t->target_cpu_id);
		callout_reset_millisec(&t->callout,
				t->target_ms,
				test_fpn0_timers_scalability_handler,
				t);
	}

	t = timers;
	callout_init(&t->callout);
	t->idx = i;
	t->launch_cpu_id = cpu_id;
	t->target_cpu_id = fpn_get_online_core_num(i%mod);
	t->target_ms = 5500;
	t->launch_time = fpn_get_clock_cycles();
	t->stats = stats;

	callout_bind(&t->callout, t->target_cpu_id);
	callout_reset_millisec(&t->callout,
			t->target_ms,
			test_fpn0_timers_scalability_end_handler,
			t);
}
#endif /* CONFIG_MCORE_TIMER_GENERIC */

#ifdef CONFIG_MCORE_AATREE
static void test_fpn0_aatree(void)
{
#define TEST_FPN0_AATREE_MAX 200000

	fpn_aatree_node_t *Node;
	fpn_aatree_node_t *t, *t_prev;
	fpn_aatree_ctx_t ctx;
	uint64_t now;

	int i;
	int error = 0;

	fpn_printf("AA tree test:\n");

	fpn_aatree_init(&ctx);
	Node = fpn_zalloc(TEST_FPN0_AATREE_MAX * sizeof(*Node), 32);

	if (Node == NULL) {
		fpn_printf("malloc failed - ABORTING\n");
		return;
	}

	for (i=0; i<TEST_FPN0_AATREE_MAX; i++) {
		fpn_aatree_node_init(&Node[i]);
		Node[i].priority = fpn_get_pseudo_rnd();
	}

	now = fpn_get_local_cycles();
	for (i=0; i<TEST_FPN0_AATREE_MAX; i++) {
		fpn_aatree_insert(&ctx, &Node[i]);
	}
	now = fpn_get_local_cycles() - now;

	t_prev = FPN_TAILQ_FIRST(&ctx.list);
	i = 0;

	FPN_TAILQ_FOREACH(t, &ctx.list, next) {
		if ((int64_t)(t->priority - t_prev->priority) < 0) {
			fpn_printf("ERROR: aatree node order is bad: %"PRIu64" < %"PRIu64"\n", t->priority, t_prev->priority);
			error = 1;
		}
		t_prev = t;
		i++;
	}

	if (i != TEST_FPN0_AATREE_MAX) {
		fpn_printf("ERROR: aatree node insert count is bad: %d != %d\n",
			i, TEST_FPN0_AATREE_MAX);
		error = 1;
	}

	if (error == 0)
		fpn_printf("AA tree insert %u nodes succeeded in %"PRIu64" ms\n",
			TEST_FPN0_AATREE_MAX, LOCAL_CYCLES_TO_MS(now));

	error = 0;
	i = 0;

	now = fpn_get_local_cycles();
	while ((t = FPN_TAILQ_FIRST(&ctx.list)) != NULL) {
		fpn_aatree_remove(&ctx, t);
		i++;
	}
	now = fpn_get_local_cycles() - now;

	if (i != TEST_FPN0_AATREE_MAX) {
		fpn_printf("ERROR: aatree node remove count is bad: %d != %d\n",
			i, TEST_FPN0_AATREE_MAX);
		error = 1;
	}

	if (error == 0)
		fpn_printf("AA tree remove %u nodes succeeded in %"PRIu64" ms\n",
			TEST_FPN0_AATREE_MAX, LOCAL_CYCLES_TO_MS(now));

#ifdef FPN_AATREE_SANITY_CHECK
	fpn_printf("Try to delete an already deleted node:\n");
	fpn_aatree_remove(&ctx, &Node[0]);


	fpn_printf("Try to delete an invalid pointer:\n");
	fpn_aatree_remove(&ctx, (fpn_aatree_node_t*)((uint8_t*)&Node[0]+1));
#endif

	fpn_free(Node);
}
#endif /* CONFIG_MCORE_AATREE */

static FPN_DEFINE_SHARED(int, lock_test_init_done) = 0;
static FPN_DEFINE_SHARED(fpn_atomic_t, lock_test_used);     /* flag: entry is not free */
static FPN_DEFINE_SHARED(fpn_atomic_t, lock_test_refcount); /* currently used by a core */
static FPN_DEFINE_SHARED(fpn_spinlock_t, lock_test_lock);   /* spinlock while entry is used */
static FPN_DEFINE_SHARED(uint32_t, lock_test_nexec);        /* test execution number */
static FPN_DEFINE_SHARED(uint64_t, lock_test_sumtime);      /* sum of exec time */

static void test_fpn0_lock_audit(void)
{
	uint64_t lock_test_beg_time, lock_test_end_time;

	if (lock_test_init_done == 0) {
		fpn_atomic_clear(&lock_test_used);
		fpn_spinlock_init(&lock_test_lock);
		lock_test_init_done = 1;
		lock_test_nexec = lock_test_sumtime = 0;
	}

	lock_test_beg_time = fpn_get_clock_cycles();

	/* try allocating : if OK, increment reference counter. */
	if (fpn_atomic_test_and_set(&lock_test_used)) {
		fpn_atomic_inc(&lock_test_refcount);
	}

	/* decrement reference counter. if 0, free back to pool */
	if (fpn_atomic_dec_and_test(&lock_test_refcount)) {
		fpn_atomic_clear(&lock_test_used);
	}

	fpn_spinlock_lock(&lock_test_lock);

	/* do something */
	lock_test_end_time = fpn_get_clock_cycles();
	lock_test_sumtime += (lock_test_end_time - lock_test_beg_time);
	lock_test_nexec++;

	fpn_spinlock_unlock(&lock_test_lock);

	if ( !(lock_test_nexec % (1024*1024)) ) {
		fpn_printf("%s avg exec time %llu nexec %d\n", __FUNCTION__,
			   (unsigned long long)fpn_div64_32(lock_test_sumtime,lock_test_nexec),
			   (lock_test_nexec / (1024*1024)));
	}
}

/* Currently only VNB proposes an API to allocate
 * shared memory dynamically.
 */
static void test_fpn0_timers_free_handler(void *arg)
{
	fpn_printf("run timer handler: %s\n",__FUNCTION__);
	callout_stop((struct callout *)arg);
	memset(arg, 0, sizeof(struct callout));
	fpn_free(arg);
}

static void test_fpn0_timers_free_callout(void)
{
	struct callout *cllt;

	cllt = fpn_malloc(sizeof(*cllt), 0);
	if (cllt) {
		callout_init(cllt);
		callout_reset(cllt, 3, test_fpn0_timers_free_handler, cllt);
	} else {
		fpn_printf("MEM allocation failed\n");
	}
}

static void test_fpn0_get_local_cycles(void)
{
	uint64_t cur_cycles, last_cycles;
	unsigned int i;

	fpn_printf("Test: fpn_get_local_cylces() return correct values\n");
	cur_cycles = fpn_get_local_cycles();
	for (i=0; i < 268435455; i++) {
		last_cycles = cur_cycles;
		cur_cycles = fpn_get_local_cycles();
		if (last_cycles > cur_cycles) {
			fpn_printf("Error: fpn_get_local_cyles return an uncorrect value\n");
			fpn_printf("last measured cycles > current measured cycles!\n");
			fpn_printf("current cycles:%llu\n", \
				   (unsigned long long) cur_cycles);
			fpn_printf("last cycles:%llu\n", \
				   (unsigned long long) last_cycles);
			return;
		}
	}
	fpn_printf("Success: fpn_get_local_cylces() returns correct values\n");
}

/*
 * test mempool and ring
 */

#define TEST_FPN0_MEMPOOL_ELT_SIZE 128
#define TEST_FPN0_MEMPOOL_SIZE (FPN_MAX_CORES*64 - 1)

/*
 * save the object number in the first 4 bytes of object data. All
 * other bytes are set to 0.
 */
static void test_fpn0_mempool_obj_init(struct fpn_mempool *mp,
				       __attribute__((unused)) void *arg,
				       void *obj, unsigned i)
{
	uint32_t *objnum = obj;
	memset(obj, 0, mp->elt_size);
	*objnum = i;
}


/* basic tests (done on one core) */
static int test_fpn0_mempool_basic(struct fpn_mempool *mp)
{
	uint32_t *objnum;
	void **objtable;
	void *obj, *obj2;
	char *obj_data;
	int ret = 0;
	unsigned i, j;

	/* dump the mempool status */
	fpn_mempool_dump(mp);

	fpn_printf("get an object\n");
	if (fpn_mempool_get(mp, &obj) < 0)
		return -1;
	fpn_mempool_dump(mp);

	fpn_printf("put the object back\n");
	fpn_mempool_put(mp, obj);
	fpn_mempool_dump(mp);

	fpn_printf("get 2 objects\n");
	if (fpn_mempool_get(mp, &obj) < 0)
		return -1;
	if (fpn_mempool_get(mp, &obj2) < 0) {
		fpn_mempool_put(mp, obj);
		return -1;
	}
	fpn_mempool_dump(mp);

	fpn_printf("put the objects back\n");
	fpn_mempool_put(mp, obj);
	fpn_mempool_put(mp, obj2);
	fpn_mempool_dump(mp);

	/*
	 * get many objects: we cannot get them all because the cache
	 * on other cores may not be empty.
	 */
	fpn_printf("get many objects\n");
	objtable = fpn_malloc(TEST_FPN0_MEMPOOL_SIZE * sizeof(void *),
			      FPN_CACHELINE_SIZE);
	if (objtable == NULL) {
		fpn_printf("malloc obj table failed\n");
		return -1;
	}

	for (i = 0; i<TEST_FPN0_MEMPOOL_SIZE; i++) {
		int got;
		if ((got = fpn_mempool_get(mp, &objtable[i])) < 0) {
			fpn_printf("get object failed, index(%d), ret=%d\n",
				   i, got);
			break;
		}
	}

	/*
	 * for each object, check that its content was not modified,
	 * and put objects back in pool
	 */
	fpn_printf("put many objects back\n");
	while (i--) {
		obj = objtable[i];
		obj_data = obj;
		objnum = obj;
		if (*objnum > TEST_FPN0_MEMPOOL_SIZE) {
			fpn_printf("bad object number\n");
			ret = -1;
			break;
		}
		for (j = sizeof(*objnum); j < mp->elt_size; j++) {
			if (obj_data[j] != 0)
				ret = -1;
		}

		fpn_mempool_put(mp, objtable[i]);
	}

	fpn_free(objtable);
	if (ret == -1)
		fpn_printf("objects were modified!\n");

	fpn_printf("finish basic test for mempool(%s), ret=%d\n", mp->name, ret);
	return ret;
}

static int
test_fpn0_mempool(void)
{
	int ret = 0;
	struct fpn_mempool *mp_cache, *mp_nocache;

	/* create a mempool (without cache) */
	mp_nocache = fpn_mempool_create("test_nocache", TEST_FPN0_MEMPOOL_SIZE,
					TEST_FPN0_MEMPOOL_ELT_SIZE, 0, 0,
					NULL, NULL, test_fpn0_mempool_obj_init,
					NULL, 0);
	if (mp_nocache == NULL) {
		fpn_printf("Cannot allocate mempool\n");
		return -1;
	}

	/* create a mempool (with cache) */
	mp_cache = fpn_mempool_create("test_cache", TEST_FPN0_MEMPOOL_SIZE,
					TEST_FPN0_MEMPOOL_ELT_SIZE,
					FPN_MEMPOOL_CACHE_MAX_SIZE, 0,
					NULL, NULL, test_fpn0_mempool_obj_init,
					NULL, 0);
	if (mp_cache == NULL) {
		fpn_printf("Cannot allocate mempool\n");
		ret = -1;
		goto end;
	}

	/* retrieve the mempool from its name */
	if (fpn_mempool_lookup("test_nocache") != mp_nocache) {
		fpn_printf("Cannot lookup mempool from its name(%s)\n",
			mp_nocache->name);
		fpn_mempool_list_dump();
		ret = -1;
		goto end;
	}

	/* retrieve the mempool from its name */
	if (fpn_mempool_lookup("test_cache") != mp_cache) {
		fpn_printf("Cannot lookup mempool from its name(%s)\n",
			mp_cache->name);
		fpn_mempool_list_dump();
		ret = -1;
		goto end;
	}

	/* basic tests without cache */
	fpn_printf("test basic functions for mempool without cache\n");
	if (test_fpn0_mempool_basic(mp_nocache) < 0) {
		ret = -1;
		goto end;
	}

	/* basic tests with cache */
	fpn_printf("test basic functions for mempool with cache\n");
	if (test_fpn0_mempool_basic(mp_cache) < 0) {
		ret = -1;
		goto end;
	}

end:
	if (mp_nocache != NULL)
		fpn_free(mp_nocache);
	if (mp_cache != NULL)
		fpn_free(mp_cache);
	fpn_printf("finished testing mempool\n");
	return ret;
}

#define TEST_FPN0_RING_SIZE 4096
#define TEST_FPN0_RING_MAX_BULK 32

static int
test_fpn0_ring_basic(struct fpn_ring *r)
{
	void **src, **cur_src, **dst, **cur_dst;
	void *peek;
	int ret;
	unsigned i, n;

	/* alloc dummy object pointers */
	src = fpn_malloc(TEST_FPN0_RING_SIZE * 2 * sizeof(void *),
			 FPN_CACHELINE_SIZE);
	if (!src) {
		fpn_printf("failed to malloc memory (size=%d)\n",
			   (int)(TEST_FPN0_RING_SIZE * 2 * sizeof(void *)));
		return -1;
	}
	for (i = 0; i < TEST_FPN0_RING_SIZE*2 ; i++) {
		src[i] = (void *)(unsigned long)i;
	}
	cur_src = src;

	/* alloc some room for copied objects */
	dst = fpn_malloc(TEST_FPN0_RING_SIZE * 2 * sizeof(void *),
			 FPN_CACHELINE_SIZE);
	if (!dst) {
		fpn_printf("failed to malloc memory (size=%d)\n",
			   (int)(TEST_FPN0_RING_SIZE * 2 * sizeof(void *)));
		goto fail2;
	}
	memset(dst, 0, TEST_FPN0_RING_SIZE * 2 * sizeof(void *));
	cur_dst = dst;

	fpn_printf("enqueue 1 obj\n");
	ret = fpn_ring_sp_enqueue_bulk(r, cur_src, 1);
	cur_src += 1;
	if (ret != 0) {
		fpn_printf("%s(%d): sp enqueue 1 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("enqueue 2 objs\n");
	ret = fpn_ring_sp_enqueue_bulk(r, cur_src, 2);
	cur_src += 2;
	if (ret != 0) {
		fpn_printf("%s(%d): sp enqueue 2 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("enqueue TEST_FPN0_RING_MAX_BULK objs\n");
	ret = fpn_ring_sp_enqueue_bulk(r, cur_src, TEST_FPN0_RING_MAX_BULK);
	if (ret != 0) {
		fpn_printf("%s(%d): sp enqueue max bulk obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("peek 1 obj\n");
	ret = fpn_ring_sc_peek(r, &peek);
	if (ret != 0) {
		fpn_printf("%s(%d): sc peek failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("dequeue 1 obj\n");
	ret = fpn_ring_sc_dequeue_bulk(r, cur_dst, 1);
	cur_dst += 1;
	if (ret != 0) {
		fpn_printf("%s(%d): sc dequeue 1 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("dequeue 2 objs\n");
	ret = fpn_ring_sc_dequeue_bulk(r, cur_dst, 2);
	cur_dst += 2;
	if (ret != 0) {
		fpn_printf("%s(%d): sc dequeue 2 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("dequeue TEST_FPN0_RING_MAX_BULK objs\n");
	ret = fpn_ring_sc_dequeue_bulk(r, cur_dst, TEST_FPN0_RING_MAX_BULK);
	cur_dst += TEST_FPN0_RING_MAX_BULK;
	if (ret != 0) {
		fpn_printf("%s(%d): sc dequeue max bulk obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		fpn_printf("data after dequeue is not the same\n");
		goto fail;
	}
	if (*src != peek) {
		fpn_printf("peeked data is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	fpn_printf("enqueue 1 obj\n");
	ret = fpn_ring_mp_enqueue_bulk(r, cur_src, 1);
	cur_src += 1;
	if (ret != 0) {
		fpn_printf("%s(%d): mp enqueue 1 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("enqueue 2 objs\n");
	ret = fpn_ring_mp_enqueue_bulk(r, cur_src, 2);
	cur_src += 2;
	if (ret != 0) {
		fpn_printf("%s(%d): mp enqueue 2 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("enqueue TEST_FPN0_RING_MAX_BULK objs\n");
	ret = fpn_ring_mp_enqueue_bulk(r, cur_src, TEST_FPN0_RING_MAX_BULK);
	if (ret != 0) {
		fpn_printf("%s(%d): mp enqueue max bulk obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("dequeue 1 obj\n");
	ret = fpn_ring_mc_dequeue_bulk(r, cur_dst, 1);
	cur_dst += 1;
	if (ret != 0) {
		fpn_printf("%s(%d): mc dequeue 1 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("dequeue 2 objs\n");
	ret = fpn_ring_mc_dequeue_bulk(r, cur_dst, 2);
	cur_dst += 2;
	if (ret != 0) {
		fpn_printf("%s(%d): mc dequeue 2 obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	fpn_printf("dequeue TEST_FPN0_RING_MAX_BULK objs\n");
	ret = fpn_ring_mc_dequeue_bulk(r, cur_dst, TEST_FPN0_RING_MAX_BULK);
	cur_dst += TEST_FPN0_RING_MAX_BULK;
	if (ret != 0) {
		fpn_printf("%s(%d): mc dequeue max bulk obj failed, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		fpn_printf("data after dequeue is not the same\n");
		goto fail;
	}
	cur_src = src;
	cur_dst = dst;

	fpn_printf("fill and empty the ring\n");
	for (i = 0; i<TEST_FPN0_RING_SIZE/TEST_FPN0_RING_MAX_BULK; i++) {
		ret = fpn_ring_mp_enqueue_bulk(r, cur_src,
					       TEST_FPN0_RING_MAX_BULK);
		cur_src += TEST_FPN0_RING_MAX_BULK;
		if (ret != 0) {
			fpn_printf("%s(%d): mp fill ring to full failed, "
				   "ret=%d\n", __func__, __LINE__, ret);
			goto fail;
		}
		ret = fpn_ring_mc_dequeue_bulk(r, cur_dst,
					       TEST_FPN0_RING_MAX_BULK);
		cur_dst += TEST_FPN0_RING_MAX_BULK;
		if (ret != 0) {
			fpn_printf("%s(%d): mp empty ring failed, ret=%d\n",
				   __func__, __LINE__, ret);
			goto fail;
		}
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		fpn_printf("data after dequeue is not the same\n");
		goto fail;
	}

	fpn_printf("test watermark and default bulk enqueue / dequeue\n");
	fpn_ring_set_bulk_count(r, 16);
	fpn_ring_set_water_mark(r, 20);
	n = fpn_ring_get_bulk_count(r);
	if (n != 16) {
		fpn_printf("fpn_ring_get_bulk_count() returned %u instead "
			   "of 16\n", n);
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;
	ret = fpn_ring_enqueue_bulk(r, cur_src, n);
	cur_src += 16;
	if (ret != 0) {
		fpn_printf("%s(%d): Cannot enqueue, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}
	ret = fpn_ring_enqueue_bulk(r, cur_src, n);
	if (ret != -EDQUOT) {
		fpn_printf("%s(%d): Watermark not exceeded, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}
	ret = fpn_ring_dequeue_bulk(r, cur_dst, n);
	cur_dst += 16;
	if (ret != 0) {
		fpn_printf("%s(%d): Cannot dequeue, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}
	ret = fpn_ring_dequeue_bulk(r, cur_dst, n);
	cur_dst += 16;
	if (ret != 0) {
		fpn_printf("%s(%d): Cannot dequeue2, ret=%d\n",
			   __func__, __LINE__, ret);
		goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		fpn_printf("data after dequeue is not the same\n");
		goto fail;
	}

	fpn_free(src);
	fpn_free(dst);
	fpn_printf("%s(%d): finished test basic functions for ring\n",
		   __func__, __LINE__);
	return 0;

 fail:
	fpn_free(dst);
	fpn_printf("%s(%d): failed during testing basic functions for ring\n",
		   __func__, __LINE__);
 fail2:
	fpn_free(src);
	fpn_printf("%s(%d): failed2 during testing basic functions for ring\n",
		   __func__, __LINE__);
	return -1;
}

static int
test_fpn0_ring(void)
{
	struct fpn_ring *r;

	r = fpn_ring_create("test_ring", TEST_FPN0_RING_SIZE, 0);
	if (r == NULL) {
		fpn_printf("Cannot allocate ring\n");
		return -1;
	}

	/* dump ring init status */
	fpn_ring_dump(r);

	/* basic operations */
	if (test_fpn0_ring_basic(r) < 0) {
		fpn_ring_dump(r);
		return -1;
	}

	/* dump the ring status */
	fpn_ring_dump(r);

	return 0;
}

static void
test_fpn0_ringpool(void)
{
#define RINGPOOL_SIZE 64
	static struct fpn_ring *rg[RINGPOOL_SIZE];
	struct fpn_mempool *mp;
	int i;

	fpn_printf("ringpool test");
	/*
	 * Pool of RINGPOOL_SIZE rings, each one holding
	 * TEST_FPN0_RING_SIZE elements
	 */
	mp = fpn_ringpool_create ("ringpool", RINGPOOL_SIZE,
				  TEST_FPN0_RING_SIZE);
	if (mp == NULL) {
		fpn_printf("ringpool alloc failed");
		return;
	}

	/* Get all rings */
	for (i = 0; i<RINGPOOL_SIZE; i++) {
		int ret;
		if ((ret = fpn_mempool_get(mp, (void **)&rg[i])) < 0) {
			fpn_printf("get ring failed, index(%d), ret=%d\n",
				   i, ret);
			break;
		}
	}

	for (i = 0; i<RINGPOOL_SIZE; i++) {
		fpn_printf("--- checking ring #%d", i);
		/* dump ring init status */
		fpn_ring_dump(rg[i]);
		if (test_fpn0_ring_basic(rg[i]) < 0) {
			fpn_printf("--- failed");
			fpn_ring_dump(rg[i]);
			return;
		}
		/* dump the ring status */
		fpn_ring_dump(rg[i]);
	}
	return;
}

static void
test_fpn0_ringqueue(void)
{
#define TEST_FPN0_RINGQUEUE_SIZE	512
#define TEST_FPN0_RING_SIZE1		128
#define TEST_FPN0_RING_SIZE2		256
	int res;
	long i;
	void *obj;
	struct fpn_ringqueue *rq = NULL;
	struct fpn_mempool *rp1 = NULL;
	struct fpn_mempool *rp2 = NULL;
	void **list = NULL;
	unsigned size_r1, size_h1, size_r2, size_h2;

	fpn_printf("=================== ringqueue test ====================");

	/*
	 * ringpool creation and linkage
	 * this loops rp1 --> rp2 --> rp1
	 */
	rp1 = fpn_ringpool_create("rq_ringpool_1", RINGPOOL_SIZE,
				  TEST_FPN0_RING_SIZE1);
	if (rp1 == NULL) {
		fpn_printf("ringpool #1 allocation failed");
		goto test_fpn0_ringqueue_end;
	}
	rp2 = fpn_ringpool_create("rq_ringpool_2", RINGPOOL_SIZE,
				  TEST_FPN0_RING_SIZE2);
	if (rp2 == NULL) {
		fpn_printf("ringpool #1 allocation failed");
		goto test_fpn0_ringqueue_end;
	}
	list = fpn_malloc(TEST_FPN0_RINGQUEUE_SIZE * sizeof(void*), 0);
	if (list == NULL) {
		fpn_printf("list allocation failed");
		goto test_fpn0_ringqueue_end;
	}
	fpn_ringpool_link(rp1, rp2);
	fpn_ringpool_link(rp2, rp1);

	rq = fpn_ringqueue_create(rp1, TEST_FPN0_RINGQUEUE_SIZE,
				  FPN_RINGQUEUE_SC_DEQ);
	if (rq == NULL)
		goto test_fpn0_ringqueue_end;

	fpn_ringqueue_dump(rq);

	/* fill the ringqueue ... */
	for (i = 0; i < TEST_FPN0_RINGQUEUE_SIZE; i++) {
		if ((res = fpn_ringqueue_enqueue(rq, (void *)i)) < 0) {
			fpn_printf("rq_write failure");
			fpn_ringqueue_dump(rq);
			fpn_printf("rq_write failure (rank %ld) %d", i, res);
			goto test_fpn0_ringqueue_end;
		}
	}
	/* ... until we get over */
	if ((res = fpn_ringqueue_enqueue(rq, (void *)i)) != -ENOBUFS) {
		fpn_printf("rq_write failure");
		fpn_ringqueue_dump(rq);
		fpn_printf("rq_write -ENOBUFS expected but got %d",
			   res);
		goto test_fpn0_ringqueue_end;
	}
	fpn_printf("----------------- ringqueue write OK ------------------");
	fpn_ringqueue_dump(rq);
	/* read the ringqueue */
	for (i = 0; i < TEST_FPN0_RINGQUEUE_SIZE; i++) {
		if ((res = fpn_ringqueue_dequeue(rq, &obj)) < 0) {
			fpn_printf("rq_read failure");
			fpn_ringqueue_dump(rq);
			fpn_printf("rq_read failure (rank %ld) %d", i, res);
			goto test_fpn0_ringqueue_end;
		}
		if ((long)obj != i) {
			fpn_printf("rq_read check failed %ld != %ld",
				   (long)obj, i);
			goto test_fpn0_ringqueue_end;
		}
	}
	/* ... until we get over */
	if ((res = fpn_ringqueue_dequeue(rq, &obj)) != -ENOENT) {
		fpn_printf("rq_read failure");
		fpn_ringqueue_dump(rq);
		fpn_printf("rq_write -ENOENT expected but got %d",
			   res);
		goto test_fpn0_ringqueue_end;
	}
	fpn_printf("----------------- ringqueue read OK ------------------");
	fpn_ringqueue_dump(rq);
	/* fill the ringqueue again */
	for (i = 0; i < TEST_FPN0_RINGQUEUE_SIZE; i++) {
		if ((res = fpn_ringqueue_enqueue(rq, (void *)i)) < 0) {
			fpn_printf("rq_write2 failure");
			fpn_ringqueue_dump(rq);
			fpn_printf("rq_write2 failure (rank %ld) %d", i, res);
			goto test_fpn0_ringqueue_end;
		}
	}
	/* dump it ... */
	size_r1 = fpn_ringqueue_count(rq)/2;
	size_h1 = size_r1;
	res = fpn_ringqueue_sc_dequeue_bulk(rq, list, &size_h1);
	if (res < 0 || size_h1 != size_r1) {
		fpn_printf("rq_su_read_bulk #1 failure");
		fpn_ringqueue_dump(rq);
		fpn_printf("rq_su_read_bulk #1 failure %d", res);
		goto test_fpn0_ringqueue_end;
	}
	size_r2 = TEST_FPN0_RINGQUEUE_SIZE - size_r1;
	size_h2 = size_r2;
	res = fpn_ringqueue_sc_dequeue_bulk(rq, &list[size_r2], &size_h2);
	if (res < 0 || size_h2 != size_r2) {
		fpn_printf("rq_su_read_bulk #2 failure");
		fpn_ringqueue_dump(rq);
		fpn_printf("rq_su_read_bulk #2 failure %d", res);
		goto test_fpn0_ringqueue_end;
	}
	/* ... and check contents */
	if (fpn_ringqueue_count (rq) != 0)  {
		fpn_ringqueue_dump(rq);
		fpn_printf("rq_su_read_bulk check: remaining packet !!!");
		goto test_fpn0_ringqueue_end;
	}
	for (i = 0; i < TEST_FPN0_RINGQUEUE_SIZE; i++) {
		if ((long)list[i] != i) {
			fpn_printf("rq_linearize check failed %ld != %ld",
				   (long)list[i], i);
			goto test_fpn0_ringqueue_end;
		}
	}
	fpn_printf("--------------- ringqueue bulk read OK ---------------");
	fpn_printf("############# ringqueue test OK #################");

 test_fpn0_ringqueue_end:

	if (rp1)
		fpn_free(rp1);
	if (rp2)
		fpn_free(rp2);
	if (rq)
		fpn_free(rq);
	if (list)
		fpn_free(list);
	return;
}

static void
test_fpn0_shmem_conf(void)
{
	fpn_printf("Display conf of the shared memory:\n");
	fpn_printf("\tShared mem = %p\n", fp_shared);
	fpn_printf("\tShared mem magic = 0x%"PRIx32"\n", fp_shared->conf.s.magic);
	fpn_printf("\tShared mem conf:\n");
#define FPDEBUG_ONOFF(x) (fp_shared->conf.s.x ? "on": "off")
	fpn_printf("\t\tNetfilter: %s \n", FPDEBUG_ONOFF(do_netfilter));
	fpn_printf("\t\tIPv6 Netfilter: %s \n", FPDEBUG_ONOFF(do_netfilter6));
	fpn_printf("\t\tIPsec output: %s \n", FPDEBUG_ONOFF(do_ipsec_output));
	fpn_printf("\t\tIPsec input: %s \n", FPDEBUG_ONOFF(do_ipsec_input));
	fpn_printf("\t\tIPv6 IPsec output: %s \n", FPDEBUG_ONOFF(do_ipsec6_output));
	fpn_printf("\t\tIPv6 IPsec input: %s \n", FPDEBUG_ONOFF(do_ipsec6_input));
	fpn_printf("\t\tForced reassembly: %s \n", FPDEBUG_ONOFF(do_forced_reassembly));
	fpn_printf("\t\tTap: %s %s \n", FPDEBUG_ONOFF(do_tap),
		   fp_shared->conf.s.do_tap_global ? "(global)" : "(local)");
	fpn_printf("\t\tDo IPsec only once: %s \n", FPDEBUG_ONOFF(do_ipsec_once));
	fpn_printf("\t\tNetfilter cache: %s \n", FPDEBUG_ONOFF(do_nf_cache));
	fpn_printf("\t\tIPv6 Netfilter cache: %s \n", FPDEBUG_ONOFF(do_nf6_cache));
	fpn_printf("\t\tFast forward: %s \n", fp_shared->conf.w32.do_func & FP_CONF_NO_FAST_FORWARD ? "off": "on");
#undef FPDEBUG_ONOFF
}

#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
/* number of lock records displays for each core */
#define FPN0_DEFAULT_LOCK_RECORDS 4
static void
test_fpn0_debug_lock_log_dump(void)
{
	int core_id;

	for (core_id = 0; core_id < FPN_MAX_CORES; core_id++)
		fpn_debug_lock_log_display(core_id, FPN0_DEFAULT_LOCK_RECORDS);
}
#endif

static void test_fpn0_fpnmalloc(void)
{
	int i,j;
	char **ptr;
	char *p;
	int size_mb = 8;

	ptr = fpn_malloc(1024 * sizeof(char *), 0);
	if (ptr == NULL) {
		fpn_printf("Could not allocate memory %uB\n",
				(unsigned int)(1024 * sizeof(char *)));
		return;
	}

	fpn_printf("Starting allocation test with block size %um\n", size_mb);
	for (i = 0; i < 1024; i++) {
		/* Alloc minus 8 bytes used by fpn-malloc() to save pointer */
		p = fpn_malloc((size_mb<<20) - sizeof(void*), 0);
		if (p == NULL)
			break;
		ptr[i] = p;
	}
	if (i == 0) {
		fpn_printf("Could not allocate memory\n");
	} else {
		fpn_printf("%u x %um = %um allocated (%p - %p)\n",
				i, size_mb, i*size_mb,
				ptr[i-1] + size_mb, ptr[0]);
		for (j = 0; j < i; j++) {
			fpn_free(ptr[j]);
		}
	}
	fpn_free(ptr);
}

static void test_fpn0_memtest(void)
{
	volatile char *cp = (volatile char *)fp_shared;
	unsigned long i;
	unsigned long size = sizeof(*fp_shared);
	char c;

	fpn_printf("FP starting memtest\n");
	for (i = 0; i < size; i++) {
		c = *cp;
		*cp = c;
		cp++;
	}
	fpn_printf("FP test ok addr=%p - %p size=%lx\n", fp_shared, cp-1, size);
}


static void test_fpn0_spinlock(void)
{

	unsigned long cpt;
	uint64_t cycles1 = 0, cycles2 = 0;
	fpn_spinlock_t slock;
	fpn_recurs_spinlock_t rlock;

	cpt = 0;
	fpn_spinlock_init(&slock);
	cycles1 = fpn_get_local_cycles();

	while (cpt < 1000000) {
		fpn_spinlock_lock(&slock);
		cpt++;
		fpn_spinlock_unlock(&slock);
	}
	cycles2 = fpn_get_local_cycles();
	fpn_printf("spinlock [lock + unlock] cost=%"PRIu64"\n",
		   fpn_div64_32(cycles2 - cycles1, cpt));

	cpt = 0;
	fpn_recurs_spinlock_init(&rlock);
	cycles1 = fpn_get_local_cycles();

	while (cpt < 1000000) {
		fpn_recurs_spinlock_lock(&rlock);
		cpt++;
		fpn_recurs_spinlock_unlock(&rlock);
	}
	cycles2 = fpn_get_local_cycles();
	fpn_printf("recurs_spinlock [lock + unlock] cost=%"PRIu64"\n",
		   fpn_div64_32(cycles2 - cycles1, cpt));
}

#if defined(CONFIG_MCORE_FPN_CRYPTO) && \
    (defined(CONFIG_MCORE_ARCH_DPDK) || \
     defined(CONFIG_MCORE_ARCH_TILEGX))
/**
 * This function display crypto statistics through fpn0
 */
static fpn_crypto_statistics_t global_stats;
static fpn_crypto_statistics_t per_core_stats[FPN_MAX_CORES];

static void
test_fpn0_crypto_stats(void)
{
	fpn_crypto_statistics_t s;
	fpn_crypto_statistics_t *old;
	unsigned index;

	/* Set up test pointer on all running cores */
	for (index=0 ; index<fpn_get_online_core_count() ; index++) {
		int core = fpn_get_online_core_num(index);

		fpn_crypto_statistics(NULL, core, &s);

		old  = &per_core_stats[core];
		fpn_printf("\nCore %d statistics\n", core);
		fpn_printf("Nb crypto                 : %9lu [%+ld]\n",
				   s.nb_crypto, s.nb_crypto - old->nb_crypto);
		fpn_printf("Nb asymmetric operations  : %9lu [%+ld]\n",
				   s.nb_kop, s.nb_kop - old->nb_kop);
		fpn_printf("Nb random operations      : %9lu [%+ld]\n",
				   s.nb_rand, s.nb_rand - old->nb_rand);
		fpn_printf("Out of space in queue     : %9lu [%+ld]\n",
				   s.out_of_space, s.out_of_space - old->out_of_space);
		fpn_printf("Out of mbufs              : %9lu [%+ld]\n",
				   s.out_of_buffer, s.out_of_buffer - old->out_of_buffer);
		fpn_printf("Internal errors           : %9lu [%+ld]\n",
				   s.internal_error, s.internal_error - old->internal_error);
		fpn_printf("Nb polls                  : %9lu [%+ld]\n",
				   s.nb_poll, s.nb_poll - old->nb_poll);
		fpn_printf("Dummy polls               : %9lu [%+ld]\n",
				   s.dummy_poll, s.dummy_poll - old->dummy_poll);
		fpn_printf("Timeout flushs            : %9lu [%+ld]\n",
				   s.timeout_flush, s.timeout_flush - old->timeout_flush);
		fpn_printf("Bulk flushs               : %9lu [%+ld]\n",
				   s.bulk_flush, s.bulk_flush - old->bulk_flush);

		* old = s;
	}

	fpn_crypto_statistics(NULL, FPN_CRYPTO(ALL_CORES), &s);

	old = &global_stats;
	fpn_printf("\nGlobal statistics\n");
	fpn_printf("Nb sessions               : %9lu [%+ld]\n",
	           s.nb_session, s.nb_session - old->nb_session);
	fpn_printf("Out of sessions           : %9lu [%+ld]\n",
	           s.out_of_session, s.out_of_session - old->out_of_session);
	fpn_printf("\nCumulative statistics\n");
	fpn_printf("Nb crypto                 : %9lu [%+ld]\n",
	           s.nb_crypto, s.nb_crypto - old->nb_crypto);
	fpn_printf("Nb asymmetric operations  : %9lu [%+ld]\n",
	           s.nb_kop, s.nb_kop - old->nb_kop);
	fpn_printf("Nb random operations      : %9lu [%+ld]\n",
	           s.nb_rand, s.nb_rand - old->nb_rand);
	fpn_printf("Out of space in queue     : %9lu [%+ld]\n",
	           s.out_of_space, s.out_of_space - old->out_of_space);
	fpn_printf("Out of mbufs              : %9lu [%+ld]\n",
	           s.out_of_buffer, s.out_of_buffer - old->out_of_buffer);
	fpn_printf("Internal errors           : %9lu [%+ld]\n",
	           s.internal_error, s.internal_error - old->internal_error);
	fpn_printf("Nb polls                  : %9lu [%+ld]\n",
	           s.nb_poll, s.nb_poll - old->nb_poll);
	fpn_printf("Dummy polls               : %9lu [%+ld]\n",
	           s.dummy_poll, s.dummy_poll - old->dummy_poll);
	fpn_printf("Timeout flushs            : %9lu [%+ld]\n",
	           s.timeout_flush, s.timeout_flush - old->timeout_flush);
	fpn_printf("Bulk flushs               : %9lu [%+ld]\n",
	           s.bulk_flush, s.bulk_flush - old->bulk_flush);
	* old = s;
}
#endif

static void test_fpn0_cpumask(void)
{
	char string1[256], string2[256];
	fpn_cpumask_t set1, set2, set3, empty, full;
	int i, res = 0;

	/* Clear empty set */
	fpn_cpumask_clear(&empty);
	fpn_cpumask_clear(&full);
	fpn_cpumask_invert(&full);

	/* Check numbet of cores in simple sets */
	if (fpn_cpumask_size(&empty) != 0) {
		fpn_printf("Invalid empty mask size\n");
		res = -1;
	}
	if (fpn_cpumask_size(&full) != FPN_MAX_CORES) {
		fpn_printf("Invalid full mask size\n");
		res = -1;
	}

	/* Check parsing function */

	/* Build hex string that sets all cores */
	sprintf(string1, "0x");
	for (i=0; i<FPN_MAX_CORES/4 ; i++)
		strcat(string1, "F");
	fpn_cpumask_parse(string1, &set1);

	/* Build list string that sets all cores */
	sprintf(string2, "0-%d", FPN_MAX_CORES-1);
	fpn_cpumask_parse(string2, &set2);

	/* Check result */
	if (!fpn_cpumask_isequal(&set1, &full)) {
		fpn_printf("Invalid parsed mask from string %s : ", string1);
		fpn_cpumask_display("", &set1);
		fpn_cpumask_display("\nExpected : ", &full);
		fpn_printf("\n");
		res = -1;
	}
	if (!fpn_cpumask_isequal(&set2, &full)) {
		fpn_printf("Invalid parsed mask from string %s : ", string2);
		fpn_cpumask_display("", &set2);
		fpn_cpumask_display("\nExpected : ", &full);
		fpn_printf("\n");
		res = -1;
	}

	/* Build hex string that sets upper and lower cores */
	sprintf(string1, "0x8");
	for (i=0; i<(FPN_MAX_CORES/4)-2 ; i++)
		strcat(string1, "0");
	strcat(string1, "1");
	fpn_cpumask_parse(string1, &set1);

	/* Build list string that sets upper and lower cores */
	sprintf(string2, "%d,0", FPN_MAX_CORES-1);
	fpn_cpumask_parse(string2, &set2);

	/* Set comparison mask */
	fpn_cpumask_clear(&set3);
	fpn_cpumask_set(&set3, 0);
	fpn_cpumask_set(&set3, FPN_MAX_CORES-1);

	/* Check result */
	if (!fpn_cpumask_isequal(&set1, &set3)) {
		fpn_printf("Invalid parsed mask from string %s : ", string1);
		fpn_cpumask_display("", &set1);
		fpn_cpumask_display("\nExpected : ", &set3);
		fpn_printf("\n");
		res = -1;
	}
	if (!fpn_cpumask_isequal(&set2, &set3)) {
		fpn_printf("Invalid parsed mask from string %s : ", string2);
		fpn_cpumask_display("", &set2);
		fpn_cpumask_display("\nExpected : ", &set3);
		fpn_printf("\n");
		res = -1;
	}

	/* Check size function */
	if (fpn_cpumask_size(&set1) != 2) {
		fpn_printf("Invalid mask size\n");
		res = -1;
	}

	/* Check unset function */
	/* Build same set by adding or removing CPUs from/in a set */
	set1 = empty;
	set2 = full;
	for (i=0; i<FPN_MAX_CORES/2 ; i++) {
		fpn_cpumask_set(&set1, i*2);
		fpn_cpumask_unset(&set2, i*2+1);
	}
	if (!fpn_cpumask_isequal(&set1, &set2)) {
		fpn_printf("Invalid set/unset masks : ");
		fpn_cpumask_display("", &set1);
		fpn_cpumask_display(" != ", &set2);
		fpn_printf("\n");
		res = -1;
	}

	/* Chek add function */
	fpn_cpumask_invert(&set2);
	fpn_cpumask_add(&set2, &set1);
	if (!fpn_cpumask_isequal(&full, &set2)) {
		fpn_cpumask_display("Invalid add masks : ", &set2);
		fpn_cpumask_display(" != ", &full);
		fpn_printf("\n");
		res = -1;
	}

	/* Check sub function */
	fpn_cpumask_sub(&set2, &set1);
	set3 = set2;
	fpn_cpumask_invert(&set2);
	if (!fpn_cpumask_isequal(&set1, &set2)) {
		fpn_cpumask_display("Invalid sub masks : ", &set1);
		fpn_cpumask_display(" != ", &set2);
		fpn_printf("\n");
		res = -1;
	}

	/* Check filter function */
	fpn_cpumask_filter(&set3, &set1);
	fpn_cpumask_filter(&set2, &set1);
	if (!fpn_cpumask_isequal(&set3, &empty)) {
		fpn_cpumask_display("Invalid filtered masks : ", &set3);
		fpn_cpumask_display(" != ", &empty);
		fpn_printf("\n");
		res = -1;
	}
	if (!fpn_cpumask_isequal(&set2, &set1)) {
		fpn_cpumask_display("Invalid filtered masks : ", &set1);
		fpn_cpumask_display(" != ", &set2);
		fpn_printf("\n");
		res = -1;
	}

	/* Check ismember */
	if ((fpn_cpumask_ismember(&set1, 1)) ||
		(!fpn_cpumask_ismember(&set1, 0))) {
		fpn_printf("Invalid member test : %d - !%d in ", 0, 1);
		fpn_cpumask_display("", &set1);
		fpn_printf("\n");
		res = -1;
	}
	if ((fpn_cpumask_ismember(&set1, FPN_MAX_CORES-1)) ||
		(!fpn_cpumask_ismember(&set1, FPN_MAX_CORES-2))) {
		fpn_printf("Invalid member test : %d - !%d in ", FPN_MAX_CORES-2, FPN_MAX_CORES-1);
		fpn_cpumask_display("", &set1);
		fpn_printf("\n");
		res = -1;
	}

	/* Check isempty */
	if ((fpn_cpumask_isempty(&set2)) ||
		(!fpn_cpumask_isempty(&empty))) {
		fpn_printf("Invalid empty test");
		res = -1;
	}

	if (res == 0)
		fpn_printf("== cpumask API test : OK ==\n");
	else
		fpn_printf("== cpumask API test : FAILED ==\n");
}

int fp_do_test_fpn0(uint8_t type)
{
	int res = 0;
	const char *comment;

	if (fp_test_fpn0_handlers[type])
		comment = fp_test_fpn0_handlers[type]->comment;
	else
		comment = fpn0_usage[get_fpn0_test_comment(type)].comment;

	fpn_printf("\nStarting test #%d: %s\n", type, comment);

	switch (type) {
	case TEST_FPN0_MBUF_AUDIT:
		test_fpn0_mbuf_audit();
		break;

	case TEST_FPN0_CKSUM_AUDIT:
		test_fpn0_cksum_audit();
		break;

	case TEST_FPN0_EQOS_STATS:
#ifdef CONFIG_MCORE_ARCH_OCTEON
		octeon_test_fpn0_eqos_stats();
#else
		fpn_printf("This test runs only on OCTEON\n");
#endif
		break;

	case TEST_FPN0_REASS_INFO:
		test_fpn0_reass_info();
		break;

	case TEST_FPN0_CHECK_SIZE:
		test_fpn0_check_size();
		break;

	case TEST_FPN0_CRYPTO_AUDIT:
		test_fpn0_crypto_audit();
		break;

	case TEST_FPN0_MTAG_AUDIT:
		test_fpn0_mtag_audit();
		break;

	case TEST_FPN0_TIMERS_ACCURACY:
		test_fpn0_timers_accuracy();
		break;

#ifdef CONFIG_MCORE_TIMER_GENERIC
	case TEST_FPN0_TIMERS_BIND:
		test_fpn0_timers_bind();
		break;

	case TEST_FPN0_TIMERS_SCALABILITY:
		test_fpn0_timers_scalability();
		break;
#endif
#ifdef CONFIG_MCORE_AATREE
	case TEST_FPN0_AATREE:
		test_fpn0_aatree();
		break;
#endif

	case TEST_FPN0_TIMERS_CALLOUT:
		test_fpn0_timers_callout();
		break;

	case TEST_FPN0_TIMERS_STRESS_RESET:
		test_fpn0_timers_stress_reset();
		break;

	case TEST_FPN0_TIMER_CALLOUTS_CHECK:
#ifdef CONFIG_MCORE_TIMER_GENERIC
		fpn_test_timer_callouts_check();
#else
		fpn_printf("This test is not implemented\n");
#endif
		break;

	case TEST_FPN0_LOCK_AUDIT:
		test_fpn0_lock_audit();
		break;

	case TEST_FPN0_POOL_DUMP:
#if defined(CONFIG_MCORE_ARCH_DPDK)
		fpn_dump_pools();
#else
		fpn_printf("This test runs only on DPDK\n");
#endif
		break;

	case TEST_FPN0_TIMERS_FREE_CALLLOUT:
		test_fpn0_timers_free_callout();
		break;

	case TEST_FPN0_GET_LOCAL_CYCLES:
		test_fpn0_get_local_cycles();
		break;

	case TEST_FPN0_REPLY_ONLY:
		break;

	case TEST_FPN0_MEMPOOL:
		res = test_fpn0_mempool();
		break;

	case TEST_FPN0_RING:
		test_fpn0_ring();
		break;

	case TEST_FPN0_RINGPOOL:
		test_fpn0_ringpool();
		break;

	case TEST_FPN0_RINGQUEUE:
		test_fpn0_ringqueue();
		break;

	case TEST_FPN0_SHMEM_CONF:
		test_fpn0_shmem_conf();
		break;

#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
	case TEST_FPN0_DEBUG_LOCK_LOG_DUMP:
		test_fpn0_debug_lock_log_dump();
		break;
#endif
	case TEST_FPN0_FPNMALLOC:
		test_fpn0_fpnmalloc();
		break;

	case TEST_FPN0_DO_MEMTEST:
		test_fpn0_memtest();
		break;

	case TEST_FPN0_SPINLOCK:
		test_fpn0_spinlock();
		break;

	case TEST_FPN0_XLP_DEBUG_MBUF:
		{
#ifdef CONFIG_MCORE_ARCH_XLP
		mbq_print_stats();
#else
		fpn_printf("This test runs only on XLP\n");
#endif
		}
		break;

	case TEST_FPN0_XLP_MAX_MBUF:
		{
#ifdef CONFIG_MCORE_ARCH_XLP
		test_fpn0_max_mbuf();
#else
		fpn_printf("This test runs only on XLP\n");
#endif
		}
		break;

	case TEST_FPN0_CRYPTO_STAT:
		{
#if defined(CONFIG_MCORE_FPN_CRYPTO) && defined(CONFIG_MCORE_ARCH_DPDK)
		test_fpn0_crypto_stats();
#else
		fpn_printf("This test runs only on platform implementing FPN crypto API\n");
#endif
		}
		break;

	case TEST_FPN0_NIC_STATS:
		{
#ifdef CONFIG_MCORE_ARCH_XLP
		extern void fpn_xlp_nae_print_freein(int node);
		int node;

		for (node = 0; node < NLM_MAX_NODES; node++) {
			if (nlm_node_cfg.nae_cfg[node] == NULL)
				continue;
			fpn_xlp_nae_print_freein(node);
		}
#else
		fpn_printf("This test runs only on XLP\n");
#endif
		}
		break;

	case TEST_FPN0_CPUMASK:
		test_fpn0_cpumask();
		break;

	default:
		if (fp_test_fpn0_handlers[type]) {
			fp_test_fpn0_handlers[type]->func();
			break;
		}
		fpn_printf("This test is not implemented\n");
		show_fpn0_usage();
		res = -1;
		break;
	}

	fpn_printf("\nTest (%d) is done. Status: %d\n", type, res);
	return res;
}

int fp_test_fpn0(struct mbuf *m)
{
	uint8_t type;

	/* test if it's an ICMP echo request on fpn0 */
	type = fp_test_fpn0_is_icmp_echo(m);

	if (type == TEST_FPN0_NOT_A_REQUEST)
		return -1;

	fp_do_test_fpn0(type);

	test_fpn0_answer_icmp_echo(m);

	return 0;
}

