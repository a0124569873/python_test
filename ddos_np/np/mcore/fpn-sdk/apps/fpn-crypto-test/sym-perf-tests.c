/*
 * Copyright(c) 2013 6WIND
 */

#include <sys/time.h>

#include <fpn-crypto-test.h>

sym_perf_test_desc_t sym_perf_tests[] = {
	{"\nVarious packet sizes tests", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"=========================="  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"\nPartial write tests", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"-------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128-CBC - size 1408 crypt  64 hash  64  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC - size 1408 crypt  68 hash  64  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408, 68, 64, 48, DEF_REQ, 0},
	{"AES128-CBC - size 1408 crypt 124 hash  64  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408,124, 64, 48, DEF_REQ, 0},
	{"AES128-CBC - size 1408 crypt  64 hash  68  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408, 64, 68, 48, DEF_REQ, 0},
	{"AES128-CBC - size 1408 crypt  64 hash 124  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408, 64,124, 48, DEF_REQ, 0},
	{"AES128-CBC - size 1408 crypt  68 hash  68  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408, 68, 68, 48, DEF_REQ, 0},
	{"AES128-CBC - size 1408 crypt 124 hash 124  ",    FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1408,124,124, 48, DEF_REQ, 0},

	{"\nAutobench comparison", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"--------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128-CBC SHA1-96 encryption - 64   bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,   64, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 decryption - 64   bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 0,   64, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 encryption - 128  bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  128, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 decryption - 128  bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 0,  128, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 encryption - 256  bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  256, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 decryption - 256  bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 0,  256, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 encryption - 512  bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  512, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 decryption - 512  bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 0,  512, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 encryption - 1024 bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 1024, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 decryption - 1024 bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 0, 1024, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 encryption - 1420 bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 1424, 44, 20, 28, DEF_REQ, 0},
	{"AES128-CBC SHA1-96 decryption - 1420 bytes " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 0, 1424, 44, 20, 28, DEF_REQ, 0},

	{"\nAlignements on AES128-CBC SHA1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"------------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"offset unaligned even                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,   64, 68, 68, 48, DEF_REQ, 0},
	{"offset unaligned odd                       " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,   64, 69, 69, 48, DEF_REQ, 0},
	{"offset aligned  (64/0)                     " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"offset aligned  (512/0)                    " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"offset aligned  (1504/0)                   " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},

	{"\nvarious packet sizes AES 128 CBC SHA1", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"-------------------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

	{"64    bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"128   bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  128, 64, 64, 48, DEF_REQ, 0},
	{"256   bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  256, 64, 64, 48, DEF_REQ, 0},
	{"512   bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"1024  bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 1024, 64, 64, 48, DEF_REQ, 0},
	{"1504  bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"2048  bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 2048, 64, 64, 48, DEF_REQ, 0},
	{"4096  bytes                                " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 4096, 64, 64, 48, DEF_REQ, 0},

	{"\n64 bytes packets", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"================"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

	{"\nNumber of queued requests AES128-CBC", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"------------------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"16   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, 16,  0},
	{"32   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, 32,  0},
	{"64   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, 64,  0},
	{"128  per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, 128, 0},

	{"\nEncryption/Decryption", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"---------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128-ECB encryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128-ECB decryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC encryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC decryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128-GCM encryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128-GCM decryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 0,   64, 64, 64, 48, DEF_REQ, 1},
	{"AES256-ECB encryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256-ECB decryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256-CBC encryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256-CBC decryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256-GCM encryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256-GCM decryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 0,   64, 64, 64, 48, DEF_REQ, 2},

	{"\nhash/no hash (encryption)", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"-------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128 - NULL                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - SHA1                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - GCM                               " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - XCBC                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_AES_XCBC)  , 128, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - NULL                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - SHA512                            " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_HMACSHA512), 512,256, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - GCM                               " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - XCBC                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_AES_XCBC)  , 128, 96, 1,   64, 64, 64, 48, DEF_REQ, 0},

	{"\n512 bytes packets", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"================="  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

	{"\nNumber of queued requests AES128-CBC", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"------------------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"16   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, 16,  0},
	{"32   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, 32,  0},
	{"64   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, 64,  0},
	{"128  per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, 128, 0},

	{"\nEncryption/Decryption", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"---------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128-ECB encryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128-ECB decryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC encryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC decryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128-GCM encryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128-GCM decryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 0,  512, 64, 64, 48, DEF_REQ, 3},
	{"AES256-ECB encryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256-ECB decryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256-CBC encryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256-CBC decryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256-GCM encryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256-GCM decryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 0,  512, 64, 64, 48, DEF_REQ, 4},

	{"\nhash/no hash (encryption)", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"-------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128 - NULL                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - SHA1                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - GCM                               " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - XCBC                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_AES_XCBC)  , 128, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - NULL                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - SHA512                            " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_HMACSHA512), 512,256, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - GCM                               " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - XCBC                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_AES_XCBC)  , 128, 96, 1,  512, 64, 64, 48, DEF_REQ, 0},

	{"\n1504 bytes packets", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"=================="  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

	{"\nNumber of queued requests AES128-CBC", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"------------------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"16   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, 16,  0},
	{"32   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, 32,  0},
	{"64   per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, 64,  0},
	{"128  per session                           " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, 128, 0},

	{"\nEncryption/Decryption", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"---------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128-ECB encryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128-ECB decryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC encryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128-CBC decryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128-GCM encryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128-GCM decryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 0, 1504, 64, 64, 48, DEF_REQ, 5},
	{"AES256-ECB encryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256-ECB decryption                      " ,   FPN_CRYPTO(ALGO_AES_ECB), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256-CBC encryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256-CBC decryption                      " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 0, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256-GCM encryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256-GCM decryption                      " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 0, 1504, 64, 64, 48, DEF_REQ, 6},

	{"\nhash/no hash (encryption)", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"-------------------------"  , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{"AES128 - NULL                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - SHA1                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_HMACSHA1)  , 160, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - GCM                               " ,   FPN_CRYPTO(ALGO_AES_GCM), 128, FPN_CRYPTO(AUTH_AES_GCM)   , 128, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES128 - XCBC                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 128, FPN_CRYPTO(AUTH_AES_XCBC)  , 128, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - NULL                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_NULL)      ,   0,  0, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - SHA512                            " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_HMACSHA512), 512,256, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - GCM                               " ,   FPN_CRYPTO(ALGO_AES_GCM), 256, FPN_CRYPTO(AUTH_AES_GCM)   , 256, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},
	{"AES256 - XCBC                              " ,   FPN_CRYPTO(ALGO_AES_CBC), 256, FPN_CRYPTO(AUTH_AES_XCBC)  , 128, 96, 1, 1504, 64, 64, 48, DEF_REQ, 0},

	/* No more test */
	{NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

static char key[] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
                      0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
                      0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
                      0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50
                    };

static char null_data[65535];

struct keys_s g_keys = {
	.cipher_key = key,
	.auth_key   = key,
	.iv         = key,
};

static char g_hash [][16] = {
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x38, 0x66, 0x34, 0x61, 0x34, 0xc5, 0x46, 0x90, 0xef, 0xda, 0x88, 0x85, 0xdb, 0xbf, 0x03, 0x1b },
	{ 0xc3, 0x7f, 0xd1, 0xfe, 0x47, 0xcf, 0x7d, 0x80, 0xc5, 0x92, 0xd8, 0xc8, 0x2e, 0x00, 0xb1, 0x24 },
	{ 0x89, 0xf4, 0xd9, 0x23, 0xbb, 0x85, 0xf4, 0x48, 0x91, 0x59, 0x0a, 0x19, 0x6f, 0x5e, 0x97, 0x2a },
	{ 0x9b, 0x70, 0x7d, 0x7c, 0x89, 0xac, 0xee, 0x6e, 0xd1, 0xc6, 0xa3, 0x46, 0xda, 0xb4, 0x09, 0xf7 },
	{ 0x20, 0x8a, 0x98, 0x45, 0x6d, 0xe4, 0x7a, 0x4c, 0x2d, 0x9c, 0x4c, 0xf2, 0xe8, 0x0c, 0xe1, 0x60 },
	{ 0xbe, 0x67, 0x5e, 0xba, 0xbc, 0x39, 0x93, 0xab, 0xe7, 0x10, 0x12, 0x12, 0xbd, 0x33, 0x9c, 0xeb },
};

int fpn_crypto_init_sym_perf_per_core(void * param);

void sym_perf_callback(void * param, void * buf, int result)
{
	struct core_conf_s * conf = param;
	struct mbuf * mbuf, * mbuf_dst;
	uint32_t    inst;
	int         res;

	mbuf_dst = (struct mbuf *) buf;
	mbuf     = m_nextpkt(mbuf_dst);

	/* An error occured */
	if (result != FPN_CRYPTO(SUCCESS)) {
		printf("Error during encryption of mbuf %p\n", mbuf);

		/* Free mbuf */
		m_freem(mbuf);
		m_freem(mbuf_dst);

		return;
	}

	/* One more packet processed */
	conf->loop_count++;

	/* Check end of test */
	if (unlikely(conf->ending)) {
		/* Free mbuf */
		m_freem(mbuf);
		m_freem(mbuf_dst);

		conf->in_process -= 1;
		if (unlikely(conf->in_process == 0)) {
			struct timeval ts;

			gettimeofday(&ts, 0);
			conf->end_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

			/* Close sessions */
			for (inst=0 ; inst<conf->nb_inst ; inst++) {
				/* Close session */
				if (fpn_crypto_session_free(conf->session[inst]) != FPN_CRYPTO(SUCCESS)) {
					printf("Can not close session\n");
				}

				/* Reset session */
				conf->session[inst] = NULL;
			}

			/* Signal master thread */
			fpn_atomic_inc(&done);
		}
	} else {
		struct sym_perf_test_desc_s * test = conf->test;
		fpn_crypto_op_t operation;

		/* Resend packet */
		if (iv_len[test->cipher]) {
			operation.enc_iv    = mtod(mbuf, char *) + test->iv_offset;
		} else {
			operation.enc_iv    = NULL;
		}

		if (test->digest_len != 0) {
			operation.auth_dst  = m_tail(mbuf);
		} else {
			operation.auth_dst  = NULL;
		}

		operation.session       = conf->session[m_input_port(mbuf)];
		operation.src           = mbuf;
		operation.enc_dst       = mbuf_dst;
		operation.enc_len       = test->data_size;
		operation.enc_skip      = test->crypto_offset;
		operation.enc_inject    = 0;
		operation.auth_len      = test->data_size + test->crypto_offset - test->auth_offset;
		operation.auth_skip     = test->auth_offset;
		operation.opaque        = conf;
		operation.cb            = sym_perf_callback;
		operation.flags         = FPN_CRYPTO(F_MBUF);

		while ((res = fpn_crypto_invoke(&operation)) == FPN_CRYPTO(BUSY));
		if (res < 0) {
			printf("Can not re-encrypt buffer [%d]\n", res);

			/* Free mbuf */
			m_freem(mbuf);
			m_freem(mbuf_dst);

			conf->in_process -= 1;
			if (unlikely(conf->in_process == 0)) {
				struct timeval ts;

				gettimeofday(&ts, 0);
				conf->end_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

				/* Close sessions */
				for (inst=0 ; inst<conf->nb_inst ; inst++) {
					/* Close session */
					if (fpn_crypto_session_free(conf->session[inst]) != FPN_CRYPTO(SUCCESS)) {
						printf("Can not close session\n");
					}

					/* Reset session */
					conf->session[inst] = NULL;
				}

				/* Signal master thread */
				fpn_atomic_inc(&done);
			}
		}
	}
}


/* main processing loop */
int fpn_crypto_init_sym_perf_per_core(void * param)
{
	struct core_conf_s * conf = (struct core_conf_s *) param;
	struct sym_perf_test_desc_s * test;
	uint32_t count, inst;
	int      res;
	struct mbuf * mbuf, * mbuf_dst;
	struct timeval ts;

	/* Get test from conf */
	test = conf->test;

	/* Initialize structure */
	conf->end_time         = 0;
	conf->loop_count       = 0;
	conf->ending           = 0;
	conf->nb_inst          = DEF_SESS;

	/* Initialize startup time */
	gettimeofday(&ts, 0);
	conf->start_time = (ts.tv_sec * 1000 + (ts.tv_usec / 1000));

	for (inst=0 ; inst<conf->nb_inst ; inst++) {
		fpn_crypto_init_t init;
		fpn_crypto_op_t operation;

		/* Initialize a crypto session */
		init.enc_alg   = test->cipher;
		init.enc_klen  = test->cipher_key_len;
		init.enc_key   = g_keys.cipher_key;
		init.auth_alg  = test->auth;
		init.auth_klen = test->cipher == FPN_CRYPTO(ALGO_AES_GCM) ? 0 : test->auth_key_len;
		init.auth_dlen = test->digest_len;
		init.auth_key  = g_keys.auth_key;
		init.flags     = test->encrypt ? FPN_CRYPTO(F_ENCRYPT) : 0;
		if ((init.enc_alg == FPN_CRYPTO(ALGO_AES_GCM)) ||
		    (init.auth_alg == FPN_CRYPTO(AUTH_AES_GMAC))) {
			init.flags |= FPN_CRYPTO(F_AUTH_CHECK);
		}
		if ((conf->session[inst] = fpn_crypto_session_new(&init)) == NULL) {
			/* Signal master thread */
			fpn_atomic_inc(&done);
			return(-1);
		}

		/* Send some packets */
		for (count = 0 ; count<test->tx_burst; count++) {
			mbuf = m_alloc();
			if (mbuf == NULL) {
				printf("Can not allocate buffer\n");
				return(-1);
			}

			if (iv_len[test->cipher]) {
				operation.enc_iv    = mtod(mbuf, char *) + test->iv_offset;
				if (m_copyfrombuf(mbuf, test->iv_offset, g_keys.iv, iv_len[test->cipher]) != iv_len[test->cipher]) {
					printf("Can not populate buffer\n");
					return(-1);
				}
			} else {
				operation.enc_iv    = NULL;
			}

			/* Copy data to encrypt */
			if (m_copyfrombuf(mbuf, test->crypto_offset, null_data, test->data_size) != test->data_size) {
				printf("Can not populate buffer\n");
				return(-1);
			}

			if (test->digest_len != 0) {
				/* Check that there is enough space for authentication result */
				if (m_tailroom(mbuf) < test->digest_len / 8) {
					printf("Not enough room in last segment\n");
					return(-1);
				}

				/* Copy hash after data to authenticate */
				operation.auth_dst  = m_tail(mbuf);

				/* For decrypt tests that need a valid tag, set up auth tag */
				memcpy(operation.auth_dst, g_hash[test->expected_hash], test->digest_len / 8);
			} else {
				operation.auth_dst  = NULL;
			}

			m_set_input_port(mbuf, inst);

			/* No in place encryption, to be able to reuse source buffer as is */
			mbuf_dst = m_dup(mbuf);
			if (mbuf_dst == NULL) {
				printf("Can not duplicate buffer\n");
				return(-1);
			}

			/* Link dest buffer to source buffer */
			m_set_nextpkt(mbuf_dst, mbuf);

			operation.session       = conf->session[m_input_port(mbuf)];
			operation.src           = mbuf;
			operation.enc_dst       = mbuf_dst;
			operation.enc_len       = test->data_size;
			operation.enc_skip      = test->crypto_offset;
			operation.enc_inject    = 0;
			operation.auth_len      = test->data_size + test->crypto_offset - test->auth_offset;
			operation.auth_skip     = test->auth_offset;
			operation.opaque        = conf;
			operation.cb            = sym_perf_callback;
			operation.flags         = FPN_CRYPTO(F_MBUF);

			/* One more buffer to process */
			conf->in_process++;

			/* Process buffer */
			while ((res = fpn_crypto_invoke(&operation)) == FPN_CRYPTO(BUSY));
			if (res < 0) {
				printf("Can not encrypt buffer [%d]\n", res);

				/* Free mbuf */
				m_freem(mbuf);
				m_freem(mbuf_dst);
			}
		}
	}

	return(0);
}

