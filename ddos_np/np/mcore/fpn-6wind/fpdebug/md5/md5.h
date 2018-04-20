/*
 * Copyright 2005 6WIND, All rights reserved.
 */

/* MD5.H - header file for MD5C.C */
#ifndef _FPDEBUG_MD5_
#define _FPDEBUG_MD5_

#define word32 u_int32_t
#define word8 u_int8_t
#define mxmalloc malloc
#define HAVE_MEMSET 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/* POINTER defines a generic pointer type */
typedef u_int8_t *POINTER;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

/* MD5 context. */
typedef struct  {
	word32 state[4];			/* state (ABCD) */
	word32 count[2];			/* number of bits, modulo 2^64 (lsb first) */
	word8 buffer[64];			/* input buffer */
} MD5_CTX;

#define md5_ctxt MD5_CTX

void MD5Init PROTO_LIST((MD5_CTX *));
void MD5Update PROTO_LIST((MD5_CTX *, u_int8_t *, u_int32_t));
void *MD5Final PROTO_LIST((MD5_CTX *));

#endif // _FPDEBUG_MD5_