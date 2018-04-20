/*
 * Copyright(c) 2011  6WIND
 */

/*	$OpenBSD: des.h,v 1.3 2005/06/13 10:56:44 hshoexer Exp $	*/

/* lib/des/des.h */
/* Copyright (C) 1995 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 *
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef __FPN_DES_H__
#define __FPN_DES_H__

#include <sys/types.h>
#ifndef _KERNEL
#include <stdio.h>
#endif

#include "fpn.h"

typedef unsigned char des_cblock[8];
typedef struct des_ks_struct {
	union {
		des_cblock _;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		int32_t pad[2];
	} ks;
#undef _
#define _	ks._
} des_key_schedule[16];


#define DES_KEY_SZ	(sizeof(des_cblock))
#define DES_BLK_SZ	(sizeof(des_cblock))
#define DES_SCHEDULE_SZ (sizeof(des_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define DES_CBC_MODE	0
#define DES_PCBC_MODE	1


/* The next line is used to disable full ANSI prototypes, if your
 * compiler has problems with the prototypes, make sure this line always
 * evaluates to true :-) */
#if defined(__STDC__)
#undef PROTO
#define PROTO
#endif
#ifdef PROTO
void fpn_des_blk_encrypt(uint8_t *src, uint8_t *dst, uint8_t *key);
void fpn_des_blk_decrypt(uint8_t *src, uint8_t *dst, uint8_t *key);
int fpn_des_setkey(uint8_t *sched, uint8_t *key, int len);
void fpn_3des_blk_encrypt(uint8_t *src, uint8_t *dst, uint8_t *key);
void fpn_3des_blk_decrypt(uint8_t *src, uint8_t *dst, uint8_t *key);
int fpn_3des_setkey(uint8_t *sched, uint8_t *key, int len);

void des_ecb3_encrypt(des_cblock *input,des_cblock *output,
		      des_key_schedule *ks1,des_key_schedule *ks2,
		      des_key_schedule *ks3, int enc);
void des_ecb_encrypt(des_cblock *input,des_cblock *output,
		     des_key_schedule *ks,int enc);
void des_encrypt(u_int32_t *data,des_key_schedule *ks, int enc);
void des_encrypt2(u_int32_t *data,des_key_schedule *ks, int enc);

void des_set_odd_parity(des_cblock *key);
int des_is_weak_key(des_cblock *key);
int des_set_key(des_cblock *key,des_key_schedule *schedule);
int des_key_sched(des_cblock *key,des_key_schedule *schedule);

#endif

#include "fpn-cbc.h"
#include "fpn-des_locl.h"
#define fpn_des_cbc_encrypt(m, o, l, i, K) \
	fpn_des_cbc(m, o, l, i, K, DES_ENCRYPT)
#define fpn_des_cbc_decrypt(m, o, l, i, K) \
	fpn_des_cbc(m, o, l, i, K, DES_DECRYPT)
static inline void fpn_des_cbc(struct mbuf *m,
			       uint32_t off,
			       unsigned int nbytes,
			       const uint64_t *iv,
			       const uint64_t *K64,
			       int enc)
{
	uint64_t *src = m_off(m, off, uint64_t*);
	des_key_schedule sch;
	des_cblock iv_tmp;

	memcpy(iv_tmp, iv, sizeof(des_cblock));
	fpn_des_setkey((uint8_t *)&sch, (uint8_t *)K64, 64);

	if (m_is_contiguous(m)) {
		if(enc)
			cbc_encrypt((unsigned char *)src, (unsigned char *)src,
				    nbytes, (uint8_t *)&sch, (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_des_blk_encrypt);
		else
			cbc_decrypt((unsigned char *)src, (unsigned char *)src,
				    nbytes, (uint8_t *)&sch, (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_des_blk_decrypt);
	} else {
		char *buf = (char *)fpn_malloc(nbytes, 64);
		if (buf == NULL)
			return;

		__m_copytobuf(buf, m, off, nbytes);
		if(enc)
			cbc_encrypt((unsigned char *)buf, (unsigned char *)buf,
				    nbytes, (uint8_t *)&sch, (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_des_blk_encrypt);
		else
			cbc_decrypt((unsigned char *)buf, (unsigned char *)buf,
				    nbytes, (uint8_t *)&sch, (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_des_blk_decrypt);
		__m_copyfrombuf(m, off, buf, nbytes);
		fpn_free(buf);
	}
}

#define fpn_3des_cbc_encrypt(m, o, l, i, K) \
	fpn_3des_cbc(m, o, l, i, K, DES_ENCRYPT)
#define fpn_3des_cbc_decrypt(m, o, l, i, K) \
	fpn_3des_cbc(m, o, l, i, K, DES_DECRYPT)
static inline void fpn_3des_cbc(struct mbuf *m,
				uint32_t off,
				unsigned int nbytes,
				const uint64_t *iv,
				const uint64_t *K64,
				int enc)
{
	uint64_t *src = m_off(m, off, uint64_t*);
	des_key_schedule sch[3];
	des_cblock iv_tmp;

	memcpy(iv_tmp, iv, sizeof(des_cblock));
	fpn_3des_setkey((uint8_t *)sch, (uint8_t *)K64, 192);

	if (m_is_contiguous(m)) {
		if(enc)
			cbc_encrypt((unsigned char *)src, (unsigned char *)src,
				    (unsigned long)nbytes, (uint8_t *)sch,
				    (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_3des_blk_encrypt);
		else
			cbc_decrypt((unsigned char *)src, (unsigned char *)src,
				    (unsigned long)nbytes, (uint8_t *)sch,
				    (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_3des_blk_decrypt);
	} else {
		char *buf = (char *)fpn_malloc(nbytes, 64);
		if (buf == NULL)
			return;

		__m_copytobuf(buf, m, off, nbytes);
		if(enc)
			cbc_encrypt((unsigned char *)buf, (unsigned char *)buf,
				    (unsigned long)nbytes, (uint8_t *)sch,
				    (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_3des_blk_encrypt);
		else
			cbc_decrypt((unsigned char *)buf, (unsigned char *)buf,
				    (unsigned long)nbytes, (uint8_t *)sch,
				    (uint8_t *)iv_tmp,
				    DES_BLK_SZ, fpn_3des_blk_decrypt);
		__m_copyfrombuf(m, off, buf, nbytes);
		fpn_free(buf);
	}
}
#endif /* __FPN_DES_H__ */
