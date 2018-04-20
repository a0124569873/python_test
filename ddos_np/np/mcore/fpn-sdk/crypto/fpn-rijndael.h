/*
 * Copyright(c) 2011  6WIND
 */

/*	$OpenBSD: rijndael.h,v 1.13 2008/06/09 07:49:45 djm Exp $ */

/**
 * rijndael-alg-fst.h
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __FPN_RIJNDAEL_H__
#define __FPN_RIJNDAEL_H__

#include <assert.h>
#include "fpn-cbc.h"

#define AES_MAXKEYBITS	(256)
#define AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)
/* for 256-bit keys, fewer for less */
#define AES_MAXROUNDS	14

#define AES_BLOCK_SIZE 16

typedef unsigned char	u8;
typedef unsigned short	u16;
typedef unsigned int	u32;

/*  The structure for key information */
typedef struct {
	int	enc_only;		/* context contains only encrypt schedule */
	int	Nr;			/* key-length-dependent number of rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u32	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

void aes_encrypt(uint8_t *src, uint8_t *dst, uint8_t *key);
void aes_decrypt(uint8_t *src, uint8_t *dst, uint8_t *key);
int aes_setkey(uint8_t *sched, uint8_t *key, int len);
int aes_setkey_enc(uint8_t *sched, uint8_t *key, int len);

int	 rijndael_set_key(rijndael_ctx *, const uint8_t *, int);
int	 rijndael_set_key_enc_only(rijndael_ctx *, const uint8_t *, int);
void	 rijndael_decrypt(rijndael_ctx *, const uint8_t *, uint8_t *);
void	 rijndael_encrypt(rijndael_ctx *, const uint8_t *, uint8_t *);

int	rijndaelKeySetupEnc(unsigned int [], const unsigned char [], int);
int	rijndaelKeySetupDec(unsigned int [], const unsigned char [], int);
void	rijndaelEncrypt(const unsigned int [], int, const unsigned char [],
	    unsigned char []);

#define AES_ENCRYPT 1
#define AES_DECRYPT 0

static inline void fpn_aes_cbc(struct mbuf *m,
			      uint32_t off,
			      unsigned int nbytes,
			      const uint64_t *iv,
			      const uint64_t *K64,
			      uint8_t key_len,
			      int enc)
{
	uint64_t *src = m_off(m, off, uint64_t*);
	rijndael_ctx ctx;
	unsigned char iv_tmp[AES_BLOCK_SIZE];

	aes_setkey((uint8_t *)&ctx, (uint8_t *)K64, key_len);
	memcpy(iv_tmp, iv, AES_BLOCK_SIZE);

	if (m_is_contiguous(m)) {
		if(enc)
			cbc_encrypt((unsigned char *)src, (unsigned char *)src,
				    nbytes, (uint8_t *)&ctx, (uint8_t *)iv_tmp,
				    AES_BLOCK_SIZE, aes_encrypt);
		else
			cbc_decrypt((unsigned char *)src, (unsigned char *)src,
				    nbytes, (uint8_t *)&ctx, (uint8_t *)iv_tmp,
				    AES_BLOCK_SIZE, aes_decrypt);
	} else {
		char *buf = (char *)fpn_malloc(nbytes, 64);
		if (buf == NULL)
			return;

		__m_copytobuf(buf, m, off, nbytes);
		if(enc)
			cbc_encrypt((unsigned char *)buf, (unsigned char *)buf,
				    nbytes, (uint8_t *)&ctx, (uint8_t *)iv_tmp,
				    AES_BLOCK_SIZE, aes_encrypt);
		else
			cbc_decrypt((unsigned char *)buf, (unsigned char *)buf,
				    nbytes, (uint8_t *)&ctx, (uint8_t *)iv_tmp,
				    AES_BLOCK_SIZE, aes_decrypt);
		__m_copyfrombuf(m, off, buf, nbytes);
		fpn_free(buf);
	}
}

/*
 * AES-XCBC-MAC-96 (RFC3566)
 */
static const unsigned char k1[16] = {
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
static const unsigned char k2[16] = {
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
	0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02};
static const unsigned char k3[16] = {
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
	0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03};

static inline void AES_xcbc_mac(const unsigned char *in,
				const unsigned long length, rijndael_ctx *ctx_p,
				unsigned char *ivec)
{
	unsigned long len = length, n;
	unsigned char tmp[AES_BLOCK_SIZE], pad[AES_BLOCK_SIZE];
	unsigned char key1[AES_BLOCK_SIZE],
		      key2[AES_BLOCK_SIZE],
		      key3[AES_BLOCK_SIZE];
	rijndael_ctx ctx1;

	assert(in && ctx_p && ivec);

	rijndael_encrypt(ctx_p, k1, key1);
	rijndael_encrypt(ctx_p, k2, key2);
	rijndael_encrypt(ctx_p, k3, key3);

	rijndael_set_key_enc_only(&ctx1, key1, AES_BLOCK_SIZE * 8);

	while (len > AES_BLOCK_SIZE) {
		for (n = 0; n < AES_BLOCK_SIZE; n++)
			tmp[n] = in[n] ^ ivec[n];
		rijndael_encrypt(&ctx1, tmp, tmp);
		memcpy(ivec, tmp, AES_BLOCK_SIZE);

		len -= AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
	}

	if (len == AES_BLOCK_SIZE) {
		for (n = 0; n < len; n++)
			tmp[n] = in[n] ^ ivec[n] ^ key2[n];
		rijndael_encrypt(&ctx1, tmp, tmp);
		memcpy(ivec, tmp, AES_BLOCK_SIZE);
	} else {
		memcpy(pad, in, len);
		pad[len] = 0x80;
		for (n = len + 1; n < AES_BLOCK_SIZE; n++)
			pad[n] = 0x00;

		for (n = 0; n < AES_BLOCK_SIZE; n++)
			tmp[n] = pad[n] ^ ivec[n] ^ key3[n];
		rijndael_encrypt(&ctx1, tmp, tmp);
		memcpy(ivec, tmp, AES_BLOCK_SIZE);
	}
}

static inline void fpn_generic_aes_xcbc_mac(char *aes_xcbc, const char *key,
					    const struct mbuf *m, uint32_t off,
					    uint32_t buffer_len)
{
	const unsigned char *buffer = m_off(m, off, const unsigned char *);
	unsigned char iv_tmp[AES_BLOCK_SIZE];
	rijndael_ctx ctx;

	memset(iv_tmp, 0, AES_BLOCK_SIZE);

	rijndael_set_key_enc_only(&ctx, (const uint8_t *)key,
				  AES_BLOCK_SIZE * 8);

	if (m_is_contiguous(m)) {
		AES_xcbc_mac(buffer, (const unsigned long)buffer_len,
			     &ctx, (unsigned char *)iv_tmp);
	} else {
		char *authbuf = (char *)fpn_malloc(buffer_len, 64);
		if (authbuf == NULL)
			return;

		__m_copytobuf(authbuf, m, off, buffer_len);
		AES_xcbc_mac((const unsigned char *)authbuf,
			     (const unsigned long)buffer_len,
			     &ctx, (unsigned char *)iv_tmp);
		fpn_free(authbuf);
	}
	memcpy(aes_xcbc, iv_tmp, AES_BLOCK_SIZE);
}

#endif /* __FPN_RIJNDAEL_H */
