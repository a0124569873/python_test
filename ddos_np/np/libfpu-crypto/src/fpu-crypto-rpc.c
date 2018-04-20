/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "fpu-rpc-var.h"
#include "libfpu-rpc.h"
#include "libfpu-crypto.h"

/* Maximum crypto block size */
#define MAX_CRYPTO_BLOCK_SIZE       16

/* Memory barriers */
#define wmb() __sync_synchronize()
#define rmb() __sync_synchronize()

static struct fpu_rpc_fp_shmem  *fpu_crypto_fp_shmem;
static __thread struct fpu_rpc_app_shmem *fpu_crypto_app_shmem;
static __thread pthread_t fpu_crypto_tid;

/**
 * Reset per process variables in child on fork
 */
static void fpu_crypto_atfork_child(void)
{
	/* Reset tid of current thread */
	/* pthread_id may be identical in two processes */
	/* shared mem will be created on first API call */
	memset(&fpu_crypto_tid, 0, sizeof(pthread_t));
}

/**
 * Check if a thread was created
 */
static inline void fpu_crypto_check_thread(void)
{
	int s, id, res = 0;
	char app_shmname[64];

	/* Get current thread id */
	pthread_t tid = pthread_self();

	/* Tid is not the running one, either it is the first call, */
	/* or a new thread was spawned using pthread_create */
	if (!pthread_equal(tid, fpu_crypto_tid)) {
		/* Store current tid */
		fpu_crypto_tid = tid;

		/* Get socket and id */
		s = fpu_rpc_connect(&id);
		if (s < 0) {
			res = -1;
		}

		if (res == 0) {
			/* Set shared mem name */
			snprintf(app_shmname, sizeof(app_shmname),
				 "fpu-crypto-%d-%d", (int) syscall(SYS_gettid), id);

			/* Map mem */
			fpu_crypto_app_shmem = fpu_rpc_create_app_shmem(app_shmname);
			if (fpu_crypto_app_shmem == NULL) {
				close(s);
				res = -1;
			}
		}

		if (res == 0) {
			/* Register thread */
			if (fpu_rpc_register(s, app_shmname, fpu_crypto_app_shmem) < 0) {
				fpu_rpc_delete_app_shmem(app_shmname);
				close(s);
				res = -1;
			}
		}
	}

	/* Do not let thread starting if shared mem can not be allocated */
	if (res < 0) {
		abort();
	}
}

/**
 * Initialize the library
 */
int fpu_crypto_rpc_init(void)
{
	/* Map common shared mem */
	fpu_crypto_fp_shmem = fpu_rpc_map_fp_shmem();
	if (fpu_crypto_fp_shmem == NULL) {
		return -1;
	}

	/* Hook fork */
	if (pthread_atfork(NULL, NULL, fpu_crypto_atfork_child) < 0) {
		return -1;
	}

	return 0;
}

/**
 * Initialize a session
 */
uint64_t fpu_crypto_session_new(fpu_crypto_init_t * init)
{
	struct fpu_rpc_cmd_crypto_session_new *session_new;
	int offset = 0;
	int len;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	session_new = &fpu_crypto_app_shmem->crypto_session_new;

	/* Setup new session data */
	fpu_crypto_app_shmem->type = CRYPTO_SESSION_NEW;
	session_new->enc_alg    = init->enc_alg;
	session_new->enc_klen   = init->enc_klen;
	session_new->auth_alg   = init->auth_alg;
	session_new->auth_klen  = init->auth_klen;
	session_new->auth_dlen  = init->auth_dlen;
	session_new->flags      = init->flags;

	/* Copy keys */
	len = (init->enc_klen + 7) / 8;
	if ((offset + len) > FPU_CRYPTO_MAX_KEY_SIZE) {
		return(-ENOMEM);
	}
	if (len > 0) {
		memcpy(&session_new->data[offset], init->enc_key,  len);
		offset += len;
	}

	len = (init->auth_klen + 7) / 8;
	if ((offset + len) > FPU_CRYPTO_MAX_KEY_SIZE) {
		return(-ENOMEM);
	}
	if (len > 0) {
		memcpy(&session_new->data[offset], init->auth_key, len);
		offset += len;
	}

	/* Start session creation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Return result */
	return session_new->ret;
}


/**
 * Duplicate a session
 */
uint64_t fpu_crypto_session_dup(uint64_t session)
{
	struct fpu_rpc_cmd_crypto_session_dup *session_dup;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	session_dup = &fpu_crypto_app_shmem->crypto_session_dup;

	/* Setup message data */
	fpu_crypto_app_shmem->type = CRYPTO_SESSION_DUP;
	session_dup->session = session;

	/* Start session closure */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Return result */
	return session_dup->ret;
}


/**
 * Close a session
 */
int32_t fpu_crypto_session_free(uint64_t session)
{
	struct fpu_rpc_cmd_crypto_session_free *session_free;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	session_free = &fpu_crypto_app_shmem->crypto_session_free;

	/* Setup message data */
	fpu_crypto_app_shmem->type = CRYPTO_SESSION_FREE;
	session_free->session = session;

	/* Start session closure */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Return result */
	return session_free->ret;
}


/**
 * Start a symmetric crypto operation
 */
int32_t fpu_crypto_invoke(fpu_crypto_op_t * operation)
{
	struct fpu_rpc_cmd_crypto_invoke *invoke;
	fpu_buf_t * buf;
	uint32_t to_copy;
	uint32_t len;
	uint32_t output;
	uint32_t offset = 0;
	uint32_t vec;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	invoke = &fpu_crypto_app_shmem->crypto_invoke;

	/* Setup crypto operation */
	fpu_crypto_app_shmem->type        = CRYPTO_INVOKE;
	invoke->session     = operation->session;
	invoke->enc_len     = operation->enc_len;
	invoke->enc_skip    = operation->enc_skip;
	invoke->auth_len    = operation->auth_len;
	invoke->auth_skip   = operation->auth_skip;
	invoke->iv_len      = operation->iv_len;
	invoke->flags       = operation->flags;

	/* First set iv in buffer */
	if (operation->iv_len) {
		len = operation->iv_len;
		if ((offset + len) > FPU_CRYPTO_MAX_BUF_SIZE) {
			return(-ENOMEM);
		}
		memcpy(&invoke->data[offset], operation->enc_iv, len);
		offset += len;
	}

	/* Get length of used data in buffer */
	if ((operation->enc_skip  + operation->enc_len) >
	    (operation->auth_skip + operation->auth_len)) {
		len = operation->enc_skip  + operation->enc_len;
	} else {
		len = operation->auth_skip + operation->auth_len;
	}

	if ((offset + len) > FPU_CRYPTO_MAX_BUF_SIZE) {
		return(-ENOMEM);
	}

	if (len > 0) {
		/* Copy all source segments in buffer */
		vec     = 0;
		buf     = operation->src;
		to_copy = len;
		while ((to_copy > 0) && (vec<buf->veccnt)) {
			/* Limit data copy to vec length */
			len = to_copy > buf->vec[vec].len ? buf->vec[vec].len : to_copy;
			if ((offset + len) > FPU_CRYPTO_MAX_BUF_SIZE) {
				return(-ENOMEM);
			}

			/* Copy data */
			memcpy(&invoke->data[offset], buf->vec[vec].base, len);

			/* Update remaining length and data offset */
			to_copy -= len;
			offset  += len;
			vec++;
		}

		/* Skip padding bytes */
		offset += to_copy;
	}

	/* Store digest output offset */
	output = offset;

	/* Start crypto operation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Avoid copy in case of error */
	if (invoke->ret >= 0) {
		/* Copy en/decrypted buffer */
		if (invoke->dest_len != 0) {
			int inject = 0;

			/* Copy injected data from source */
			buf = operation->enc_dst;
			if ((operation->enc_dst != operation->src) &&
				(operation->enc_inject != 0)) {
				inject = operation->enc_inject;

				/* Copy injected data */
				memcpy(buf->vec[0].base, operation->src->vec[0].base, inject);
			} else {
				inject = operation->enc_skip;
			}

			/* Copy all data */
			vec     = 0;
			offset  = operation->iv_len + operation->enc_skip;
			to_copy = invoke->dest_len;
			while ((to_copy > 0) &&
				   (vec < buf->veccnt)) {
				/* Limit data copy to vec length */
				len = to_copy > buf->vec[vec].len - inject ?
					  buf->vec[vec].len - inject : to_copy;

				/* Copy data */
				memcpy(buf->vec[vec].base + inject, &invoke->data[offset], len);

				/* Update remaining length and data offset */
				to_copy -= len;
				offset  += len;
				vec++;

				/* Inject data in first vec only */
				inject = 0;
			}

			/* Check that all data are copied */
			if (to_copy > 0) {
				return(-ENOMEM);
			}
		}

		/* Copy digest (only on last buffer) */
		if ((invoke->digest_len != 0) &&
		    (!(operation->flags & FPU_CRYPTO_F_PARTIAL))) {
			memcpy(operation->auth_dst, &invoke->data[output], invoke->digest_len);
		}
	}

	return invoke->ret;
}

/**
 * Start an asymmetric crypto operation
 */
int32_t fpu_crypto_kinvoke(fpu_crypto_kop_t * operation)
{
	struct fpu_rpc_cmd_crypto_kinvoke *kinvoke;
	int offset = 0;
	int len;
	int output;
	int p;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	kinvoke = &fpu_crypto_app_shmem->crypto_kinvoke;

	/* Setup crypto operation */
	fpu_crypto_app_shmem->type     = CRYPTO_KINVOKE;
	kinvoke->op      = operation->op;
	kinvoke->iparams = operation->iparams;
	kinvoke->oparams = operation->oparams;
	kinvoke->flags   = operation->flags;

	/* Copy input parameters */
	for (p=0 ; p<operation->iparams ; p++) {
		kinvoke->nbits[p] = operation->param[p].nbits;
		len = (operation->param[p].nbits + 7) / 8;
		if ((offset + len) > FPU_CRYPTO_MAX_BUF_SIZE) {
			return(-ENOMEM);
		}
		memcpy(&kinvoke->data[offset], operation->param[p].ptr, len);
		offset += len;
	}

	/* Store output offset */
	output = offset;

	/* Copy length of output parameters */
	for (; p<operation->iparams+operation->oparams ; p++) {
		kinvoke->nbits[p] = operation->param[p].nbits;
		len = (operation->param[p].nbits + 7) / 8;
		if ((offset + len) > FPU_CRYPTO_MAX_BUF_SIZE) {
			return(-ENOMEM);
		}
		offset += len;
	}

	/* Start crypto operation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Avoid copy in case of error */
	if (kinvoke->ret >= 0) {
		/* Copy back output result */
		offset = output;
		for (p=operation->iparams; p<operation->iparams+operation->oparams ; p++) {
			len = (operation->param[p].nbits + 7) / 8;
			memcpy(operation->param[p].ptr, &kinvoke->data[offset], len);
			offset += len;
		}
	}

	return kinvoke->ret;
}


/**
 * Initialize a DRBG session
 */
uint64_t fpu_drbg_session_new()
{
	struct fpu_rpc_cmd_drbg_session_new *session_new;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	session_new = &fpu_crypto_app_shmem->drbg_session_new;

	/* Setup new session data */
	fpu_crypto_app_shmem->type = DRBG_SESSION_NEW;

	/* Start session creation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Return result */
	return session_new->ret;
}


/**
 * Close a DRBG session
 */
int32_t fpu_drbg_session_free(uint64_t session)
{
	struct fpu_rpc_cmd_drbg_session_free *session_free;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	session_free = &fpu_crypto_app_shmem->drbg_session_free;

	/* Setup message data */
	fpu_crypto_app_shmem->type = DRBG_SESSION_FREE;
	session_free->session = session;

	/* Start session closure */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Return result */
	return session_free->ret;
}


/**
 * Seed a DRBG session
 */
int32_t fpu_drbg_seed(fpu_rbg_op_t * operation)
{
	struct fpu_rpc_cmd_drbg_seed *drbg_seed;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	drbg_seed = &fpu_crypto_app_shmem->drbg_seed;

	/* Setup crypto operation */
	fpu_crypto_app_shmem->type       = DRBG_SEED;
	drbg_seed->session = operation->session;
	drbg_seed->len     = operation->len;

	/* Copy input parameters */
	memcpy(&drbg_seed->data, operation->buf, operation->len);

	/* Start crypto operation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Return result */
	return drbg_seed->ret;
}


/**
 * Generate random bytes using DRBG session
 */
int32_t fpu_drbg_generate(fpu_rbg_op_t * operation)
{
	struct fpu_rpc_cmd_drbg_generate *drbg_generate;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	drbg_generate = &fpu_crypto_app_shmem->drbg_generate;

	/* Setup crypto operation */
	fpu_crypto_app_shmem->type           = DRBG_GENERATE;
	drbg_generate->session = operation->session;
	drbg_generate->len     = operation->len;

	/* Start crypto operation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Avoid copy in case of error */
	if (drbg_generate->ret >= 0) {
		/* Copy output values */
		memcpy(operation->buf, &drbg_generate->data, operation->len);
	}

	/* Return result */
	return drbg_generate->ret;
}


/**
 * Generate non deterministic random bytes
 */
int32_t fpu_nrbg_generate(fpu_rbg_op_t * operation)
{
	struct fpu_rpc_cmd_nrbg_generate *nrbg_generate;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	nrbg_generate = &fpu_crypto_app_shmem->nrbg_generate;

	/* Setup crypto operation */
	fpu_crypto_app_shmem->type = NRBG_GENERATE;
	nrbg_generate->len         = operation->len;

	/* Start crypto operation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Avoid copy in case of error */
	if (nrbg_generate->ret >= 0) {
		/* Copy output values */
		memcpy(operation->buf, &nrbg_generate->data, operation->len);
	}

	/* Return result */
	return nrbg_generate->ret;
}


/**
 * Recover statistics
 */
int32_t fpu_crypto_statistics(char const * device, uint32_t core_id, 
                              fpu_crypto_statistics_t * arg)
{
	struct fpu_rpc_cmd_crypto_statistics * statistics;

	/* Check thread status */
	fpu_crypto_check_thread();

	/* Get shared mem */
	statistics = &fpu_crypto_app_shmem->crypto_statistics;

	/* Setup crypto operation */
	fpu_crypto_app_shmem->type = CRYPTO_STATISTICS;
	statistics->core_id = core_id;
	memset(statistics->device, 0, FPU_CRYPTO_MAX_NAME_SIZE);
	if (device != NULL) {
		strncpy(statistics->device, device, FPU_CRYPTO_MAX_NAME_SIZE-1);
	}

	/* Start crypto operation */
	wmb();
	fpu_crypto_app_shmem->status = FPU_RPC_STATUS_WAITING;
	while (fpu_crypto_app_shmem->status >= FPU_RPC_STATUS_WAITING);
	rmb();

	/* Copy back statistics */
	arg->nb_session     = statistics->nb_session;
	arg->nb_crypto      = statistics->nb_crypto;
	arg->nb_kop         = statistics->nb_kop;
	arg->nb_rand        = statistics->nb_rand;
	arg->out_of_space   = statistics->out_of_space;
	arg->out_of_buffer  = statistics->out_of_buffer;
	arg->out_of_session = statistics->out_of_session;
	arg->internal_error = statistics->internal_error;
	arg->nb_poll        = statistics->nb_poll;
	arg->dummy_poll     = statistics->dummy_poll;
	arg->timeout_flush  = statistics->timeout_flush;
	arg->bulk_flush     = statistics->bulk_flush;

	return statistics->ret;
}
