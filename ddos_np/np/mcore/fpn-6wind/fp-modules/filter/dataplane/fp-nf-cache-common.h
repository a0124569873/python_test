/*
 * Copyright (c) 2010 6WIND
 */
#ifndef __FP_NF_CACHE_COMMON_H__
#define __FP_NF_CACHE_COMMON_H__

#define TRACE_NF_CACHE(level, fmt, args...) do {			\
		FP_LOG(level, NF_CACHE, fmt "\n", ## args);		\
} while(0)

/* equivalent of a NULL pointer but for an index */
#define IDX_NONE 0xFFFFFFFF
#define NF_CACHE_INVALID_HASH 0xFFFFFFFF

typedef struct fp_nf_cache_bucket {
	uint32_t head;
	fpn_spinlock_t lock;
} fp_nf_cache_bucket_t;

struct fp_nf_cache_mask {
	const uint32_t *mask;
	int len32;
};
#endif /* __FP_NF_CACHE_COMMON_H__ */
