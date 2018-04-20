/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __FP_ADDR_LIST_H__
#define __FP_ADDR_LIST_H__

#define FP_ADDR_INDEX_NONE 0xffffffff

#ifdef CONFIG_MCORE_MAX_NB_ADDR4
#define FP_MAX_NB_ADDR4 CONFIG_MCORE_MAX_NB_ADDR4
#else
#define FP_MAX_NB_ADDR4 4096
#endif

typedef struct fp_addr_object {
	uint32_t next;
	uint32_t addr;
} fp_addr_object_t;

struct fp_pool_addr4 {
	uint32_t head_index;
	fp_addr_object_t table_addr4[FP_MAX_NB_ADDR4];
};

#ifdef CONFIG_MCORE_IPV6

#ifdef CONFIG_MCORE_MAX_NB_ADDR6
#define FP_MAX_NB_ADDR6 CONFIG_MCORE_MAX_NB_ADDR6
#else
#define FP_MAX_NB_ADDR4 4096
#endif

typedef struct fp_addr6_object {
	uint32_t next;
	fp_in6_addr_t addr6;
} fp_addr6_object_t;


struct fp_pool_addr6 {
	uint32_t head_index;
	fp_addr6_object_t table_addr6[FP_MAX_NB_ADDR6];
};
#endif

#define fp_pool_addr4_object(index) \
	fp_shared->fp_empty_pool_addr4.table_addr4[index]

void fp_pool_addr_init(void);

uint32_t fp_pool_get_addr4(void);
uint32_t fp_pool_addr4(uint32_t index);
void fp_pool_put_addr4(uint32_t index);
void fp_pool_free_list_addr4(uint32_t index, uint32_t ifuid, uint16_t vrfid);
int fp_pool_remove_addr4(uint32_t addr, uint32_t *pindex);

#ifdef CONFIG_MCORE_IPV6

#define fp_pool_addr6_object(index) \
	fp_shared->fp_empty_pool_addr6.table_addr6[index]

uint32_t fp_pool_get_addr6(void);
fp_in6_addr_t fp_pool_addr6(uint32_t index);
void fp_pool_put_addr6(uint32_t index);
void fp_pool_free_list_addr6(uint32_t index);
int fp_pool_remove_addr6(fp_in6_addr_t addr6, uint32_t *pindex);
#endif

#endif
