/*
 * Copyright(c) 2013 6WIND
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"
#include "fp-var.h"
#include "fp-addr-list.h"

/*
 * Initialize the fp_pool_addr4 & fp_pool_addr6
 */
void fp_pool_addr_init(void)
{
	struct fp_pool_addr4 *pool4 = &(fp_shared->fp_empty_pool_addr4);
#ifdef CONFIG_MCORE_IPV6
	struct fp_pool_addr6 *pool6 = &(fp_shared->fp_empty_pool_addr6);
#endif
	uint32_t i;

	/* init the list of addr for the pool4 */
	pool4->head_index = 0;
	for (i=0; i < FP_MAX_NB_ADDR4-1; i++)
		pool4->table_addr4[i].next = i+1;
	pool4->table_addr4[FP_MAX_NB_ADDR4-1].next = FP_ADDR_INDEX_NONE;

#ifdef CONFIG_MCORE_IPV6
	/* init the list of addr for the pool6 */
	pool6->head_index = 0;
	for (i=0; i < FP_MAX_NB_ADDR6-1; i++)
		pool6->table_addr6[i].next = i+1;
	pool6->table_addr6[FP_MAX_NB_ADDR6-1].next = FP_ADDR_INDEX_NONE;
#endif
}

/*
 * Get a new fp_addr_object from the pool
 * Set this one with the following parameters
 *
 * @return the index of the new fp_addr_object
 *          if pool is empty, return FP_ADDR_INDEX_NONE
 */
uint32_t fp_pool_get_addr4(void)
{
	uint32_t index;
	struct fp_pool_addr4 *pool4 = &(fp_shared->fp_empty_pool_addr4);

	/* pool is empty, exit */
	if (unlikely(pool4->head_index >= FP_MAX_NB_ADDR4))
		return FP_ADDR_INDEX_NONE;

	/* get the first object  from the empty_pool4 */
	index = pool4->head_index;
	pool4->head_index = pool4->table_addr4[index].next;

	return index;
}

/*
 * Put a fp_addr_object in the pool
 * @param index of the fp_addr_object to put in the pool
 */
void fp_pool_put_addr4(uint32_t index)
{
	struct fp_pool_addr4 *pool4 = &(fp_shared->fp_empty_pool_addr4);
	uint32_t save_index = 0;

	if (unlikely(index >= FP_MAX_NB_ADDR4))
		return;

	save_index = pool4->head_index;
	pool4->head_index = index;
	pool4->table_addr4[index].addr = 0;
	pool4->table_addr4[index].next = save_index;
}

/*
 * Put back a list of fp_addr_objectl
 * @param index  index of the first fp_addr_object to put in the pool
 *        All the next fp_addr_object are also put in the pool
 */
void fp_pool_free_list_addr4(uint32_t index, uint32_t ifuid, uint16_t vrfid)
{
	struct fp_pool_addr4 *pool4 = &(fp_shared->fp_empty_pool_addr4);
	uint32_t save_index = 0;

	if (unlikely(index >= FP_MAX_NB_ADDR4))
		return;

	save_index = pool4->head_index;

	pool4->head_index = index;
	fp_delete_route4_nhmark(vrfid, pool4->table_addr4[index].addr, 32, 0,
				ifuid, RT_TYPE_ADDRESS, NULL);
	pool4->table_addr4[index].addr = 0;
	while (pool4->table_addr4[index].next < FP_MAX_NB_ADDR4) {
		fp_delete_route4_nhmark(vrfid, pool4->table_addr4[index].addr, 32, 0,
					ifuid, RT_TYPE_ADDRESS, NULL);
		pool4->table_addr4[index].addr = 0;
		index = pool4->table_addr4[index].next;
	}
	pool4->table_addr4[index].next = save_index;
}

/*
 * Remove an addr from an address list and put back in the pool
 * @param addr remove the fp_addr_object having this 'addr'
 * @param pindex pointer on the index of the first object in the address list
 */
int fp_pool_remove_addr4(uint32_t addr, uint32_t *pindex) {
	struct fp_pool_addr4 *pool4 = &(fp_shared->fp_empty_pool_addr4);
	uint32_t index_remove;

	while (*pindex < FP_MAX_NB_ADDR4) {

		if (pool4->table_addr4[*pindex].addr == addr) {
			/* remove the object from the current list */
			index_remove = *pindex;
			*pindex = pool4->table_addr4[index_remove].next;

			/* put back the object in the pool */
			fp_pool_put_addr4(index_remove);
			/* success */
			return 0;
		}
		pindex = &(pool4->table_addr4[*pindex].next);
	}
	/* failed to remove it */
	return -1;
}

/* IPv6 functions */
#ifdef CONFIG_MCORE_IPV6

/*
 * Get a new fp_addr6_object from the pool
 * Set this one with the following parameters
 *
 * @return the index of the new fp_addr_object
 *          if pool is empty, return FP_ADDR_INDEX_NONE
 */
uint32_t fp_pool_get_addr6(void)
{
	uint32_t index;
	struct fp_pool_addr6 *pool6 = &(fp_shared->fp_empty_pool_addr6);

	/* pool is empty, exit */
	if (unlikely(pool6->head_index >= FP_MAX_NB_ADDR6))
		return FP_ADDR_INDEX_NONE;

	/* get the first object  from the empty_pool6 */
	index = pool6->head_index;
	pool6->head_index = pool6->table_addr6[index].next;

	return index;
}

/*
 * Put a fp_addr6_object in the pool
 * @param index of the fp_addr6_object to put in the pool
 */
void fp_pool_put_addr6(uint32_t index)
{
	fp_in6_addr_t zeroin6_addr= { .fp_s6_addr32 = { 0, 0, 0, 0} };
	struct fp_pool_addr6 *pool6 = &(fp_shared->fp_empty_pool_addr6);
	uint32_t save_index = 0;

	if (unlikely(index >= FP_MAX_NB_ADDR6))
		return;

	save_index = pool6->head_index;
	pool6->head_index = index;
	pool6->table_addr6[index].addr6 = zeroin6_addr;
	pool6->table_addr6[index].next = save_index;
}

/*
 * Put back a list of fp_addr6_object
 * @param index index of the first fp_addr6_object to put in the pool
 *        All the next fp_addr6_object are also put in the pool
 */
void fp_pool_free_list_addr6(uint32_t index)
{
	struct fp_pool_addr6 *pool6 = &(fp_shared->fp_empty_pool_addr6);
	fp_in6_addr_t zeroin6_addr= { .fp_s6_addr32 = { 0, 0, 0, 0} };
	uint32_t save_index = 0;

	if (unlikely(index >= FP_MAX_NB_ADDR6))
		return;

	save_index = pool6->head_index;

	pool6->head_index = index;
	pool6->table_addr6[index].addr6 = zeroin6_addr;
	while (pool6->table_addr6[index].next < FP_MAX_NB_ADDR6) {
		pool6->table_addr6[index].addr6 = zeroin6_addr;
		index = pool6->table_addr6[index].next;
	}
	pool6->table_addr6[index].next = save_index;
}

/*
 * Remove an addr6 from an address list and put back in the pool
 * @param addr remove the fp_addr6_object having this 'addr6'
 * @param pindex pointer on the index of the first object in the list of addresses
 */
int fp_pool_remove_addr6(fp_in6_addr_t addr6, uint32_t *pindex) {
	struct fp_pool_addr6 *pool6 = &(fp_shared->fp_empty_pool_addr6);
	uint32_t index_remove;

	while (*pindex < FP_MAX_NB_ADDR6) {
		if (is_in6_addr_equal(pool6->table_addr6[*pindex].addr6,
				      addr6)) {
			/* remove the object from the current list */
			index_remove = *pindex;
			*pindex = pool6->table_addr6[index_remove].next;

			/* put back the object in the pool */
			fp_pool_put_addr6(index_remove);
			/* success */
			return 0;
		}
		pindex = &(pool6->table_addr6[*pindex].next);
	}
	/* failed to remove it */
	return -1;
}

#endif /* CONFIG_MCORE_IPV6 */
