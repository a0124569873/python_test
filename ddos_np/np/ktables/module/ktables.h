/*
 * Kernel mapping tables module header
 */
#ifndef _KTABLES_H
#define _KTABLES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define KT_TABLE_SIZE	8 /* uint64_t mapped, do not modify */
#define KT_NL_FAMILY_NAME	"KTABLES"
#define KT_NL_GRP_NAME		"mapping"

/* Answer possible values */
#define KT_ACK_OK	1

enum {
	KT_CMD_MAP_SET,
	KT_CMD_MAP_GET,
	KT_CMD_MAP_DUMP,
	KT_CMD_MAX
};

enum {
	KT_ATTR_UNSPEC = 0,
	KT_ATTR_SET_ONE_BYTE,
	KT_ATTR_SET_ONE_TABLE,
	KT_ATTR_GET_ONE_TABLE,
	KT_ATTR_GET_ALL_TABLES,
	__KT_ATTR_MAX,
};
#define KT_ATTR_MAX (__KT_ATTR_MAX - 1)

enum {
	KT_TYPE_UNSPEC = 0,
	KT_TYPE_ONE_BYTE_SET,
	KT_TYPE_ONE_TABLE,
	__KT_TYPE_MAX
};
#define KT_TYPE_MAX (__KT_TYPE_MAX - 1)

struct attr_byte_s {
	uint32_t	table;
	uint8_t		value;
	uint8_t		idx;
};

struct attr_table_s {
	uint32_t	table;
	uint8_t         table_value[KT_TABLE_SIZE];
};

uint32_t kt_get_max_table(void);
int kt_get(uint32_t table, uint8_t idx);
int kt_set_table(uint32_t table, uint8_t idx, uint8_t value);
uint8_t  const *kt_get_table_elmt_ptr(uint32_t table, uint8_t idx);
uint8_t const *kt_get_table_ptr(uint32_t table);

#endif /* _KTABLES_H */

