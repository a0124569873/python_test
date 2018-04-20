/*
 * Copyright(c) 2009 6WIND
 */
#ifndef __FPN_TRACK_H__
#define __FPN_TRACK_H__

#ifdef CONFIG_MCORE_FPN_TRACK

#define FPN_TRACK_MAX_ORDER  5
#define FPN_TRACK_MAX_SIZE  (1<<FPN_TRACK_MAX_ORDER)
#define FPN_TRACK_MASK_INDEX (FPN_TRACK_MAX_SIZE-1)

#define MAX_FUNC_NAME_LEN    32
#define ADDR_LEN             11 /* 32 bit address should be enough. sizeof(0xffffffff) is 11 */

struct fpn_tk_e {
	char		pc_addr[ADDR_LEN];		// PC pointer
	char		ra_addr[ADDR_LEN];		// return address pointer.
	char		func_name[MAX_FUNC_NAME_LEN];
	uint32_t	cycles;
	uint32_t	line;
};

struct fpn_tk_s {
	struct fpn_tk_e entry[FPN_TRACK_MAX_SIZE];
	uint32_t index;
} __fpn_cache_aligned;


typedef struct fpn_track_shared_mem {
	struct fpn_tk_s fpn_tk_table[FPN_MAX_CORES];
} fpn_track_shared_mem_t;

#ifdef __FastPath__
extern int fpn_track_init(void);
extern void fpn_track(void *ra_addr, const char *func_name, size_t line);

#define FPN_RECORD_TRACK() do {                                                \
        fpn_track(__builtin_return_address(0), __func__, __LINE__); \
    } while (0)
#endif

#else

#define FPN_RECORD_TRACK() do {} while (0)

#endif

#endif
