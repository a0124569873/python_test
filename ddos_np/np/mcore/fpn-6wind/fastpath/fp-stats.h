/*
 * Copyright(c) 2006 6WIND
 */
#ifndef __FP_STATS_H__
#define __FP_STATS_H__

#ifndef CONFIG_MCORE_NO_STATS_COLLECTING
/*
 * Statistics access: should never be accessed directly
 * (can be per CPU, depending on options)
 */
#define FP_STATS_INC(st, field) do {                \
                 if (sizeof (st[0].field) == 8)     \
                     FPN_STATS_INC(&st[0].field);   \
                 else                               \
                     FPN_STATS_INC32(&st[0].field); \
	} while (0)

#define FP_STATS_DEC(st, field) do {                \
                 if (sizeof (st[0].field) == 8)     \
                     FPN_STATS_DEC(&st[0].field);   \
                 else                               \
                     FPN_STATS_DEC32(&st[0].field); \
	} while (0)

#define FP_STATS_ADD(st, field, val) do {                \
                 if (sizeof (st[0].field) == 8)          \
                     FPN_STATS_ADD(&st[0].field, val);   \
                 else                                    \
                     FPN_STATS_ADD32(&st[0].field, val); \
	} while (0)

#define FP_STATS_SUB(st, field, val) do {                \
                 if (sizeof (st[0].field) == 8)          \
                     FPN_STATS_SUB(&st[0].field, val);   \
                 else                                    \
                     FPN_STATS_SUB32(&st[0].field, val); \
	} while (0)

#define FP_STATS_PERCORE_INC(st, field) \
                 (st[fpn_get_core_num()].field)++

#define FP_STATS_PERCORE_DEC(st, field) \
                 (st[fpn_get_core_num()].field)--


#define FP_STATS_PERCORE_ADD(st, field, val) \
                 (st[fpn_get_core_num()].field) += val

#define FP_STATS_PERCORE_SUB(st, field, val) \
                 (st[fpn_get_core_num()].field) -= val

#else /* CONFIG_MCORE_NO_STATS_COLLECTING */

#define FP_STATS_INC(st, field) do {} while(0)
#define FP_STATS_DEC(st, field) do {} while(0)
#define FP_STATS_ADD(st, field, val) do {} while(0)
#define FP_STATS_SUB(st, field, val) do {} while(0)
#define FP_STATS_PERCORE_INC(st, field) do {} while(0)
#define FP_STATS_PERCORE_DEC(st, field) do {} while(0)
#define FP_STATS_PERCORE_ADD(st, field, val) do {} while(0)
#define FP_STATS_PERCORE_SUB(st, field, val) do {} while(0)

#endif /* CONFIG_MCORE_NO_STATS_COLLECTING */

#endif /* __FP_STATS_H__ */
