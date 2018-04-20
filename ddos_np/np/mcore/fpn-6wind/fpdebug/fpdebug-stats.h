/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __FPDEBUG_STATS_H__
#define __FPDEBUG_STATS_H__

typedef struct {
	const char *name;
	int (*dump)(int percore);
	void (*reset)(void);
} CLI_STATS;

typedef struct cli_stats {
	FPN_STAILQ_ENTRY(cli_stats) next;
	const char *module;
	CLI_STATS *s;
} cli_stats_t;

int fpdebug_add_stats(cli_stats_t *stats);
int fpdebug_del_stats(const char *module);

extern int nonzero;
#define __nonzero(x)  (!nonzero || (x))

#define parse_stats_token(tok, percore) do { \
	int tokens = gettokens(tok); \
	percore = 0; \
	while (tokens) { \
		if (!strcmp(chargv[tokens - 1], "percore")) \
			percore = 1; \
		else if (!strcmp(chargv[tokens - 1], "non-zero")) \
			nonzero = 1; \
		else { \
			fpdebug_printf("Unknown argument: \"%s\"\n", chargv[tokens - 1]); \
			return -1; \
		} \
		tokens--; \
	} \
} while(0)

#define reset_non_zero_stats() do { \
	nonzero = 0; \
} while(0)

#define _dump_stats(tok, func) \
({ \
	int percore, ret; \
	parse_stats_token(tok, percore); \
	ret = func(percore); \
	reset_non_zero_stats(); \
	ret; \
})

#define reset_stat(field) \
	memset((void *)fp_shared->field, 0, sizeof(fp_shared->field));

#define print_stats(pref, field, num) do { \
	unsigned int __i, __first = 0; \
	uint64_t __val, __total; \
	for (__i=0, __total=0 ; __i<num ; __i++) { \
		__val = pref[__i].field ; \
		__total += __val; \
		if (__nonzero(__val)) { \
			if (__first == 0) { \
				__first = 1; \
				fpdebug_printf("  %s:", #field); \
				if (percore) \
					fpdebug_printf("\n"); \
			} \
			if (percore) { \
				fpdebug_printf("    %s[%u]:%"PRIu64"\n", #field, __i, __val); \
			} \
		} \
	} \
	if (__nonzero(__total)) { \
		if (percore) \
			fpdebug_printf("    Total:%"PRIu64"\n", __total); \
		else \
			fpdebug_printf("%"PRIu64"\n", __total); \
	}\
} while (0)

#endif
