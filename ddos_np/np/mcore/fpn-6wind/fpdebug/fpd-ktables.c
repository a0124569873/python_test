/**
 * Copyright (c) <2011>, 6WIND
 * All rights reserved.
 */

/**
 * Kernel table interface
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

#include <ktables_config.h>

#include "fp.h"
#include "fp-ktables.h"

#include "fpdebug.h"
#include "fpdebug-priv.h"

#define TOLOWER(x) ((x) | 0x20)
#define ISXDIGIT(x)    (('0' <= (x) && (x) <= '9') || \
                ('a' <= (x) && (x) <= 'f') || \
                ('A' <= (x) && (x) <= 'F'))
#define ISDIGIT(c)    ('0' <= (c) && (c) <= '9')

void
print_one_table(uint8_t *table)
{
        int i;
        for(i = 0; i < 8; i++) {
                printf("%02x", table[i]);
        }
        printf("\n");
}

int
strtouint8(char *cp, int len, uint8_t *value)
{
        int i = 0;
        uint8_t tmp;

        if (cp[0] == '0' && TOLOWER(cp[1]) == 'x') {
                cp += 2;
                len -= 2;
        }

        *value = 0;
        while ( i < len) {
                if(!ISXDIGIT(cp[i])) {
                        return -1;
                }
                else {
                        tmp = ISDIGIT(cp[i]) ? (uint8_t)(cp[i] - '0') :
                                (uint8_t)(TOLOWER(cp[i]) -'a' + 10);
                        *value += (i%2) ? tmp : tmp << 4;
                        i++;
                }
        }
        return 0;
}

int
strtoktable(char *cp, uint8_t *value)
{
        int i = 0;

        if (cp[0] == '0' && TOLOWER(cp[1]) == 'x') {
                cp += 2;
        }

        memset(value, 0, 8);
        while ( i < 8) {
                if (strtouint8(cp + 2*i, 2, &value[i]) < 0) {
                        return -1;
                }
                else {
                        i++;
                }
        }

        return 0;
}

int
fpd_ktables_set(char *tok)
{
	uint16_t	table;
	uint8_t 	value[8];
	char		*str;

	if (gettokens(tok) != 2) {
		fprintf(stderr,
			"wrong arguments: ktables-set <table> <value>\n");
		return 0;
	}

	errno = 0;
	table = strtol(chargv[0], &str, 10);
	if (errno || *str) {
		fprintf(stderr,
			"wrong arguments: <table> is the index of the table\n");
		return 0;
	}
	if (table >= CONFIG_KTABLES_MAX_TABLES) {
		fprintf(stderr, "<table> is out of scope (0-%d)\n",
			CONFIG_KTABLES_MAX_TABLES - 1);
		return 0;
	}
	if (strtoktable(chargv[1], value) < 0) {
		fprintf(stderr,
			"wrong arguments: <value> is a 64 bit hexadecimal value\n");
		return 0;
	}

	fp_ktables_set(table, value);

	return 0;
}

int
fpd_ktables_dump(char *tok)
{
	int i;

	for (i = 0; i < CONFIG_KTABLES_MAX_TABLES; i++) {
		printf("ktable[%02u]: ", i);
		print_one_table(fp_shared->ktables[i]);

	}

	return 0;
}

