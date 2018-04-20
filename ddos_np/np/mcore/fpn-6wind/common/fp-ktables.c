/**
 * Kernel table interface
 *
 */

/*-
   * Copyright (c) <2011>, 6WIND
   * All rights reserved.
   */

#include <stdio.h>
#include <string.h>

#include <ktables_config.h>

#include "fp.h"

void
fp_ktables_set(uint32_t table, uint8_t *value)
{
	if (likely(table < CONFIG_KTABLES_MAX_TABLES))
		memcpy(fp_shared->ktables[table], value, 8);
}
