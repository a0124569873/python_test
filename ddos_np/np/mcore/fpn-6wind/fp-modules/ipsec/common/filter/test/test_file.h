/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _TEST_FILE_H_
#define _TEST_FILE_H_

#define MAXFILTERS 		100000

#include "filter.h"

struct FILTSET
{
	uint32_t numFilters;
	struct FILTER filtArr[MAXFILTERS];
};

typedef struct FILTSET* FiltSet;

int LoadFilters_from_file(char *filename, struct FILTSET *filtset, int max);

#endif
