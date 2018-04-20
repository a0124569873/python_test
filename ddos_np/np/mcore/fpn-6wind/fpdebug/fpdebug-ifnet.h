/*
 * Copyright(c) 2014 6WIND
 */

#ifndef __FPDEBUG_IFNET_H__
#define __FPDEBUG_IFNET_H__

#include "fpn.h"
#include "fp.h"
#include "fp-if.h"

typedef struct fpdebug_ifnet_info {
	FPN_STAILQ_ENTRY(fpdebug_ifnet_info) next;
	int (*func)(fp_ifnet_t *ifp);
} fpdebug_ifnet_info_t;

int fpdebug_add_ifnet_info(fpdebug_ifnet_info_t *ifnet_info);

#endif
