/*
 * Copyright(c) 2014 6WIND
 */
#ifndef __FP_MODULE_INTERNAL_H__
#define __FP_MODULE_INTERNAL_H__

#include "fp-module.h"

FPN_STAILQ_HEAD(fp_mod_list, fp_mod);
FPN_STAILQ_HEAD(fp_dependency_list, fp_dep);

/**
   Call init function for all modules.
 */
void fp_modules_init(void);

#endif
