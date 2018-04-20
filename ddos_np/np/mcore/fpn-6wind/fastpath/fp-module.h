/*
 * Copyright(c) 2014 6WIND
 */
#ifndef __FP_MODULE_H__
#define __FP_MODULE_H__

#include "fp.h"
#include "fpn-queue.h"
#include "fp-var.h"

/*
 * Fast Path Module API.
 */

/**
   Callback function for module initialization.
 */
typedef void (*fp_mod_init_t)(void);

/**
   Structure to hold info about the module.
 */
struct fp_mod {
	FPN_STAILQ_ENTRY(fp_mod) next;
	const char *name;    /* must be non empty */
	const char **dependency_list; /* list of modules that must be initialized
				       * before this one. May be NULL. If present
				       * the list must be NULL terminated */
	fp_mod_init_t init;  /* may be NULL */
	void *if_ops[FP_IFNET_MAX_OPS]; /* dev ops */
	uint16_t uid;         /* unique module id (>0) */
};

/**
   Structure to hold list of dependency
 */
struct fp_dep {
	FPN_STAILQ_ENTRY(fp_dep) next;
	const char *name;
	uint32_t installed;
};


/**
   Register a Fast Path module.

   You should not use this function directly.
   Use the FP_MOD_REGISTER macro instead.

   @param mod the module object
   @return 0 on success, -1 on failure.
 */
int fp_mod_register(struct fp_mod *mod);

/**
   Helper macro: define a constructor function to register the fp module.
 */
#define FP_MOD_REGISTER(module) \
static void __attribute__((constructor)) fp_mod_register_ ## module(void) { \
       fp_mod_register(&module); \
}

/* assign string name to logtype flag */
int fp_log_register(uint64_t flag, const char *name);

/* helper macro */
#define FP_LOG_REGISTER(f) fp_log_register(FP_LOGTYPE_##f, #f)

#endif
