/*
 * Copyright(c) 2014 6WIND
 */
#include "fpn.h"
#include "fp-module-internal.h"
#include "fp-includes.h"
#include "fp-log.h"

#define TRACE_MAIN_PROC(level, fmt, args...) do {		\
	FP_LOG(level, MAIN_PROC, fmt "\n", ## args);		\
} while(0)

/* No FPN_DEFINE_SHARED here: there must be one list per Octeon core
 * because cores execute the module constructor functions in parallel.
 * Then only the master core calls fp_modules_init().
*/
struct fp_mod_list fp_modules = FPN_STAILQ_HEAD_INITIALIZER(fp_modules);
struct fp_dependency_list fp_dependencies = FPN_STAILQ_HEAD_INITIALIZER(fp_dependencies);

static struct fp_mod *fp_mod_find(const char *name)
{
	struct fp_mod *mod = NULL;

	FPN_STAILQ_FOREACH(mod, &fp_modules, next) {
		if (!strcmp(mod->name, name))
			break;
	}

	return mod;
}

int fp_mod_register(struct fp_mod *mod)
{
	const char **dependency_list = mod->dependency_list;
	int i;

	if (!mod || !mod->name || !strcmp(mod->name, "") ||
	    (strlen(mod->name) >= FP_MODNAME_MAXLEN)) {
		fpn_printf("cannot register module: invalid name\n");
		return -1;
	}

	if (fp_mod_find(mod->name)) {
		fpn_printf("cannot register %s module: a module with the same "
		           "name is already registered\n", mod->name);
		return -1;
	}

	if ((dependency_list != NULL) && (dependency_list[0] != NULL)) {
		/* Set module with dependencies at the end 
		 * During the init we will check that requested modules are
		 * installed before install this module
		 */
		for (i = 0; dependency_list[i]; i++) {
			int found = 0;
			struct fp_dep *dep;

			FPN_STAILQ_FOREACH(dep, &fp_dependencies, next) {
				if (strcmp(dep->name, dependency_list[i]) == 0) {
					found = 1;
					break;
				}
			}

			if (found == 0) {
				/* Add dependency in the list */
				dep = (struct fp_dep *)calloc(sizeof(struct fp_dep), 1);
				if (dep == NULL) {
					fpn_printf("cannot register %s module: memory allocation failure\n",
					           mod->name);
					return -1;
				}
				dep->name = dependency_list[i];
				FPN_STAILQ_INSERT_HEAD(&fp_dependencies, dep, next);
			}
		}
		FPN_STAILQ_INSERT_TAIL(&fp_modules, mod, next);
	} else
		FPN_STAILQ_INSERT_HEAD(&fp_modules, mod, next);

	return 0;
}

void fp_modules_init(void)
{
	struct fp_mod *mod;
	struct fp_dep *dep;
	int module, insert;
	int installation_do_in_loop, installation_possible, i;

	FPN_STAILQ_FOREACH(mod, &fp_modules, next)
		/* Reset uid */
		mod->uid = 0;

	FPN_STAILQ_FOREACH(dep, &fp_dependencies, next)
		/* Reset installation flag */
		dep->installed = 0;

restart:
	installation_do_in_loop = 0;
	FPN_STAILQ_FOREACH(mod, &fp_modules, next) {
		const char **dependency_list = mod->dependency_list;
		insert = 0;

		/* Check if the module has been installed in a previous loop */
		if (mod->uid)
			continue;

		if (dependency_list == NULL)
			goto no_dep;

		/* For module with dependencies check that all
		 * needed depencies are installed. If not yet skip it,
		 * installation will be do in future loop */
		installation_possible = 1;

		for (i = 0; dependency_list[i]; i++)
			FPN_STAILQ_FOREACH(dep, &fp_dependencies, next)
				if ((dep->installed == 0) &&
				    (strcmp(dep->name, dependency_list[i]) == 0)) {
					TRACE_MAIN_PROC(FP_LOG_DEBUG,
							"INIT fast path module: %s postponed (miss dependency %s)\n",
							mod->name,dependency_list[i]);
					installation_possible = 0;
					goto next;
				}
next:
		if (installation_possible == 0)
			continue;

no_dep:
		TRACE_MAIN_PROC(FP_LOG_INFO, "INIT fast path module: %s\n",
		                mod->name);

		/* Try to find a module with that name in shared memory */
		/* index 0 is never used */
		for (module=1 ; module<FP_MAX_MODULES ; module++) {
			/* If a module with that name is found, reuse the same uid */
			if (!strcmp(mod->name, fp_shared->fp_modules[module].name)) {
				mod->uid = module;
				break;
			}

			/* In case we will need to insert this module, find the first */
			/* empty location in fp_shared->fp_modules table */
			if ((fp_shared->fp_modules[module].name[0] == 0) &&
			    (insert == 0))
				insert = module;
		}

		/* Associate a new uid if not found */
		if (mod->uid == 0) {
			if (insert == 0) {
				TRACE_MAIN_PROC(FP_LOG_ERR, "INIT can not initialize module %s, no space in shared mem\n",
								mod->name);
				continue;
			} else {
				/* Setup shared mem */
				size_t size = sizeof(fp_shared->fp_modules[insert].name);
				strncpy(fp_shared->fp_modules[insert].name, mod->name, size);
				fp_shared->fp_modules[insert].name[size-1] = 0;

				/* Setup uid */
				mod->uid = insert;
			}
		}

		/* Store dev_ops in shared mem */
		memcpy(&fp_shared->fp_modules[mod->uid].if_ops, &mod->if_ops, 
		       sizeof(mod->if_ops));

		/* Call init function */
		if (mod->init)
			mod->init();

		installation_do_in_loop = 1;
		FPN_STAILQ_FOREACH(dep, &fp_dependencies, next) {
			if ((dep->installed == 0) &&
			    (strcmp(dep->name, mod->name) == 0)) {
				dep->installed = 1;
				break;
			}
		}
	}

	if (installation_do_in_loop)
		goto restart;

	FPN_STAILQ_FOREACH(dep, &fp_dependencies, next)
		if (dep->installed == 0)
			FPN_STAILQ_FOREACH(mod, &fp_modules, next) {
				const char **dependency_list = mod->dependency_list;

				if (dependency_list == NULL)
					continue;

				for (i = 0; dependency_list[i]; i++)
					if (strcmp(dep->name, dependency_list[i]) == 0)
						TRACE_MAIN_PROC(FP_LOG_ERR,
							"Module %s not installed: dependency %s is missing\n",
							mod->name, dep->name);
			}
}

int fp_log_register(uint64_t flag, const char *name)
{
	int i;

	if (!name || !name[0]) {
		fpn_printf("fp_log_register error for %"PRIu64": empty name\n",
		           flag);
		return -1;
	}

	for (i = 0; i < FP_MAX_LOGTYPES; i++)
		if (flag & (UINT64_C(1) << i))
			break;

	if (i >= FP_MAX_LOGTYPES) {
		fpn_printf("fp_log_register error for %s (%"PRIu64"): "
		           "flag offset must be below %u\n",
		           name, flag, FP_MAX_LOGTYPES);
		return -1;
	}

	if (fp_shared->logname[i][0]) {
		fpn_printf("fp_log_register error for %s (%"PRIu64"): "
		           "flag already used by %s\n",
		           name, flag, fp_shared->logname[i]);
		return -1;
	}
	memcpy(fp_shared->logname[i], name, FP_LOGNAME_MAXLEN - 1);
	return 0;
}
