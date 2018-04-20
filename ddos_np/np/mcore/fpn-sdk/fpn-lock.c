/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#include "fpn.h"

/*
 * Per-core recording of lock operations.
 */
#define SPLOCK_LOCK    0
#define SPLOCK_TRYLOCK 1
#define SPLOCK_UNLOCK  2
#define RWLOCK_RLOCK   3
#define RWLOCK_RUNLOCK 4
#define RWLOCK_WLOCK   5
#define RWLOCK_WUNLOCK 6

struct lock_record {
	void *lock;       /* target lock operated on */
	const char *func; /* name of function that called the lock operation */
	const char *file; /* source file of function */
	int line;         /* line number in source file of lock operation */
	int ops_id;       /* type of lock and type of operation */
};

struct lock_log {
	struct lock_record lock_records[CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS];
	uint32_t last_record; /* last entry used in lock_records */
} __fpn_cache_aligned;

static FPN_DEFINE_SHARED(struct lock_log, core_lock_logs[FPN_MAX_CORES]);

static const char *
basename(const char *filename)
{
	const char *cp;
	const char *bname;

	for (cp = filename, bname = cp; *cp != '\0'; cp++)
		if (*cp == '/')
			bname = cp + 1;
	return bname;
}

void
fpn_debug_lock_display(void *debug_lock_addr)
{
	fpn_debug_lock_t *lock;

	lock = (fpn_debug_lock_t *)debug_lock_addr;
	if (lock->owning_core >= 0) {
		fpn_printf("lock=%p owned by core %d in %s() [%s:%d]\n",
			   lock, lock->owning_core, lock->func,
			   basename(lock->file), lock->line);
		return;
	}
	if (lock->line == 0)
		fpn_printf("lock=%p was never locked\n", lock);
	else
		fpn_printf("lock=%p unlocked in %s() [%s:%d]\n",
			   lock, lock->func, basename(lock->file), lock->line);
}

static const char * lock_ops_names[] = {
	"lock spinlock",
	"trylock spinlock",
	"unlock spinlock",
	"read-lock rwlock",
	"read-unlock rwlock",
	"write-lock rwlock",
	"write-unlock rwlock",
};

void
fpn_debug_lock_log_display(int core_id, int max_records)
{
	struct lock_log *core_log;
	struct lock_record *record;
	uint32_t rcd_idx;
	int nb_records;

	core_log = &core_lock_logs[core_id];
	rcd_idx = core_log->last_record;
	record = &core_log->lock_records[rcd_idx];
	if (record->lock == NULL) { /* core did not perform any lock ops */
		return;
	}

	/*
	 * Determine the number of lock records and the first record in the log.
	 */
	rcd_idx = ((core_log->last_record + 1) %
		   CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS);
	nb_records = CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS;
	while (core_log->lock_records[rcd_idx].lock == NULL) {
		rcd_idx = ((rcd_idx + 1) % CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS);
		nb_records--;
	}

	/*
	 * Arrange to only display up to the required maximum of records.
	 */
	if (nb_records > max_records) {
		rcd_idx = ((rcd_idx + (max_records - nb_records)) %
			   CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS);
		nb_records = max_records;
	}
	fpn_printf("    Last %2d lock operations on core %d\n"
		   "    ---------------------------------\n",
		   nb_records, core_id);
	do {
		record = &core_log->lock_records[rcd_idx];
		fpn_printf("%s=%p in %s() [%s:%d]\n",
			   lock_ops_names[record->ops_id],
			   record->lock, record->func,
			   basename(record->file), record->line);
		rcd_idx = ((rcd_idx + 1) % CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS);
	} while (--nb_records > 0);
}

static void
lock_ops_record(int lock_ops_id, void *lock, const char *func,
		const char *file, int line)
{
	struct lock_log *core_log;
	struct lock_record *record;
	uint32_t rcd_idx;

	core_log = &core_lock_logs[fpn_get_core_num()];
	rcd_idx = (core_log->last_record + 1) %
		CONFIG_MCORE_FPN_LOCK_DEBUG_MAX_RECORDS;
	record = &core_log->lock_records[rcd_idx];
	record->ops_id = lock_ops_id;
	record->lock   = lock;
	record->func   = func;
	record->file   = file;
	record->line   = line;
	core_log->last_record = rcd_idx;
}

static inline void
lock_not_initialized_warn(fpn_debug_lock_t *lock, int lock_ops_id,
			  const char *func, const char *file, int line)
{
	fpn_printf("%s() [%s:%d]: core %d %s=%p that has not [yet] been "
		   "initialized\n",
		   func, basename(file), line, fpn_get_core_num(),
		   lock_ops_names[lock_ops_id], lock);
}

static inline void
lock_again_by_same_core_warn(fpn_debug_lock_t *lock, int lock_ops_id,
			     const char *func, const char *file, int line)
{
	fpn_printf("%s() [%s:%d]: core %d %s=%p that it already acquired "
		   "in %s() [%s:%d]\n",
		   func, basename(file), line, fpn_get_core_num(),
		   lock_ops_names[lock_ops_id], lock, lock->func,
		   basename(lock->file), lock->line);
}

static inline void
unlock_by_core_not_owner_warn(fpn_debug_lock_t *lock, int lock_ops_id,
			      const char *func, const char *file, int line)
{
	fpn_printf("%s() [%s:%d]: core %d %s=%p that is owned by core %d "
		   "in %s() [%s:%d]\n",
		   func, basename(file), line, fpn_get_core_num(),
		   lock_ops_names[lock_ops_id], lock,
		   lock->owning_core, lock->func, basename(lock->file),
		   lock->line);
}

static inline void
fpn_debug_lock_set(fpn_debug_lock_t *lock, int core_id,
		   const char *func, const char *file, int line)
{
	lock->func        = func;
	lock->file        = file;
	lock->line        = line;
	lock->owning_core = core_id;
}

static inline void
fpn_debug_lock_init(fpn_debug_lock_t *lock, const char *func,
		    const char *file, int line)
{
	fpn_debug_lock_set(lock, -1, func, file, line);
}

static inline int
fpn_debug_lock_initialized(fpn_debug_lock_t *lock)
{
	return (lock->line > 0);
}

/*
 * Spinlocks
 */
void
fpn_debug_spinlock_init(fpn_spinlock_t *sp_lock, const char *func,
			const char *file, int line)
{
	if (! fpn_debug_lock_initialized(&sp_lock->debug_state)) {
		fpn_debug_lock_init(&sp_lock->debug_state, func, file, line);
		__fpn_spinlock_init(&sp_lock->the_lock);
		return;
	}
	fpn_printf("%s() [%s:%d]: core %d initializes spinlock=%p that is "
		   "already initialized\n",
		   func, basename(file), line, fpn_get_core_num(), sp_lock);
}

void
fpn_debug_spinlock_lock(fpn_spinlock_t *sp_lock, const char *func,
			const char *file, int line)
{
	int core_id = fpn_get_core_num();

	if (! fpn_debug_lock_initialized(&sp_lock->debug_state)) {
		lock_not_initialized_warn(&sp_lock->debug_state, SPLOCK_LOCK,
					  func, file, line);
		return;
	}
	if (unlikely(sp_lock->debug_state.owning_core == core_id)) {
		lock_again_by_same_core_warn(&sp_lock->debug_state, SPLOCK_LOCK,
					     func, file, line);
		return;
	}
	lock_ops_record(SPLOCK_LOCK, sp_lock, func, file, line);
	__fpn_spinlock_lock(&sp_lock->the_lock);
	if (unlikely(sp_lock->debug_state.owning_core != -1)) {
		fpn_printf("%s() [%s:line %d]: core %d locked spinlock=%p "
			   "owned by core %d in %s() [%s:%d]\n",
			   func, basename(file), line, core_id, sp_lock,
			   sp_lock->debug_state.owning_core,
			   sp_lock->debug_state.func,
			   basename(sp_lock->debug_state.file),
			   sp_lock->debug_state.line);
	}
	fpn_debug_lock_set(&sp_lock->debug_state, core_id, func, file, line);
}

int
fpn_debug_spinlock_trylock(fpn_spinlock_t *sp_lock, const char *func,
			   const char *file, int line)
{
	int core_id = fpn_get_core_num();

	if (! fpn_debug_lock_initialized(&sp_lock->debug_state)) {
		lock_not_initialized_warn(&sp_lock->debug_state, SPLOCK_TRYLOCK,
					  func, file, line);
		return 0;
	}
	if (unlikely(sp_lock->debug_state.owning_core == core_id)) {
		lock_again_by_same_core_warn(&sp_lock->debug_state,
					     SPLOCK_TRYLOCK, func, file, line);
		return 1;
	}
	lock_ops_record(SPLOCK_TRYLOCK, sp_lock, func, file, line);
	if (! __fpn_spinlock_trylock(&sp_lock->the_lock))
		return 0;
	fpn_debug_lock_set(&sp_lock->debug_state, core_id, func, file, line);
	return 1;
}

void
fpn_debug_spinlock_unlock(fpn_spinlock_t *sp_lock, const char *func,
			  const char *file, int line)
{
	int core_id = fpn_get_core_num();

	if (! fpn_debug_lock_initialized(&sp_lock->debug_state)) {
		lock_not_initialized_warn(&sp_lock->debug_state, SPLOCK_UNLOCK,
					  func, file, line);
		return;
	}
	if (likely(sp_lock->debug_state.owning_core == core_id)) {
		lock_ops_record(SPLOCK_UNLOCK, sp_lock, func, file, line);
		fpn_debug_lock_set(&sp_lock->debug_state, -1, func, file, line);
		__fpn_spinlock_unlock(&sp_lock->the_lock);
		return;
	}
	if (sp_lock->debug_state.owning_core != -1)
		unlock_by_core_not_owner_warn(&sp_lock->debug_state,
					      SPLOCK_UNLOCK, func, file, line);
	else
		fpn_printf("%s() [%s:%d]: core %d unlocks free spinlock=%p\n",
			   func, basename(file), line, core_id, sp_lock);
}

/*
 * Read/Write locks
 */
void
fpn_debug_rwlock_init(fpn_rwlock_t *rw_lock, const char *func,
			const char *file, int line)
{
	if (! fpn_debug_lock_initialized(&rw_lock->debug_state)) {
		fpn_debug_lock_init(&rw_lock->debug_state, func, file, line);
		__fpn_rwlock_init(&rw_lock->the_lock);
		return;
	}
	fpn_printf("%s() [%s:%d]: core %d initializes rwlock=%p that is "
		   "already initialized\n",
		   func, basename(file), line, fpn_get_core_num(), rw_lock);
}

void
fpn_debug_rwlock_read_lock(fpn_rwlock_t *rw_lock, const char *func,
			   const char *file, int line)
{
	int core_id = fpn_get_core_num();

	if (! fpn_debug_lock_initialized(&rw_lock->debug_state)) {
		lock_not_initialized_warn(&rw_lock->debug_state, RWLOCK_RLOCK,
					  func, file, line);
		return;
	}

	if (unlikely(rw_lock->debug_state.owning_core == core_id)) {
		lock_again_by_same_core_warn(&rw_lock->debug_state,
					     RWLOCK_RLOCK, func, file, line);
		return;
	}
	lock_ops_record(RWLOCK_RLOCK, rw_lock, func, file, line);
	__fpn_rwlock_read_lock(&rw_lock->the_lock);
	if (unlikely(rw_lock->debug_state.owning_core != -1)) {
		fpn_printf("%s() [%s:%d]: core %d read-locked rwlock=%p "
			   "write-locked by core %d in %s() [%s:%d]\n",
			   func, basename(file), line, core_id, rw_lock,
			   rw_lock->debug_state.owning_core,
			   rw_lock->debug_state.func,
			   basename(rw_lock->debug_state.file),
			   rw_lock->debug_state.line);
	}
}

void
fpn_debug_rwlock_read_unlock(fpn_rwlock_t *rw_lock, const char *func,
			     const char *file, int line)
{
	if (! fpn_debug_lock_initialized(&rw_lock->debug_state)) {
		lock_not_initialized_warn(&rw_lock->debug_state, RWLOCK_RUNLOCK,
					  func, file, line);
		return;
	}

	if (likely(rw_lock->debug_state.owning_core == -1)) {
		lock_ops_record(RWLOCK_RUNLOCK, rw_lock, func, file, line);
		__fpn_rwlock_read_unlock(&rw_lock->the_lock);
		return;
	}
	unlock_by_core_not_owner_warn(&rw_lock->debug_state, RWLOCK_RUNLOCK,
				      func, file, line);
}

void
fpn_debug_rwlock_write_lock(fpn_rwlock_t *rw_lock, const char *func,
			    const char *file, int line)
{
	int core_id = fpn_get_core_num();

	if (! fpn_debug_lock_initialized(&rw_lock->debug_state)) {
		lock_not_initialized_warn(&rw_lock->debug_state, RWLOCK_WLOCK,
					  func, file, line);
		return;
	}
	if (unlikely(rw_lock->debug_state.owning_core == core_id)) {
		lock_again_by_same_core_warn(&rw_lock->debug_state,
					     RWLOCK_WLOCK, func, file, line);
		return;
	}

	lock_ops_record(RWLOCK_WLOCK, rw_lock, func, file, line);
	__fpn_rwlock_write_lock(&rw_lock->the_lock);
	if (unlikely(rw_lock->debug_state.owning_core != -1)) {
		fpn_printf("%s() [%s:%d]: core %d write-locked rwlock=%p that "
			   "is write-locked by core %d in %s() [%s:%d]\n",
			   func, basename(file), line, core_id, rw_lock,
			   rw_lock->debug_state.owning_core,
			   rw_lock->debug_state.func,
			   basename(rw_lock->debug_state.file),
			   rw_lock->debug_state.line);
	}
	fpn_debug_lock_set(&rw_lock->debug_state, core_id, func, file, line);
}

void
fpn_debug_rwlock_write_unlock(fpn_rwlock_t *rw_lock, const char *func,
			      const char *file, int line)
{
	int core_id = fpn_get_core_num();

	if (! fpn_debug_lock_initialized(&rw_lock->debug_state)) {
		lock_not_initialized_warn(&rw_lock->debug_state, RWLOCK_WUNLOCK,
					  func, file, line);
		return;
	}

	if (likely(rw_lock->debug_state.owning_core == core_id)) {
		lock_ops_record(RWLOCK_WUNLOCK, rw_lock, func, file, line);
		fpn_debug_lock_set(&rw_lock->debug_state, -1, func, file, line);
		__fpn_rwlock_write_unlock(&rw_lock->the_lock);
		return;
	}
	if (rw_lock->debug_state.owning_core != -1)
		unlock_by_core_not_owner_warn(&rw_lock->debug_state,
					      RWLOCK_WUNLOCK, func, file, line);
	else
		fpn_printf("%s() [%s:%d]: core %d %s=%p that is not "
			   "write-locked\n",
			   func, basename(file), line, core_id,
			   lock_ops_names[RWLOCK_WUNLOCK], rw_lock);
}
