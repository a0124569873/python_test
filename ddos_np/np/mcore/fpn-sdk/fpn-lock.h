/*
 * Copyright(c) 2007 6WIND
 */
#ifndef __FPN_LOCK_H__
#define __FPN_LOCK_H__

#ifdef LOCK_API_MANUAL
#error Never define LOCK_API_MANUAL, this is for documentation purpose only
/**
 * @file
 * The locking API of the fast path is composed of:
 * - the spinlock API,
 * - the read/write lock API,
 * - the 32-bit atomic API,
 * - the 64-bit atomic API,
 * - the memory-barrier API.
 *
 * The syntax and the semantics of the functions of the fast path locking API
 * are described below in <doxygen> syntaxical conventions.
 * The purpose of this manual section is to explain the locking support that
 * is expected by the fast path from each architecture-specific SDK.
 *
 * By convention, each __fpn_xxx() function, and each fpn__yyy() function
 * of the fast path locking API is intended to be associated with a SDK
 * locking function that provides the expected service through a simple
 * #define macro, as for instance:
 *    #define __fpn_spinlock_init arch_sdk_spinlock_init
 *
 * Whenever possible, the actual implementation of SDK locking functions
 * should be exported as "static inline" functions to avoid the overhead
 * of function calls.
 *
 * The support for run-time locking debug-oriented features are provided
 * in the fast path through the compile-time CONFIG_MCORE_FPN_LOCK_DEBUG macro.
 * Thus, this feature is neither required nor expected from SDK spinlock
 * functions and from SDK read/write lock functions.
 * In the same way, the support of recursive spin locks is provided by a
 * dedicated fast path API. This service does not need to be supported by
 * SDK spinlocks, and should not be supported to avoid its useless overhead.
 *
 * 1 Fast path spinlock API
 *   ======================
 *
 * 1.1 Definition of spinlock type
 *     ---------------------------
 *
 * The SDK must export an architecture-specific definition of a spinlock that
 * is associated with the fast path definition of a spinlock as follows:
 *   typedef <arch-specific-spinlock-type> __fpn_spinlock_t;
 *
 * 1.2 Static initialization of a spinlock variable
 *     --------------------------------------------
 *
 * A spinlock variable of the fast path can be statically initialized in the
 * unlocked state, with the macro "__FPN_SPINLOCK_UNLOCKED_INITIALIZER", as for
 * instance:
 *   static __fpn_spinlock_t mylock = __FPN_SPINLOCK_UNLOCKED_INITIALIZER;
 *
 * For this purpose, the SDK must export an architecture-specific macro that
 * can be associated with the fast path __FPN_SPINLOCK_UNLOCKED_INITIALIZER
 * macro as follows:
 *   #define __FPN_SPINLOCK_UNLOCKED_INITIALIZER \
 *           <arch-specific-spinlock-static-init-macro>
 *
 * 1.3 Functions of spinlock API
 *     -------------------------
 *
 * The spinlock API includes functions to initialize, acquire, try to acquire,
 * and release a spinlock, respectively.
 * Each function takes a pointer to the spinlock [object] that it operates on.
 */

/**
 * Initialize a spinlock in the unlocked state.
 *
 * @param p
 *   A pointer to the spinlock.
 */
void __fpn_spinlock_init(__fpn_spinlock_t *p);

/**
 * Acquire a spinlock.
 * Must actively loop waiting for the spinlock to become available.
 *
 * @param p
 *   A pointer to the spinlock.
 */
void __fpn_spinlock_lock(__fpn_spinlock_t *p);

/**
 * Try to acquire a spinlock.
 *
 * Atomically test if the spinlock is available and acquires it in this case,
 * otherwise do nothing.
 *
 * @param p
 *   A pointer to the spinlock.
 *
 * @return
 *  1 if spinlock succesfully acquired
 *  0 otherwise
 */
int __fpn_spinlock_trylock(__fpn_spinlock_t *p);

/**
 * Release a spinlock.
 *
 * @param p
 *   A pointer to the spinlock.
 */
void __fpn_spinlock_unlock(__fpn_spinlock_t *p);

/**
 * Test if a spinlock is locked.
 *
 * @param p
 *   A pointer to the spinlock.
 *
 * @return
 *  > 0 if the spinlock is acquired
 *  0 if the spinlock is free
 */
int __fpn_spinlock_is_locked(__fpn_spinlock_t *p)

/*
 * 2 Fast path read/write lock API
 *   =============================
 *
 * 2.1 Definition of read/write lock
 *     -----------------------------
 *
 * The SDK must export an architecture-specific definition of a read/write lock
 * that is associated with the fast path definition of a read/write lock as
 * follows:
 *   typedef <arch-specific-rwlock-type> __fpn_rwlock_t;
 *
 *
 * 2.2 Functions of read/write lock API
 *     --------------------------------
 *
 * The read/write lock API includes functions to initialize, read-lock,
 * read-unlock, write-lock, and write-unlock a read/write lock, respectively.
 * Each function takes a pointer to the read/write lock [object] that it
 * operates on.
 */

/**
 * Initialize a read/write lock in the unlocked state.
 *
 * @param p
 *   A pointer to the read/write lock.
 */
void __fpn_rwlock_init(__fpn_rwlock_t *p);

/**
 * Acquire a read/write lock for reading.
 *
 * Must actively loop waiting for the read/write lock to become available for
 * readers, if the lock is currently write-locked [by another core].
 * - Support for recursivity is not required/expected.
 * - Support for checking that the read/write lock is not write-locked by
 *   the current executing core is not required/expected.
 *
 * @param p
 *   A pointer to the read/write lock.
 */
void __fpn_rwlock_read_lock(__fpn_rwlock_t *p);

/**
 * Release a read/write lock previously acquired for reading with
 * the function __fpn_rwlock_read_lock().
 *
 * @param p
 *   A pointer to the read/write lock.
 */
void __fpn_rwlock_read_unlock(__fpn_rwlock_t *p);

/**
 * Acquire a read/write lock for writing.
 *
 * Must actively loop waiting for the read/write lock to become available for
 * a writer, if the lock is currently read-locked [by other core(s)] or is
 * write-locked by another core.
 *
 * @param p
 *   A pointer to the read/write lock.
 */
void __fpn_rwlock_write_lock(__fpn_rwlock_t *p);

/**
 * Release a read/write lock previously acquired for writing with
 * the function __fpn_rwlock_write_lock().
 *
 * @param p
 *   A pointer to the read/write lock.
 */
void __fpn_rwlock_write_unlock(__fpn_rwlock_t *p);

/*
 * 3 Fast path 32-bit atomic API
 *   ===========================
 *
 * 3.1 Definition of 32-bit atomic type
 *     --------------------------------
 *
 * The SDK must export an architecture-specific definition of a 32-bit atomic
 * integer that is associated with the fast path definition of a 32-bit atomic
 * integer as follows:
 *  typedef <arch-specific-32-bit-atomic-integer> fpn_atomic_t;
 *
 * 3.2 Static initialization of a 32-bit atomic integer
 *     ------------------------------------------------
 *
 * A 32-bit atomic variable of the fast path can be statically initialized
 * to a given value with the macro "FPN_ATOMIC_INIT(init_value)", as for
 * instance:
 *   static fpn_atomic_t myatomic = FPN_ATOMIC_INIT(1);
 *
 * For this purpose, the SDK must export an architecture-specific macro that
 * can be associated with the fast path macro FPN_ATOMIC_INIT as follows:
 *   #define FPN_ATOMIC_INIT(v) <arch-specific-atomic-init-macro(v)>
 *
 * 3.3 Functions of 32-bit atomic API
 *     ------------------------------
 *
 * The 32-bit atomic API includes the following set of functions that
 * take a pointer to the 32-bit atomic integer that they must operate on.
 */

/**
 * Atomically read a 32-bit integer
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 */
void fpn_atomic_read(fpn_atomic_t *p);

/**
 * Atomically set a 32-bit integer
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 * @param val
 *   The value to set.
 */
void fpn_atomic_set(fpn_atomic_t *p, int val);

/**
 * Atomically add a value to a 32-bit integer
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 * @param val
 *   The value to add to the 32-bit atomic integer.
 */
void fpn_atomic_add(fpn_atomic_t *p, int val);

/**
 * Atomically subtract a value from a 32-bit integer
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 * @param val
 *   The value to subtract from the 32-bit atomic integer.
 */
void fpn_atomic_sub(fpn_atomic_t *p, int val);

/**
 * Atomically increment by 1 a 32-bit integer
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 */
void fpn_atomic_inc(fpn_atomic_t *p);

/**
 * Atomically decrement by 1 a 32-bit integer
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 */
void fpn_atomic_dec(fpn_atomic_t *p);

/**
 * Atomically add a value to a 32-bit integer, and return the new value
 * of the 32-bit integer after the addition.
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 * @param val
 *   The value to add to the 32-bit atomic integer.
 */
int fpn_atomic_add_return(fpn_atomic_t *p, int val);

/**
 * Atomically subtract a value from a 32-bit integer, and return the new
 * value of the 32-bit integer after the subtraction.
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 * @param val
 *   The value to subtract from the 32-bit atomic integer.
 */
void fpn_atomic_sub_return(fpn_atomic_t *p, int val);

/**
 * Atomically increment by 1 a 32-bit integer, and return a positive value if
 * the new value of the 32-bit integer is zero, or zero in all other cases.
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 *
 * @return
 *  > 0 if the new value of the 32-bit integer is zero
 *  0 otherwise
 */
int fpn_atomic_inc_and_test(fpn_atomic_t *p);

/**
 * Atomically decrement by 1 a 32-bit integer, and return a positive value if
 * the new value of the 32-bit integer is zero, or zero in all other cases.
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 *
 * @return
 *  > 0 if the new value of the 32-bit integer is zero
 *  0 otherwise
 */
int fpn_atomic_dec_and_test(fpn_atomic_t *p);

/**
 * Atomically test and set to 1 a 32-bit integer.
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 *
 * @return
 *  0 if 32-bit integer is already set (operation failed)
 *  1 if 32-bit integer was not set, and has been set (operation succeeded)
 */
int fpn_atomic_test_and_set(fpn_atomic_t *p);

/**
 * Atomically set to zero a 32-bit atomic integer.
 *
 * @param p
 *   A pointer to the 32-bit atomic integer.
 */
void fpn_atomic_clear(fpn_atomic_t *p);

/**
 * Atomically compare and set a 32-bit unsigned integer.
 *
 * This function test if the 32-bit volatile integer is equal to "old_val":
 * - if so, replaces set the 32-bit unsigned integer with "new_vaL" and
 *   return 1.
 * - otherwise, do nothing and return 0.
 *
 * @param uip
 *   A pointer to the 32-bit unsigned integer.
 * @param old_val
 *   The value with which to compare the 32-bit unsigned integer.
 * @param new_val
 *   The new value of the 32-bit unsigned integer, if its current value is
 *   equal to old_val.
 *
 * @return
 *  0 if the 32-bit unsigned integer was not equal to old_val
 *  1 if the 32-bit integer was equal to old_val, and has been atomically
 *    set to new_val.
 */
int fpn_cmpset32(fpn_atomic_t *p, int old_val, int new_val);

/*
 * 4 Fast path 64-bit atomic API
 *   ===========================
 *
 * 4.1 Definition of 64-bit atomic type
 *     --------------------------------
 *
 * The SDK must export an architecture-specific definition of a 64-bit atomic
 * integer that is associated with the fast path definition of a 64-bit atomic
 * integer as follows:
 *  typedef <arch-specific-64-bit-atomic-integer> fpn_atomic64_t;
 *
 * 4.2 Static initialization of a 64-bit atomic integer
 *     ------------------------------------------------
 *
 * A 64-bit atomic variable of the fast path can be statically initialized
 * to a given value with the macro "FPN_ATOMIC_INIT64(init_value)", as for
 * instance:
 *   static fpn_atomic64_t myatomic = FPN_ATOMIC_INIT64(1);
 *
 * For this purpose, the SDK must export an architecture-specific macro that
 * can be associated with the fast path macro FPN_ATOMIC_INIT64 as follows:
 *   #define FPN_ATOMIC_INIT64(v) <arch-specific-atomic-init64-macro(v)>
 *
 * 4.3 Functions of 64-bit atomic API
 *     ------------------------------
 *
 * The 64-bit atomic API includes the following set of functions that
 * take a pointer to the 64-bit atomic integer that they must operate on.
 */

/**
 * Atomically read a 64-bit integer
 *
 * @param p
 *   A pointer to the 64-bit atomic integer.
 */
void fpn_atomic_read64(fpn_atomic64_t *p);

/**
 * Atomically set a 64-bit integer
 *
 * @param p
 *   A pointer to the 64-bit atomic integer.
 * @param val
 *   The value to set.
 */
void fpn_atomic_set64(fpn_atomic64_t *p, int64_t val);

/**
 * Atomically add a value to a 64-bit integer
 *
 * @param p
 *   A pointer to the 64-bit atomic integer.
 * @param val
 *   The value to add to the 64-bit atomic integer.
 */
void fpn_atomic_add64(fpn_atomic64_t *p, int64_t val);

/*
 * 5 Fast path memory barrier API
 *   ============================
 *
 * 5.1 Functions of memory barrier API
 *     -------------------------------
 *
 * The memory barrier API includes the following set of functions.
 */

/**
 * General memory barrier.
 *
 * Guarantees that all LOAD and STORE operations that were issued before the
 * barrier occur before the LOAD and STORE operations issued after the barrier.
 */
void fpn_mb();

/**
 * Read memory barrier.
 *
 * Guarantees that all LOAD operations that were issued before the barrier
 * occur before the STORE operations that are issued after.
 */
void fpn_rmb();

/**
 * Write memory barrier.
 *
 * Guarantees that all STORE operations that were issued before the barrier
 * occur before the STORE operations that are issued after.
 */
void fpn_wmb();
#endif /* LOCK_API_MANUAL */

#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
/*
 * Debug structure embedded at the beginning of each lock definition.
 */
typedef struct {
	int  owning_core; /* core that currently owns the lock, -1 otherwise */
	const char *func; /* name of function that acquired/released the lock */
	const char *file; /* source file of the acquiring/releasing function */
	int  line;        /* line number in source file of lock operation */
} fpn_debug_lock_t;

#define FPN_DEBUG_LOCK_INITIALIZER \
	{ .owning_core = -1, .func = "", .file = __FILE__, .line = __LINE__, }

extern void fpn_debug_lock_display(void *debug_lock);
extern void fpn_debug_lock_log_display(int core_id, int max_records);
#endif /* CONFIG_MCORE_FPN_LOCK_DEBUG */

#ifndef CONFIG_MCORE_FPN_LOCK_DEBUG
#define fpn_spinlock_t __fpn_spinlock_t
#define fpn_spinlock_init __fpn_spinlock_init
#define fpn_spinlock_lock __fpn_spinlock_lock
#define fpn_spinlock_unlock __fpn_spinlock_unlock
#define fpn_spinlock_trylock __fpn_spinlock_trylock
#define fpn_spinlock_is_locked __fpn_spinlock_is_locked
#define FPN_SPINLOCK_UNLOCKED_INITIALIZER __FPN_SPINLOCK_UNLOCKED_INITIALIZER
#else
typedef struct {
	fpn_debug_lock_t debug_state; /* lock debug info */
	__fpn_spinlock_t the_lock;    /* the actual lock */
} fpn_spinlock_t;

#define FPN_SPINLOCK_UNLOCKED_INITIALIZER \
	{ \
		.the_lock    = __FPN_SPINLOCK_UNLOCKED_INITIALIZER,	\
		.debug_state = FPN_DEBUG_LOCK_INITIALIZER,	\
	}

extern void fpn_debug_spinlock_init(fpn_spinlock_t *lck, const char *func,
				    const char *file, int line);
extern void fpn_debug_spinlock_lock(fpn_spinlock_t *lck, const char *func,
				    const char *file, int line);
extern int  fpn_debug_spinlock_trylock(fpn_spinlock_t *lck, const char *func,
				       const char *file, int line);
extern void fpn_debug_spinlock_unlock(fpn_spinlock_t *lck, const char *func,
				      const char *file, int line);
static inline int
fpn_debug_spinlock_is_locked(fpn_spinlock_t *lck)
{
	return (__fpn_spinlock_is_locked(&lck->the_lock));
}

#define fpn_spinlock_init(sp_lock) \
	fpn_debug_spinlock_init((sp_lock), __func__, __FILE__, __LINE__)
#define fpn_spinlock_lock(sp_lock) \
	fpn_debug_spinlock_lock((sp_lock), __func__, __FILE__, __LINE__)
#define fpn_spinlock_trylock(sp_lock) \
	fpn_debug_spinlock_trylock((sp_lock), __func__, __FILE__, __LINE__)
#define fpn_spinlock_unlock(sp_lock) \
	fpn_debug_spinlock_unlock((sp_lock), __func__, __FILE__, __LINE__)
#define fpn_spinlock_is_locked(sp_lock)	\
	fpn_debug_spinlock_is_locked((sp_lock))
#endif /* CONFIG_MCORE_FPN_LOCK_DEBUG */

/**
 * The fpn_recurs_spinlock_t type.
 */
typedef struct {
	fpn_spinlock_t sl; /**< the actual spinlock */
	volatile int user; /**< core id using lock, -1 for unused */
	volatile int count; /**< count of time this lock has been called */
} fpn_recurs_spinlock_t;

/**
 * Initialize the recursive spinlock to an unlocked state.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
void fpn_recurs_spinlock_init(fpn_recurs_spinlock_t *slr);

/**
 * Take the recursive spinlock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
void __fpn_recurs_spinlock_lock(fpn_recurs_spinlock_t *slr, const char *func,
				const char *file, int line);
#define fpn_recurs_spinlock_lock(slr)					\
	__fpn_recurs_spinlock_lock(slr, __func__, __FILE__, __LINE__)
#else
void __fpn_recurs_spinlock_lock(fpn_recurs_spinlock_t *slr);
#define fpn_recurs_spinlock_lock(slr) __fpn_recurs_spinlock_lock(slr)
#endif

/**
 * Release the recursive spinlock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
void __fpn_recurs_spinlock_unlock(fpn_recurs_spinlock_t *slr, const char *func,
				  const char *file, int line);
#define fpn_recurs_spinlock_unlock(slr)					\
	__fpn_recurs_spinlock_unlock(slr, __func__, __FILE__, __LINE__)
#else
void __fpn_recurs_spinlock_unlock(fpn_recurs_spinlock_t *slr);
#define fpn_recurs_spinlock_unlock(slr)		\
	__fpn_recurs_spinlock_unlock(slr)
#endif

/**
 * Try to take the recursive lock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
int __fpn_recurs_spinlock_trylock(fpn_recurs_spinlock_t *slr, const char *func,
				  const char *file, int line);
#define fpn_recurs_spinlock_trylock(slr)				\
	__fpn_recurs_spinlock_trylock(slr, __func__, __FILE__, __LINE__)
#else
int __fpn_recurs_spinlock_trylock(fpn_recurs_spinlock_t *slr);
#define fpn_recurs_spinlock_trylock(slr)	\
	__fpn_recurs_spinlock_trylock(slr)
#endif

/**
 * Check if a recursive spinlock is locked
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 * @return
 *   1 if the lock is locked
 */
int fpn_recurs_spinlock_is_locked(fpn_recurs_spinlock_t *slr);

/**
 * Return the number of lockers
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 * @return
 *   the number of lockers
 */
int fpn_recurs_spinlock_count(fpn_recurs_spinlock_t *slr);

#ifndef CONFIG_MCORE_FPN_LOCK_DEBUG
#define fpn_rwlock_t __fpn_rwlock_t
#define fpn_rwlock_init __fpn_rwlock_init
#define fpn_rwlock_read_lock __fpn_rwlock_read_lock
#define fpn_rwlock_read_unlock __fpn_rwlock_read_unlock
#define fpn_rwlock_write_lock __fpn_rwlock_write_lock
#define fpn_rwlock_write_unlock __fpn_rwlock_write_unlock
#else
typedef struct {
	fpn_debug_lock_t debug_state; /* lock debug info */
	__fpn_rwlock_t the_lock;      /* the actual lock */
} fpn_rwlock_t;

extern void fpn_debug_rwlock_init(fpn_rwlock_t *lck, const char *func,
				  const char *file, int line);
extern void fpn_debug_rwlock_read_lock(fpn_rwlock_t *lck, const char *func,
				       const char *file, int line);
extern void fpn_debug_rwlock_read_unlock(fpn_rwlock_t *lck, const char *func,
					 const char *file, int line);
extern void fpn_debug_rwlock_write_lock(fpn_rwlock_t *lck, const char *func,
					const char *file, int line);
extern void fpn_debug_rwlock_write_unlock(fpn_rwlock_t *lck, const char *func,
					  const char *file, int line);

#define fpn_rwlock_init(rw_lock) \
	fpn_debug_rwlock_init((rw_lock), __func__, __FILE__, __LINE__)
#define fpn_rwlock_read_lock(rw_lock) \
	fpn_debug_rwlock_read_lock((rw_lock), __func__, __FILE__, __LINE__)
#define fpn_rwlock_read_unlock(rw_lock) \
	fpn_debug_rwlock_read_unlock((rw_lock), __func__, __FILE__, __LINE__)
#define fpn_rwlock_write_lock(rw_lock) \
	fpn_debug_rwlock_write_lock((rw_lock), __func__, __FILE__, __LINE__)
#define fpn_rwlock_write_unlock(rw_lock) \
	fpn_debug_rwlock_write_unlock((rw_lock), __func__, __FILE__, __LINE__)
#endif /* CONFIG_MCORE_FPN_LOCK_DEBUG */

#endif /* __FPN_LOCK_H__ */
