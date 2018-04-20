/*
 * Copyright(c) 2010 6WIND
 */

#ifndef __FPN_LOCK_DPDK_H__
#define __FPN_LOCK_DPDK_H__

#include <stdint.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_rwlock.h>

typedef rte_spinlock_t __fpn_spinlock_t;
#define __fpn_spinlock_init(x)      rte_spinlock_init(x)
#define __fpn_spinlock_lock(x)      rte_spinlock_lock(x)
#define __fpn_spinlock_trylock(x)   rte_spinlock_trylock(x)
#define __fpn_spinlock_unlock(x)    rte_spinlock_unlock(x)
#define __fpn_spinlock_is_locked(x) rte_spinlock_is_locked(x)
#define __FPN_SPINLOCK_UNLOCKED_INITIALIZER RTE_SPINLOCK_INITIALIZER


typedef rte_rwlock_t __fpn_rwlock_t;
#define __fpn_rwlock_init(x)         rte_rwlock_init(x)
#define __fpn_rwlock_read_lock(x)    rte_rwlock_read_lock(x)
#define __fpn_rwlock_read_unlock(x)  rte_rwlock_read_unlock(x)
#define __fpn_rwlock_write_lock(x)   rte_rwlock_write_lock(x)
#define __fpn_rwlock_write_unlock(x) rte_rwlock_write_unlock(x)

typedef rte_atomic32_t fpn_atomic_t;
#define FPN_ATOMIC_INIT(i)            RTE_ATOMIC32_INIT(i)
#define fpn_atomic_read(v)            rte_atomic32_read(v)
#define fpn_atomic_set(v, i)          rte_atomic32_set(v, i)

#define fpn_atomic_add(v, i)          rte_atomic32_add(v, i)
#define fpn_atomic_sub(v, i)          rte_atomic32_sub(v, i)
#define fpn_atomic_inc(v)             rte_atomic32_inc(v)
#define fpn_atomic_dec(v)             rte_atomic32_dec(v)

#define fpn_atomic_add_return(v, i)   rte_atomic32_add_return(v, i)
#define fpn_atomic_sub_return(v, i)   rte_atomic32_sub_return(v, i)

#define fpn_atomic_inc_and_test(v)    rte_atomic32_inc_and_test(v)
#define fpn_atomic_dec_and_test(v)    rte_atomic32_dec_and_test(v)

#define fpn_atomic_test_and_set(v)    rte_atomic32_test_and_set(v)
#define fpn_atomic_clear(v)           rte_atomic32_clear(v)

#define fpn_cmpset32(v, old, new) rte_atomic32_cmpset(v, old, new)

typedef rte_atomic64_t fpn_atomic64_t;
#define FPN_ATOMIC_INIT64(i)          RTE_ATOMIC64_INIT(i)
#define fpn_atomic_read64(v)          rte_atomic64_read(v)
#define fpn_atomic_set64(v, i)        rte_atomic64_set(v, i)

#define fpn_atomic_add64(v, i)        rte_atomic64_add(v, i)

#define fpn_atomic_sub64(v, i)        rte_atomic64_sub(v, i)
#define fpn_atomic_inc64(v)           rte_atomic64_inc(v)
#define fpn_atomic_dec64(v)           rte_atomic64_dec(v)

#define fpn_atomic_add_return64(v, i) rte_atomic64_add_return(v, i)
#define fpn_atomic_sub_return64(v, i) rte_atomic64_sub_return(v, i)

#define fpn_atomic_inc_and_test64(v)  rte_atomic64_inc_and_test(v)
#define fpn_atomic_dec_and_test64(v)  rte_atomic64_dec_and_test(v)

/* memory barrier */
#define fpn_mb()  rte_mb()
#define fpn_rmb() rte_rmb()
#define fpn_wmb() rte_wmb()

#endif /* __FPN_LOCK_DPDK_H__ */
