/*
 * Copyright 2014 6WIND S.A.
 */

/*
 * This file implements a sequential lock
 *
 * A sequential lock is a reader-writer consistent mechanism which avoids the
 * problem of writer starvation. A seqlock consists of storage for saving a
 * sequence number in addition to a lock. The lock is to support synchronization
 * between two writers and the counter is for indicating consistency in readers.
 * In addition to updating the shared data, the writer increments the sequence
 * number, both after acquiring the lock and before releasing the lock. Readers
 * read the sequence number before and after reading the shared data. If the
 * sequence number is odd on either occasion, a writer had taken the lock while
 * the data was being read and it may have changed. If the sequence numbers
 * are different, a writer has changed the data while it was being read.
 * In either case readers simply retry (using a loop) until they read the same
 * even sequence number before and after.
 *
 * WARNING: In current implementation, there is no spinlock to prevent several
 *          writers to write concurrently. So this seqlock version must only
 *          be used if there is a single writer.
 * 
 * Example:
 *
 * data_t d;
 * volatile fp_seqlock_t seq;
 *
 * void writer(data_t new_data)
 * {
 * 	fp_seq_write_lock(&seq);
 * 	write_data(&d, new_data);
 * 	fp_seq_write_unlock(&seq);
 * }
 *
 * int reader(void)
 * {
 * 	data_t local_data;
 * 	fp_seqlock_t local_seq;
 *
 * 	if (fp_seq_write_inprogress(&seq))
 * 		return -EAGAIN;
 *
 * 	local_seq = fp_seq_read_start(&seq);
 * 	local_data = read_data(&d);
 *
 * 	if (fp_seq_read_invalid(&seq, local_seq))
 * 		return -EAGAIN;
 *
 * 	return 0;
 * }
 */

#ifndef __FP_SEQLOCK_H__
#define __FP_SEQLOCK_H__

#ifndef __FastPath__
#define fpn_wmb() __sync_synchronize()
#define fpn_rmb() __sync_synchronize()
#endif

typedef uint32_t fp_seqlock_t;

static inline void fp_seq_write_lock(volatile fp_seqlock_t *seq)
{
	(*seq)++;
	fpn_wmb();
}

static inline void fp_seq_write_unlock(volatile fp_seqlock_t *seq)
{
	fpn_wmb();
	(*seq)++;
}

static inline int fp_seq_write_inprogress(volatile fp_seqlock_t *seq)
{
	return unlikely((*seq) & 1);
}

static inline fp_seqlock_t fp_seq_read_start(volatile fp_seqlock_t *seq)
{
	fp_seqlock_t seq_start = *seq;
	fpn_rmb();
	return seq_start;
}

static inline int fp_seq_read_invalid(volatile fp_seqlock_t *seq,
				      fp_seqlock_t seq_start)
{
	fpn_rmb();
	return unlikely(*seq != seq_start);
}

#endif
