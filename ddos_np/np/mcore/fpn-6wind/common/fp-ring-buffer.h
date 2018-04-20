#ifndef _FP_RING_BUFFER_H_
#define _FP_RING_BUFFER_H_

#ifndef _RING_BUFFER_SIZE
#define _RING_BUFFER_SIZE (1024*4)
#endif

#ifndef _BUFFER_ENNTRY_SIZE
#define _BUFFER_ENNTRY_SIZE (5 * sizeof(unsigned long))
#endif

#define DATA_CPOPY(a, b, c)  { \
    int s = c; \
    unsigned long* p1 = (unsigned long*)a; \
    unsigned long* p2 = (unsigned long*)b; \
    while(s -- > 0) *p1 ++ = *p2 ++; \
}

typedef struct buffer_entity {
	uint8_t type;
	unsigned long mem[(_BUFFER_ENNTRY_SIZE + sizeof(unsigned long) - 1)/sizeof(unsigned long)];
} __attribute__((aligned(sizeof(unsigned long)))) buffer_entity_t;

#define entry_type(e) (e)->type
#define entry_data(e, type) (type)((e)->mem)

typedef struct ring_buffer {
	int prod;
	int cons;
	fpn_spinlock_t lock;
	struct buffer_entity data[_RING_BUFFER_SIZE];
}  __attribute__((aligned(1))) ring_buffer_t;

static inline void entry_copy(struct buffer_entity* a, struct buffer_entity* b) {
	DATA_CPOPY(a, b, sizeof(struct buffer_entity)/sizeof(unsigned long));
}

static inline int ring_buffer_size(struct ring_buffer* ring) {
	return (ring->prod - ring->cons + _RING_BUFFER_SIZE)%_RING_BUFFER_SIZE;
}

static inline int ring_buffer_empty(struct ring_buffer* ring) {
	return ring->prod == ring->cons ? 1 : 0;
}

#ifndef LOCK_BLOCK

#define LOCK_BLOCK(lock, block) { \
	fpn_spinlock_lock(lock);\
	block; \
	fpn_spinlock_unlock(lock); \
}

#endif

static inline void ring_buffer_enqueue(struct ring_buffer* ring, struct buffer_entity* entry, int count, void (*of)(struct ring_buffer*, struct buffer_entity*)) {
	LOCK_BLOCK(&ring->lock, {
		int prod = ring->prod;
		int cons = ring->cons;

		int i = 0;

		for(;i < count; i ++) {
			int next_prod = (prod + 1)%_RING_BUFFER_SIZE;

			if (next_prod == cons) {
				of(ring, &ring->data[cons]);
				cons = (next_prod + 1)%_RING_BUFFER_SIZE;
			}

			entry_copy(&ring->data[prod], entry + i);

			prod = next_prod;
		}

		ring->prod = prod;
		ring->cons = cons;
	})
}

/*
*
* 	return dequeue count
*/
static inline int ring_buffer_dequeue(struct ring_buffer* ring, struct buffer_entity* entry, int count) {
	int i = 0;

	LOCK_BLOCK(&ring->lock, {
		int prod = ring->prod;
		int cons = ring->cons;

		for(; i < count && cons != prod; i++, cons = (cons + 1)%_RING_BUFFER_SIZE) {
			entry_copy(entry + i, &ring->data[cons]);
		}

		ring->cons = cons;
	})
	
	return i;
}

#endif // _FP_RING_BUFFER_H_