/*
 * Copyright(c) 2011 6WIND
 * All rights reserved.
 */

#include "fpn.h"
#include "fpn-ring.h"
#include "fpn-mempool.h"
#include "fpn-ringpool.h"

#define FPN_RINGPOOL_ERROR(fmt, args...) do {	\
		fpn_printf(fmt "\n", ## args);	\
	} while (0)

#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/*
 * Internal use
 * called at ringpool initialization on each ring
 */
static void ringpool_ring_init(__attribute__ ((unused)) struct fpn_mempool *mp,
		void *data, void *obj,
		__attribute__ ((unused)) unsigned index)
{
	struct fpn_ring *r = (struct fpn_ring *)obj;
	unsigned count = *(unsigned *)data;

	/*
	 * Inside pool, rings are
	 *  - unnamed
	 *  - multiple producer/consumer (default)
	 */
	fpn_ring_init(r, "", count, 0);
}


/*
 * A ringpool is just a mempool, with well-known objects. The private structure
 * holds a pointer to another pool, allowing to chain ringpools, hence defining
 * an allocation strategy
 */
int
fpn_ringpool_init(struct fpn_mempool *mp, struct fpn_ring *r,
		 void *objtable, const char *name, unsigned n,
		 unsigned r_n)
{
	int res;
	void **mp_priv;

	/* ring size must be a power of 2 */
	if (!POWEROF2(r_n)) {
		FPN_RINGPOOL_ERROR("Requested size is not a power of 2\n");
		return -1;
	}

	res = fpn_mempool_init(mp, r, objtable, name, n,
		/* Each element of the pool is a ring of r_n elements */
		fpn_ring_getsize(r_n),
		/*
		 * Allow some cache for accessing the pool.
		 * such pools of rings are not expected to be that many.
		 */
		FPN_MEMPOOL_CACHE_MAX_SIZE,
		/*
		 * The private field will be used to store linkage between
		 * ringpools
		 */
		sizeof(void *),
		/*
		 * No specific init inside the pool before the object (rings)
		 * initialization. The private area will be initialized later
		 */
		NULL, NULL,
		/* Local initialization of the ring as element */
		ringpool_ring_init, &r_n,
		/*
		 * Default behavior: cache aligned, multiple producers
		 * and consumers.
		 */
		0);

	if (res)
		return res;

	mp_priv = (void **)fpn_mempool_get_priv(mp);
	*mp_priv = NULL;

	return 0;
}

/*
 * Idem
 */
struct fpn_mempool *
fpn_ringpool_create(const char *name,
		unsigned n, unsigned r_n)
{
	struct fpn_mempool *mp;
	void **mp_priv;

	/* rign size must be a power of 2 */
	if (!POWEROF2(r_n)) {
		FPN_RINGPOOL_ERROR("Requested size is not a power of 2\n");
		return NULL;
	}

	mp = fpn_mempool_create(name, n,
		/* Each element of the pool is a ring of r_n elements */
		fpn_ring_getsize(r_n),
		/*
		 * Allow some cache for accessing the pool.
		 * such pools of rings are not expected to be that many.
		 */
		FPN_MEMPOOL_CACHE_MAX_SIZE,
		/*
		 * The private filed will be used to store linkage between
		 * ringpools
		 */
		sizeof(void *),
		/*
		 * No specific init inside the pool before the object (rings)
		 * initialization. The private area will be initialized later
		 */
		NULL, NULL,
		/* Local initialization of the ring as element */
		ringpool_ring_init, &r_n,
		/*
		 * Default behavior: cache aligned, multiple producers
		 * and consumers.
		 */
		0);

	if (!mp)
		return NULL;

	mp_priv = (void **)fpn_mempool_get_priv(mp);
	*mp_priv = NULL;

	return mp;
}

/*
 * Set ringpool linkage for ring allocation strategy
 */
void fpn_ringpool_link(struct fpn_mempool *first, struct fpn_mempool *next)
{
	struct fpn_mempool **mpp;

	mpp = (struct fpn_mempool **)fpn_mempool_get_priv(first);
	*mpp =  next;
}
