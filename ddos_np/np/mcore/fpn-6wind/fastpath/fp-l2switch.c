/*
 * Copyright(c) 2012 6WIND
 */

#include "fpn.h"
#include "fp-includes.h"
#include "shmem/fpn-shmem.h"
#include "fp-l2switch.h"

FPN_DEFINE_SHARED(l2switch_shared_mem_t *, l2switch_shared);

void fp_l2switch_init(void)
{
	int portid;

	memset(l2switch_shared, 0, sizeof(l2switch_shared_mem_t));

	for (portid = 0; portid < FP_MAX_PORT; portid++)
		l2switch_shared->next_portid[portid] = FP_L2SWITCH_PORT_DROP;

	/* default is off to avoid any problem */
	l2switch_shared->mode = FP_L2SWITCH_OFF;
}

void* l2switch_shared_alloc(void)
{
	void *addr;

	/* Create fp-shared memory. Ignore error, it may already
	 * exist.
	 */
	fpn_shmem_add(L2SWITCH_SHM_NAME, sizeof(l2switch_shared_mem_t));
	addr = get_l2switch_shared_mem();
	if (addr == NULL) {
		fpn_printf("cannot map l2switch_shared size=%"PRIu64" (%"PRIu64"M)\n",
			   (uint64_t)sizeof(l2switch_shared_mem_t),
			   (uint64_t)sizeof(l2switch_shared_mem_t) >> 20);
		return NULL;
	}
	fpn_printf("Using l2switch_shared=0x%p size=%"PRIu64" (%"PRIu64"M)\n",
		   addr, (uint64_t)sizeof(l2switch_shared_mem_t),
		   (uint64_t)sizeof(l2switch_shared_mem_t) >> 20);

	return addr;
}

void fp_l2switch_input(struct mbuf *m)
{
	unsigned next_portid;
	unsigned portid = m_input_port(m);

	switch (l2switch_shared->mode) {
		case FP_L2SWITCH_ON:
			next_portid = l2switch_shared->next_portid[portid];

			if (next_portid == FP_L2SWITCH_PORT_DROP) {
				FP_L2SWITCH_STATS_INC(l2switch_shared->stats[portid], drop);
				m_freem(m);
				return;
			}

			if (next_portid == FP_L2SWITCH_PORT_EXCEPTION) {
				FP_L2SWITCH_STATS_INC(l2switch_shared->stats[portid], exception);
				fpn_send_exception(m, portid);
				return;
			}

			FP_L2SWITCH_STATS_INC(l2switch_shared->stats[portid], forward);
			fpn_send_packet(m, next_portid);
			break;

		case FP_L2SWITCH_OFF:
		default:
			FP_L2SWITCH_STATS_INC(l2switch_shared->stats[portid], drop);
			m_freem(m);
			break;
	}
}
