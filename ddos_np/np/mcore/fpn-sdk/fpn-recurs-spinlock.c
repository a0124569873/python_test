/*
 * Copyright(c) 2011 6WIND
 * All rights reserved.
 */

/*-
 * Copyright (c) <2010>, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "fpn.h"

void
fpn_recurs_spinlock_init(fpn_recurs_spinlock_t *slr)
{
	fpn_spinlock_init(&slr->sl);
	slr->user = -1;
	slr->count = 0;
}

#ifdef CONFIG_MCORE_FPN_LOCK_DEBUG
void
__fpn_recurs_spinlock_lock(fpn_recurs_spinlock_t *slr, const char *func,
			   const char *file, int line)
{
	int id = fpn_get_core_num();

	if (slr->user != id) {
		fpn_debug_spinlock_lock(&slr->sl, func, file, line);
		slr->user = id;
	}
	slr->count++;
}

void
__fpn_recurs_spinlock_unlock(fpn_recurs_spinlock_t *slr, const char *func,
			     const char *file, int line)
{
	FPN_ASSERT(slr->user == fpn_get_core_num());
	FPN_ASSERT(slr->count > 0);

	if (--(slr->count) == 0) {
		slr->user = -1;
		fpn_debug_spinlock_unlock(&slr->sl, func, file, line);
	}
}

int
__fpn_recurs_spinlock_trylock(fpn_recurs_spinlock_t *slr, const char *func,
			     const char *file, int line)
{
	int id = fpn_get_core_num();

	if (slr->user != id) {
		if (fpn_debug_spinlock_trylock(&slr->sl, func, file, line) == 0)
			return 0;
		slr->user = id;
	}
	slr->count++;
	return 1;
}

#else
void
__fpn_recurs_spinlock_lock(fpn_recurs_spinlock_t *slr)
{
	int id = fpn_get_core_num();

	if (slr->user != id) {
		fpn_spinlock_lock(&slr->sl);
		slr->user = id;
	}
	slr->count++;
}

void
__fpn_recurs_spinlock_unlock(fpn_recurs_spinlock_t *slr)
{
	FPN_ASSERT(slr->user == fpn_get_core_num());
	FPN_ASSERT(slr->count > 0);

	if (--(slr->count) == 0) {
		slr->user = -1;
		fpn_spinlock_unlock(&slr->sl);
	}
}

int
__fpn_recurs_spinlock_trylock(fpn_recurs_spinlock_t *slr)
{
	int id = fpn_get_core_num();

	if (slr->user != id) {
		if (fpn_spinlock_trylock(&slr->sl) == 0)
			return 0;
		slr->user = id;
	}
	slr->count++;
	return 1;
}
#endif

int
fpn_recurs_spinlock_is_locked(fpn_recurs_spinlock_t *slr)
{
	return fpn_spinlock_is_locked(&slr->sl);
}

int
fpn_recurs_spinlock_count(fpn_recurs_spinlock_t *slr)
{
	return slr->count;
}
