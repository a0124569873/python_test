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

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

/* Allocate memory from the heap */
void *fpn_malloc(size_t size, unsigned align)
{
	void *ptr;
	unsigned long addr, align_addr;
	unsigned sz;

	/* align must be a power of 2 */
	if (unlikely(align != 0 && !POWEROF2(align)))
		return NULL;
	if (align != 0)
		align -= 1;

	/* allocated size depends on required alignment and must
	 * include some space to store malloc'd pointer */
	sz = size + sizeof(void *) + align;
	ptr = __fpn_malloc(sz);
	if (unlikely(ptr == NULL))
		return NULL;

	/* get aligned address */
	addr = (unsigned long)ptr;
	align_addr = (addr + sizeof(void *) + align) & ~((size_t)align);

	/* save allocated address for future free */
	*(void **)(align_addr - sizeof(void *)) = ptr;

	return (void *)align_addr;
}

/* Allocate zero'ed memory from the heap */
void *fpn_zalloc(size_t size, unsigned align)
{
	void *ptr;
	ptr = fpn_malloc(size, align);
	if (unlikely(ptr == NULL))
		return NULL;
	memset(ptr, 0, size);
	return ptr;
}

/* Frees the memory space pointed to by ptr */
void fpn_free(void *ptr)
{
	unsigned long addr;
	addr = (unsigned long)ptr - sizeof(void *);
	__fpn_free(*(void **)addr);
}
