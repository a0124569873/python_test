/*
 * Queue Allocator
 *
 * Implementation of a memory allocator to manage allocation of small objects,
 * and be assured to get the memory back quickly enough.
 *
 * We will focus on avoiding the process to keep the memory for itself when
 * freed (example below), instead of giving it back to the system, and try
 * to minimize system calls as well.
 * We might also take advantage of the fact that we know that our objects will
 * more or less be freed in the same order as they were alloced.
 *
 * Example of malloc/free the problem:
 *  1/ malloc 0 to 9
 *  2/ free 0 to 8
 *   -> memory from 0 to 8 is kept by the process until we free 9,
 *      for small objects.
 *
 * How it works:
 *
 *  The qa_mem structure keeps track of the current memory chunk, and
 *  a pointer to the start of the next_free zone.
 *
 *   Allocation
 *  When we want to allocate a new object, we move the next_free by
 *  ((size of the data to allocate) + (size of the object header) + 8) & ~0x7,
 *  so that next object will be naturally aligned on 64 bits,
 *  store the current chunk in the object header, and add an object to
 *  the chunk count.  If we don't have enough room in the current
 *  chunk, we allocate a new one, that becomes the current one.
 *
 *   Free
 *  When we want to free an object, we get the object header
 *  from the object data pointer that we are given, and get back the
 *  chunk. We decrement the chunk counter, and when it goes to 0, we
 *  unmap the chunk, and give the memory back to the system. A small
 *  optimization here, we try to save one chunk in the qa_mem
 *  structure, to use it for the further object allocation and avoid
 *  too much calls to mmap.
 *
 *   Configuration
 *  The behavior of the system can be configured. One
 *  can:
 *   - set the chunk size
 *   - use malloc/free in case that an object is bigger than chunk size
 *   - add debug
 *   - poison the object on free, for debugging purpose
 *
 *   Notes
 *  A few notes here:
 *   - For now, we don't keep the list of the chunks, so we can not free
 *      a qa_mem_t unless we have freed all the objects in all the chunks
 *      (and this api does not expect it).
 *   - In most cases, malloc / free is certainly way better, this was
 *      done to address the malloc problem.
 *
 *
 * Usage:
 *  - malloc a qa_mem structure
 *  - call qa_init on it, define the chunk size
 *  - then simply use qa_alloc/qa_free
 *  - some counters are kept in the qa_mem structure to count objects
 *
 * Copyright(c) 2010 6WIND, All rights reserved.
 */

#ifndef QUEUE_ALLOC_H
#define QUEUE_ALLOC_H

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <malloc.h>
#include <string.h>

/* Configuration */
/* Size of one chunk */
#define QA_MEM_CHUNK_SIZE (256*1024)

/* Debug switch (/!\ verbose) */
/* #define QA_DEBUG */

/* Fallback to malloc when the object is too big for one chunk */
#define QA_MALLOC_FALLBACK

/* Debugging purpose: poison the entry on leaving */
/* #define QA_POISON */


#ifdef QA_DEBUG
#define qa_debug(fmt, args...) fprintf(stderr, fmt, ## args)
#else
#define qa_debug(fmt, args...)
#endif


/*
 * qa_mem_chunk structure
 *  The header of a block of memory.
 */
struct qa_mem_chunk
{
	caddr_t limit;			/* end of this chunk */
	int count;			/* object count for this chunk */
	char content[0] __attribute__ ((aligned (8))); /* actual memory */
};
typedef struct qa_mem_chunk qa_mem_chunk_t;

/*
 * qa_mem structure
 *  The memory allocator structure.
 */
struct qa_mem
{
	qa_mem_chunk_t *current;	/* (= chunk where we alloc = last one) */
	qa_mem_chunk_t *saved;		/* we save an alloced and empty chunk,
					   ready to be used */
	caddr_t next_free;		/* end of the last allocated object */
	int chk_size;			/* size for the to be allocated chunks,
					   by default QA_MEM_CHUNK_SIZE */
	/* statistics */
	int chk_count;			/* chunk count */
	int chk_alloc_error;		/* chunk allocation error count */
	int chk_total_count;		/* chunk total allocated count */
	int obj_count;			/* obj chunk-allocated count */
	int obj_total_count;		/* total allocated count */
	int obj_malloc_count;		/* obj malloced count */
	int obj_ignored_free;		/* ignored frees */
};
typedef struct qa_mem qa_mem_t;

/*
 * qa_mem_object
 *  A header for each object.
 */
#define QA_MEM_MALLOC	 1
#define QA_MEM_CHUNK	 2

struct qa_mem_object
{
	qa_mem_chunk_t *chunk;	/* the chunk it was allocated into */
#ifdef QA_POISON
	size_t size;			/* object data size */
#endif
#ifdef QA_MALLOC_FALLBACK
	int alloc_type;			/* allocation type
					   (QA_MEM_MALLOC or QA_MEM_CHUNK) */
#endif
	/*
	 * using void* here ensures that data field offset is aligned
	 * on sizeof(void*).
	 */
	void *data[];			/* actual object */
};
typedef struct qa_mem_object qa_mem_object_t;

/* Get the object structure from the data pointer */
#define qa_mem_to_object(d) (void*)((char*)d - (offsetof(qa_mem_object_t, data)))


/* debug functions */
static inline void qa_print_chunk(const qa_mem_chunk_t *chunk)
{
#ifdef QA_DEBUG
	qa_debug("%s: address=%p\n", __func__, chunk);
	qa_debug("\tlimit=%p\n", chunk->limit);
	qa_debug("\tcount=%d\n", chunk->count);
#endif
}

static inline void qa_print_object(const qa_mem_object_t *object)
{
#ifdef QA_DEBUG
	qa_debug("%s: address=%p\n", __func__, object);
	qa_debug("\tchunk=%p\n", object->chunk);
#ifdef QA_POISON
	qa_debug("\tsize=%d\n", object->size);
#endif
#ifdef QA_MALLOC_FALLBACK
	qa_debug("\talloc_type=%d\n", object->alloc_type);
#endif
	qa_debug("\tdata start=%p\n", object->data);
#endif
}

static inline void qa_print_mem(const qa_mem_t *qa_mem)
{
#ifdef QA_DEBUG
	qa_debug("%s: address=%p\n", __func__, qa_mem);
	qa_debug("\tcurrent=%p\n", qa_mem->current);
	qa_debug("\tsaved=%p\n", qa_mem->saved);
	qa_debug("\tchk_count=%d\n", qa_mem->chk_count);
	qa_debug("\tchk_alloc_error=%d\n", qa_mem->chk_alloc_error);
	qa_debug("\tchk_total_count=%d\n", qa_mem->chk_total_count);
	qa_debug("\tobj_count=%d\n", qa_mem->obj_count);
	qa_debug("\tobj_malloc_count=%d\n", qa_mem->obj_malloc_count);
	qa_debug("\tobj_total_count=%d\n", qa_mem->obj_total_count);
	qa_debug("\tobj_ignored_free=%d\n", qa_mem->obj_ignored_free);
	qa_debug("\tnext_free=%p\n", qa_mem->next_free);
#endif
}


/* Private functions (chunk management) */
static inline qa_mem_chunk_t * qa_init_chunk(qa_mem_t *qa_mem)
{
	qa_mem_chunk_t *chunk = mmap(0, qa_mem->chk_size,
				     PROT_READ | PROT_WRITE,
				     MAP_PRIVATE |MAP_ANONYMOUS,
				     -1, 0);

	if (chunk == (void *) -1) {
		qa_debug("%s: could not alloc chunk\n", __func__);
		qa_mem->chk_alloc_error++;
		return NULL;
	}

	chunk->limit = (void *) chunk + qa_mem->chk_size;

	/* statistics */
	chunk->count = 0;

	return chunk;
}

/* TODO: better error handling */
static inline void qa_add_chunk(qa_mem_t *qa_mem)
{
	qa_debug("%s: adding new chunk\n", __func__);

	/* Take the saved one if any */
	if (qa_mem->saved) {
		qa_mem->current = qa_mem->saved;
		qa_mem->saved = NULL;
	/* Else alloc a new one */
	} else {
		qa_mem->current = qa_init_chunk(qa_mem);
		qa_mem->chk_count++;
		qa_mem->chk_total_count++;
	}
	qa_mem->next_free = qa_mem->current->content;

	qa_print_chunk(qa_mem->current);
}

/* TODO: better error handling */
static inline void qa_free_chunk(qa_mem_t *qa_mem, qa_mem_chunk_t *chunk)
{
	qa_debug("%s: removing chunk %p\n", __func__, chunk);

	qa_print_chunk(chunk);

	/* mummap the chunk (size = chunk_end - chunk) */
	munmap(chunk, (chunk->limit - (caddr_t)chunk));
	qa_mem->chk_count--;
}


/* Public functions */

/*
 * qa_set_size:
 *  Change chunk size for the chunk to be allocated.
 *  If we get 0 for chunk_size, we take the default value.
 */
static inline void qa_set_size(qa_mem_t *qa_mem, size_t chunk_size)
{
	if (chunk_size)
		qa_mem->chk_size = chunk_size;
	else
		qa_mem->chk_size = QA_MEM_CHUNK_SIZE;

	/* Do not keep a saved chunk with different size */
	if (qa_mem->saved) {
		qa_free_chunk(qa_mem, qa_mem->saved);
		qa_mem->saved = NULL;
	}
}

/*
 * qa_init:
 *  Initialize the qa_mem structure.
 *  /!\ qa_mem must be allocated when we get it here.
 */
static inline void qa_init(qa_mem_t *qa_mem, size_t chunk_size)
{
	qa_debug("%s: initialize a new queue_allocator %p, with chunk_size %d\n",
		 __func__, qa_mem,
		 chunk_size ? chunk_size : QA_MEM_CHUNK_SIZE);

	/* statistics */
	qa_mem->chk_count = 0;
	qa_mem->chk_alloc_error = 0;
	qa_mem->chk_total_count = 0;
	qa_mem->obj_count = 0;
	qa_mem->obj_malloc_count = 0;
	qa_mem->obj_total_count = 0;
	qa_mem->obj_ignored_free = 0;

	/* set default size */
	qa_set_size(qa_mem, chunk_size);

	/* no saved chunk at start */
	qa_mem->saved = NULL;

	/* add a chunk in advance */
	qa_add_chunk(qa_mem);
}

/*
 * qa_alloc
 *  Allocate some room in given qa_mem structure last page, allocate a new chunk
 *  if more room is needed, eventually fallback to malloc is the option is set
 *  (for big objects only).
 */
#define QA_ZERO_MEM 0x1
static inline void * qa_alloc(qa_mem_t *qa_mem, size_t size, short flags)
{
	qa_mem_object_t *object;
	qa_mem_chunk_t *chunk;

	qa_debug("%s: add new object size %d\n", __func__, size);

	/*
	 * align size on 64 bits so that next object will be
	 * naturally aligned
	 */
	size = (size + 8) & ~0x7UL;

	/* If the size is bigger than a QA_MEM_CHUNK_SIZE, fall back to malloc */
	if ((size + sizeof(*object)) > (qa_mem->chk_size - sizeof(qa_mem_chunk_t))) {
#ifdef QA_MALLOC_FALLBACK
		/* TODO: test return value */
		object = malloc(sizeof(*object) + size);
		object->alloc_type = QA_MEM_MALLOC;
		object->chunk = NULL;
#ifdef QA_POISON
		object->size = size;
#endif
		qa_mem->obj_malloc_count++;
		qa_print_object(object);
		return object->data;
#else
		qa_debug("%s: could not alloc such a big size %d (max is %d)\n",
			__func__, size,
			QA_MEM_CHUNK_SIZE - sizeof(*chunk) -  sizeof(*object));
		return NULL;
#endif
	}

	chunk = qa_mem->current;

	/* the current chunk is full, allocate a new one */
	/* TODO: qa_add_chunk may fail... */
	if ((size + sizeof(*object)) > (size_t)(chunk->limit - qa_mem->next_free)) {
		qa_debug("%s: chunk is full with %d objects\n",
			 __func__, chunk->count);
		qa_print_mem(qa_mem);

		qa_add_chunk(qa_mem);
		chunk = qa_mem->current;
	}

	/* allocate and initialize object header */
	object = (qa_mem_object_t *)qa_mem->next_free;
	object->chunk = chunk;
#ifdef QA_POISON
	object->size = size;
#endif
#ifdef QA_MALLOC_FALLBACK
	object->alloc_type = QA_MEM_CHUNK;
#endif

	/* Zero the memory if needed */
	if (flags & QA_ZERO_MEM)
		memset(object->data, 0, size);

	qa_debug("%s: object allocation is successful at %p\n", __func__, object);

	/* statistics */
	chunk->count++;
	qa_mem->obj_count++;
	qa_mem->obj_total_count++;

	/* update next_free pointer */
	qa_mem->next_free += sizeof(*object) + size;

	/* some debug */
	qa_print_chunk(chunk);
	qa_print_object(object);

	return object->data;
}

/*
 * qa_free
 *  Free the given object, free the chunk if the object was the last one.
 */
static inline void qa_free(qa_mem_t *qa_mem, void *ptr)
{
	qa_mem_object_t *object = qa_mem_to_object(ptr);

	qa_debug("%s: object deletion at %p\n", __func__, object);

#ifdef QA_MALLOC_FALLBACK
	if (object->alloc_type == QA_MEM_MALLOC) {
		qa_debug("%s: object %p was malloced, free it\n", __func__, object);
		qa_mem->obj_malloc_count--;
		free(object);
	} else if (object->alloc_type == QA_MEM_CHUNK)
#endif
	{
		qa_mem_chunk_t *chunk = object->chunk;

		/* statistics */
		chunk->count--;
		qa_mem->obj_count--;

#ifdef QA_POISON
		memset(object, 0xa, sizeof(*object) + object->size);
#endif

		if (!chunk->count) {
			qa_debug("%s: chunk %p count is 0\n", __func__, object);

			/* if we are deleting the current one, re-use it */
			if (qa_mem->current == chunk)
				qa_mem->next_free = qa_mem->current->content;
			/* Save the chunk if we don't have one saved already,
			   likely we will need a chunk later */
			else if (!qa_mem->saved) {
				qa_debug("%s: save it in allocator\n", __func__);
				qa_mem->saved = chunk;
			}
			/* Else free it */
			else {
				qa_debug("%s: free it\n", __func__);
				qa_free_chunk(qa_mem, chunk);
			}
		}
	}
#ifdef QA_MALLOC_FALLBACK
	else
		/* should not happen */
		qa_mem->obj_ignored_free++;
#endif
}
#endif /* QUEUE_ALLOC_H */
