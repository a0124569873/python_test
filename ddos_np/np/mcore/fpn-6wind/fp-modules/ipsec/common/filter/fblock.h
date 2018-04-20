/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _FBLOCK_H_
#define _FBLOCK_H_

struct fblock {
       unsigned char *start;
       unsigned char *end;
       unsigned char *pc;
};

static inline void fblock_init(struct fblock *fb, unsigned char *mem, unsigned int memsize)
{
	fb->start = mem;
	fb->pc = fb->start;
	fb->end = fb->start + memsize;
	memset(mem, 0, memsize);
}

static inline unsigned char *fblock_pop(struct fblock *fb, int len)
{
	unsigned char *p = fb->pc;
	if (fb->pc + len > fb->end)
		return NULL;
	fb->pc += len;
	return p;
}

static inline unsigned char *fblock_push(struct fblock *fb, int len)
{
	if (fb->pc - len < fb->start)
		return NULL;
	fb->pc -= len;
	return fb->pc;
}

#endif

