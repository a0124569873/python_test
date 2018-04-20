/*
 * Copyright  2013 6WIND S.A.
 */

/**
 * Name hash specific header
 *
 */

#ifndef _HASH_NAME_H
#define _HASH_NAME_H

static inline int ng_hash_name(const char * name, ng_ID_t nodeid,
				   u_int32_t name_hash_size)
{
	u_int32_t h = 5381;
	const u_char *c;

	for (c = (const u_char*)(name); *c; c++)
		h = ((h << 5) + h) + *c;
	h += nodeid;
	return h & (name_hash_size - 1);
}

#endif /* _HASH_NAME_H */
