/*
 * Copyright(c) 2007 6WIND
 */
#include "fpn.h"
#include "fp-includes.h"

#ifndef CONFIG_MCORE_M_TAG
void m_tag_init(void) {}
#else

#define M_TAG_MAX_NB 32 /* max number of registered mtags */
#define M_TAG_NAMESIZE 8

struct m_tag_type_table {
	int used;
	char name[M_TAG_NAMESIZE];
};

static FPN_DEFINE_SHARED(struct m_tag_type_table, m_tag_type_table[M_TAG_MAX_NB]);

#define M_TAG_UNUSED -1

/* initialize the m_tag module, called during fast path init */
void 
m_tag_init(void)
{
	memset(m_tag_type_table, 0, sizeof(m_tag_type_table));
}


/* Return a uniq number for a tag type value. Return a negative value
 * on error. If the tag already exists, do nothing and return the
 * registered id. */
int32_t
m_tag_type_register(const char * name) 
{
	uint32_t i;
	int32_t free_id = -1;

	/* find a free place, and check that the name is uniq */
	for ( i=0; i<M_TAG_MAX_NB; i++) {
		if (m_tag_type_table[i].used == 0 && free_id < 0) {
			free_id = i;
		}
		else if (! strncmp(m_tag_type_table[i].name, name, M_TAG_NAMESIZE)) {
			free_id = i;
			break;
		}
	}

	/* no free place */
	if (free_id < 0) {
		return -1; /* waiting for FP_ENOMEM */
	}

	/* register it */
	m_tag_type_table[free_id].used = 1;
	snprintf(m_tag_type_table[free_id].name, M_TAG_NAMESIZE, "%s", name);
	return free_id;
}

/* return a tag name associated to a type, and NULL if not used */
const char *m_tag_name_find_by_type(int32_t type)
{
	if (type < 0 || type >= M_TAG_MAX_NB)
		return NULL;
	if (!m_tag_type_table[type].used)
		return NULL;

	return m_tag_type_table[type].name;
}

/* return a tag type associated to this name, and < 0 if not found */
int32_t
m_tag_type_find_by_name(const char * name)
{
	uint32_t i;

	/* find a free place, and check that the name is uniq */
	for ( i=0; i<M_TAG_MAX_NB; i++) {
		if ( m_tag_type_table[i].used &&
		     (! strncmp(m_tag_type_table[i].name, name, M_TAG_NAMESIZE)) ) {
			return i;
		}
	}
	
	return -1; /* waiting for FP_ENOENT */
}

/* dump table */
/* it could be a fp-debug command in the future */
void
m_tag_type_dump(void)
{
	uint32_t i;

	/* find a free place, and check that the name is uniq */
	for ( i=0; i<M_TAG_MAX_NB; i++) {
		if (!m_tag_type_table[i].used)
			continue;
		fpn_printf("%.2d: %s\n", i, m_tag_type_table[i].name);
	}
}

#endif

