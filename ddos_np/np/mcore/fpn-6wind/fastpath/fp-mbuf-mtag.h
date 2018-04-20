/*
 * Copyright(c) 2007 6WIND
 *
 * mbuf mtag interface
 */
#ifndef __FP_MBUF_MTAG_H__
#define	__FP_MBUF_MTAG_H__

/*
 * Browse every mtags in a packet 'm'. The arguments 'i' and 'j' are
 * integers defined by user of the macro, that are used
 * internally. 'mtag' is a struct m_tag * that is assigned to the
 * current browsed m_tag.
 */
#define M_TAG_FOREACH(m, i, j, mtag)					\
	for (i = 0; i < M_TAG_HASH_SIZE; i++)				\
		for (j = i, mtag = &m_priv(m)->m_tag[j];		\
		     j != -1 && mtag->id != -1;				\
		     j = mtag->idx_next, mtag = &m_priv(m)->m_tag[j])


/*
 * Initialize the nb of tags associated with an mbuf. Called when
 * initializing mbuf. Just set the mark_count to -1. We will do the
 * real initialization when adding the first mtag.
 */
static inline void
m_tag_reset(struct mbuf *m)
{
#ifdef CONFIG_MCORE_M_TAG
	/* mark mtag as non-initialized */
	m_priv(m)->m_tag_count = -1;

	/* real init will be done if we add the mtag */
	/*
	 *	m_priv(m)->m_tag_count = 0;
	 *	for (i=0; i<M_TAG_HASH_SIZE; i++) {
	 *		m_priv(m)->m_tag[i].id = -1;
	 *	}
	 */
#endif
}

/* initialize the m_tag module, called during fast path init */
void m_tag_init(void);

/* Return a uniq number for a tag type value. Return a negative value
 * on error. If the tag already exist, do nothing and return the
 * registered id. */
#ifdef CONFIG_MCORE_M_TAG
int32_t m_tag_type_register(const char * name);
#else
static inline int32_t m_tag_type_register(__attribute__((unused)) const char * name)
{
	return -1;
}
#endif


/* dump type table */
void m_tag_type_dump(void);

/* return a tag type associated to this name, and < 0 on error */
int32_t m_tag_type_find_by_name(const char * name);

/* return a tag name associated to a type, and NULL if not used */
const char *m_tag_name_find_by_type(int32_t type);

/* get the number of mtag attached to this mbuf */
static inline int m_tag_get_count(struct mbuf *m)
{
	if (m_priv(m)->m_tag_count <= 0)
		return 0;
	return m_priv(m)->m_tag_count;
}

/* add a tag in mbuf, if the tag already exists, overrides the
 * value. */
static inline int
m_tag_add(struct mbuf *m, int32_t type, uint32_t data)
{
#ifdef CONFIG_MCORE_M_TAG
	int i;
	int prev;

	/* do the initialization if needed */
	if (unlikely(m_priv(m)->m_tag_count == -1)) {
		m_priv(m)->m_tag_count = 0;
		for (i=0; i<M_TAG_TABLE_SIZE; i++) {
			FPN_TRACK();
			m_priv(m)->m_tag[i].id = -1;
		}
	}

	i = type & M_TAG_HASH_MASK;
	/* common (fast) case */
	if (likely(m_priv(m)->m_tag[i].id == -1)) {
		m_priv(m)->m_tag[i].id = type;
		m_priv(m)->m_tag[i].idx_next = -1;
		m_priv(m)->m_tag[i].val = data;
		m_priv(m)->m_tag_count ++;
		return 0;
	}

	/* just modify the value */
	if (likely(m_priv(m)->m_tag[i].id == type)) {
		m_priv(m)->m_tag[i].val = data;
		return 0;
	}

	/* find the end of the list, if the tag already exists,
	 * override value */
	for (prev = i, i = m_priv(m)->m_tag[prev].idx_next;
	     i != -1;
	     prev = i, i = m_priv(m)->m_tag[prev].idx_next) {
		FPN_TRACK();
		if (m_priv(m)->m_tag[i].id == type) {
			m_priv(m)->m_tag[i].val = data;
			return 0;
		}
	}

	/* find a free entry */
	for (i = M_TAG_HASH_SIZE; i < M_TAG_TABLE_SIZE; i++) {
		FPN_TRACK();
		if (m_priv(m)->m_tag[i].id == -1) {
			m_priv(m)->m_tag[prev].idx_next = i;
			m_priv(m)->m_tag[i].id = type;
			m_priv(m)->m_tag[i].idx_next = -1;
			m_priv(m)->m_tag[i].val = data;
			m_priv(m)->m_tag_count ++;
			return 0;
		}
	}

#endif
	/* no free entry found */
	return -1;
}

/* Find a tag of registered with "type". If tag exists, return 0 and
 * fill *val, else return -1. */
static inline int
m_tag_get(struct mbuf *m, int32_t type, uint32_t *val)
{
#ifdef CONFIG_MCORE_M_TAG
	int i;

	if (unlikely(m_priv(m)->m_tag_count <= 0))
		return -1;

	/* browse the list for this type and try to match a m_tag */
	i = type & M_TAG_HASH_MASK;
	if (m_priv(m)->m_tag[i].id == -1)
		return -1;

	do {
		if (likely(m_priv(m)->m_tag[i].id == type)) {
			*val = m_priv(m)->m_tag[i].val;
			return 0;
		}
		i = m_priv(m)->m_tag[i].idx_next;
	} while (i != -1);

#endif
	return -1;
}

/* Inform if packet has a tag. */
static inline int
m_tag_is_empty(struct mbuf *m)
{
#ifdef CONFIG_MCORE_M_TAG
	if (m_priv(m)->m_tag_count <= 0)
		return 1;
	return 0;
#else
	return 1;
#endif
}

/* Delete the tag. Return 0 on sucess. */
static inline int
m_tag_del(struct mbuf *m, int32_t type)
{
#ifdef CONFIG_MCORE_M_TAG
	struct m_tag *m_tag;
	int i;

	if (unlikely(m_priv(m)->m_tag_count <= 0))
		return -1;

	i = type & M_TAG_HASH_MASK;
	m_tag = &m_priv(m)->m_tag[i];


	/* browse the list for this type and try to match a m_tag */
	do {
		FPN_TRACK();

		if (likely(type == m_tag->id)) {
			int next = m_tag->idx_next;

			if (likely(next == -1)) {
				m_tag->id = -1;
			}
			else {
				m_tag->id = m_priv(m)->m_tag[next].id;
				m_priv(m)->m_tag[next].id = -1;
				m_tag->idx_next = m_priv(m)->m_tag[next].idx_next;
				m_tag->val = m_priv(m)->m_tag[next].val;
			}
			m_priv(m)->m_tag_count --;
			return 0;
		}

		i = m_tag->idx_next;
		m_tag = &m_priv(m)->m_tag[i];

	} while (i != -1);
#endif
	return -1;
}

#endif /* __FP_MBUF_MTAG_H__ */
