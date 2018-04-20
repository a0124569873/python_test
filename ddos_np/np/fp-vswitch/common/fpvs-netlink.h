/*
 * Copyright (C) 2014 6WIND, All rights reserved.
 */
/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _FPVS_NETLINK_H_
#define _FPVS_NETLINK_H_

struct nlattr {
	uint16_t nla_len;
	uint16_t nla_type;
};
#define NLA_ALIGNTO             4
#define NLA_ALIGN(len)          (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN              ((int) NLA_ALIGN(sizeof(struct nlattr)))

#define NL_ATTR_FOR_EACH(ITER, LEFT, ATTRS, ATTRS_LEN)			\
	for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);			\
		nl_attr_is_valid(ITER, LEFT);				\
		(LEFT) -= NLA_ALIGN((ITER)->nla_len), (ITER) = nl_attr_next(ITER))

/* This macro does not check for attributes with bad lengths.  It should only
 * be used with messages from trusted sources or with messages that have
 * already been validated (e.g. with NL_ATTR_FOR_EACH).  */
#define NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, ATTRS, ATTRS_LEN)		\
	for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);			\
		(LEFT) > 0;						\
		(LEFT) -= NLA_ALIGN((ITER)->nla_len), (ITER) = nl_attr_next(ITER))

#define NL_POLICY_FOR(TYPE)						\
	.type = NL_A_UNSPEC, .min_len = sizeof(TYPE), .max_len = sizeof(TYPE)

#define NL_NESTED_FOR_EACH(ITER, LEFT, A)                               \
	NL_ATTR_FOR_EACH(ITER, LEFT, nl_attr_get(A), nl_attr_get_size(A))

/* temporary until we can remove */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(ARRAY) (sizeof ARRAY / sizeof *ARRAY)
#endif

#define NL_ATTR_GET_AS(NLA, TYPE) \
	(*(TYPE*) (NLA+1))

enum nl_attr_type
{
	NL_A_NO_ATTR = 0,
	NL_A_UNSPEC,
	NL_A_U8,
	NL_A_U16,
	NL_A_BE16 = NL_A_U16,
	NL_A_U32,
	NL_A_BE32 = NL_A_U32,
	NL_A_U64,
	NL_A_BE64 = NL_A_U64,
	NL_A_STRING,
	NL_A_FLAG,
	NL_A_NESTED,
	N_NL_ATTR_TYPES
};

#define NLA_F_NESTED        (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK       ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

/* Netlink attribute parsing. */
/* Netlink attribute iteration. */
static inline struct nlattr *
nl_attr_next(const struct nlattr *nla)
{
	return (void *) ((uint8_t *) nla + NLA_ALIGN(nla->nla_len));
}

static inline int
nl_attr_is_valid(const struct nlattr *nla, size_t maxlen)
{
	return (maxlen >= sizeof *nla
		&& nla->nla_len >= sizeof *nla
		&& (unsigned)NLA_ALIGN(nla->nla_len) <= maxlen);
}

/* Netlink attribute iteration. */
static inline int
nl_attr_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

/* Returns the first byte in the payload of attribute 'nla'. */
static inline const void *
nl_attr_get(const struct nlattr *nla)
{
	FPN_ASSERT(nla->nla_len >= NLA_HDRLEN);
	return nla + 1;
}

static inline size_t
nl_attr_get_size(const struct nlattr *nla)
{
	return nla->nla_len - NLA_HDRLEN;
}

/* Asserts that 'nla''s payload is at least 'size' bytes long, and returns the
 *  * first byte of the payload. */
static inline const void *
nl_attr_get_unspec(const struct nlattr *nla, size_t size)
{
	FPN_ASSERT(nla->nla_len >= NLA_HDRLEN + size);
	return nla + 1;
}

/* Returns the 8-bit value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 1 byte long. */
static inline uint8_t
nl_attr_get_u8(const struct nlattr *nla)
{
	return NL_ATTR_GET_AS(nla, uint8_t);
}

/* Returns the 16-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 2 bytes long. */
static inline uint16_t
nl_attr_get_u16(const struct nlattr *nla)
{
	return NL_ATTR_GET_AS(nla, uint16_t);
}

/* Returns the 32-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long. */
static inline uint32_t
nl_attr_get_u32(const struct nlattr *nla)
{
	return NL_ATTR_GET_AS(nla, uint32_t);
}

/* Returns the 64-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 8 bytes long. */
static inline uint64_t
nl_attr_get_u64(const struct nlattr *nla)
{
	return NL_ATTR_GET_AS(nla, uint64_t);
}

/* Returns the null-terminated string value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload contains a null-terminated string. */
static inline const char *
nl_attr_get_string(const struct nlattr *nla)
{
	FPN_ASSERT(nla->nla_len > NLA_HDRLEN);
	FPN_ASSERT(memchr(nl_attr_get(nla), '\0', nla->nla_len - NLA_HDRLEN) != NULL);
	return nl_attr_get(nla);
}

#endif /* _FPVS_NETLINK_H_ */
