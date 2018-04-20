/*
 * Copyright 6WIND 2007
 */
#ifndef _CLASSIF_IPV4_H_
#define _CLASSIF_IPV4_H_ 1

#include "classifier.h"

#define NBFIELDS 3 /* dst, src, proto */
static int ipv4_routing_fields[] = { 32, 32, 8 };

void *classif_init(void *memstart, uint32_t size)
{
	/* FIXME
	 * compute nSixNode & nUserData using size value
	 * define pFunc, pFuncValid to order rules and
	 * to match port range.
	 */
	funcCompare compare = NULL;
	funcValid valid = NULL;

	if (initClassifier((char *)memstart, size, NBFIELDS, ipv4_routing_fields, compare, valid) < 0)
		return 0;
	return (void *)memstart;
}

static inline int classif_update(struct FILTER *user_filter, void *user_ctx)
{
	RuleValue_t ruleDefinition[NBFIELDS];
	ruleDefinition[0].m_pData = &user_filter->dst;
	ruleDefinition[0].m_nPrefixLength = user_filter->dst_plen;
	ruleDefinition[1].m_pData = &user_filter->src;
	ruleDefinition[1].m_nPrefixLength = user_filter->src_plen;
	ruleDefinition[2].m_pData = &user_filter->ul_proto;
	if (user_filter->ul_proto == FILTER_ULPROTO_ANY)
		ruleDefinition[2].m_nPrefixLength = 0;
	else
		ruleDefinition[2].m_nPrefixLength = 8;
	addRule((SixClassifier*)user_ctx, ruleDefinition, user_filter->filtId);
	return 0;
}

#define classif_final(x) 0

static inline int classif_lookup(void *user_ctx,
		uint32_t src, uint32_t dst, uint8_t proto,
		__attribute__ ((unused)) uint16_t sport,
		__attribute__ ((unused)) uint16_t dport,
		__attribute__ ((unused)) uint16_t vrfid,
		uint32_t *index)
{
	void *Packet[NBFIELDS];

	if (unlikely(user_ctx == 0))
		return -1;

	Packet[0] = (void *)&dst;
	Packet[1] = (void *)&src;
	Packet[2] = (void *)&proto;

	*index = 0;
	match_fields(Packet, (SixClassifier*)user_ctx, index);
	if (index != 0)
		return 0;
	return -1;
}

#endif
