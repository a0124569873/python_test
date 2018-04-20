/*
 * Copyright(c) 2007 6WIND
 */
#ifndef _TRIE_H_
#define _TRIE_H_

void* trie_init(void *memstart, uint32_t size);
int trie_update(struct FILTER *user_filter, void *user_ctx);
int trie_final(void *user_ctx);

/* static inline int trie_lookup(uint64_t ctx,
   			uint32_t src, uint32_t dst, uint8_t proto,
			uint16_t sport, uint16_t dport, uint16_t vrfid,
			uint32_t *index) */
#endif
