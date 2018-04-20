#ifndef __DDOS_HASH_H__
#define __DDOS_HASH_H__

#define DPDK_JHASH_GOLDEN_RATIO      0xdeadbeef
#define rot(x, k) (((x) << (k)) | ((x) >> (32-(k))))

#define IP_HASH(v1) ({ \
  uint32_t a = (v1) - DPDK_JHASH_GOLDEN_RATIO; \
  uint32_t b = (v1) + DPDK_JHASH_GOLDEN_RATIO; \
  { \
    a ^= b; a -= rot(b, 11); \
  } \
  a; \
})

#define TUPLE_HASH(v1, v2, v3) ({ \
  uint32_t a = (v1) + DPDK_JHASH_GOLDEN_RATIO; \
  uint32_t b = (v2) + DPDK_JHASH_GOLDEN_RATIO; \
  uint32_t c = (v3) + DPDK_JHASH_GOLDEN_RATIO; \
  { \
    c ^= b; c -= rot(b, 14); \
    a ^= c; a -= rot(c, 11); \
    b ^= a; b -= rot(a, 25); \
    c ^= b; c -= rot(b, 16); \
    a ^= c; a -= rot(c, 4);  \
    b ^= a; b -= rot(a, 14); \
    c ^= b; c -= rot(b, 24); \
  } \
  c; \
})

#define TUPLE_HASH_TABLE_INDEX(src, dst, dport, size) (TUPLE_HASH(src, dst, dport)&(size - 1))
#define IP_HASH_TABLE_INDEX(src, size) (IP_HASH(src)&(size - 1))

/*
*
*  SEARCH_HASH_TABLE can add/del node from list
*  FAST_SEARCH_HASH_TABLE can only modify node self
*
*/
#define FAST_SEARCH_HASH_TABLE(table, hash, el, cons) ({ \
  int index = hash; \
  el = table[index].next; \
  while(el != NULL && !(cons)) { \
    el = el->next; \
  } \
  el != NULL; \
})

#define SEARCH_HASH_TABLE(table, hash, el, cons) ({ \
  int index = hash; \
  el = &table[index].next; \
  while(*el != NULL && !(cons)) { \
    el = &(*el)->next; \
  } \
  *el != NULL; \
})

#define FASAT_FOREACH_HASH_TABLE(table, el, size, block) { \
  int _i = 0; \
  for(; _i < size; _i ++) { \
     typeof(table[_i].next) el = table[_i].next; \
    if (!el) { \
      continue; \
    } \
    while(!!el) { \
        do{block}while(0); \
        el = el->next; \
    } \
  } \
}

#define FOREACH_HASH_TABLE(table, el, size, block) { \
  int _i = 0; \
  for(; _i < size; _i ++) { \
     typeof(table[_i].next) *el = &table[_i].next; \
     typeof(table[_i].next) __tmp = *el; \
    if (!__tmp) { \
      continue; \
    } \
    while(!!__tmp) { \
        do{block}while(0); \
        if (__tmp == *el)el = &__tmp->next; \
        __tmp = *el; \
    } \
  } \
}

//
#define SEARCH_HASH_ARRAY(ar, size, _keys, el, cons) ({ \
  unsigned int mask = size - 1; \
  int __k = (_keys)&mask; \
  int ok = 1; \
  typeof(el) _tmp = ar + __k; \
  el = _tmp; \
  while(!(cons)) { \
    __k = (__k+1)&mask; \
    el = ar + __k; \
    if (el == _tmp) { \
      ok = 0; \
      break; \
    } \
  } \
  ok; \
})

#endif /* __DDOS_HASH_H__ */