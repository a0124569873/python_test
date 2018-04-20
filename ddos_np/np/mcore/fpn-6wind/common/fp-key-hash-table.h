#ifndef _KEY_HASH_TABLE_H
#define _KEY_HASH_TABLE_H

#define DEFAUL_ENTRY_DATA_SIZE 12

struct key_hash_entry {
    unsigned int key;
    char data[DEFAUL_ENTRY_DATA_SIZE];
} __attribute__((packed));

typedef struct key_hash_entry * key_hash_table;

#define _jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

static inline unsigned int _hash_entry_hash(unsigned int key, unsigned int left, unsigned int right) {
  unsigned int a = key;
  unsigned int b = left;
  unsigned int c = right;

  _jhash_mix(a, b, c);

  return c % (right - left) + left;
}

static inline int hash_entry_index(key_hash_table table, int size, unsigned int key) {
    int left = 0;
    int right = size -1;
    int entry = size;

    while(right > left) {
        int index = _hash_entry_hash(key, left, right);

        if (table[index].key == 0 || table[index].key == key) {
            entry = index;
            break;
        }

        if (left + right > 2 * index) {
            left = index + 1;
        } else {
            right = index - 1;
        }
    }
    return entry;
}



// 
// @ret == 0: ok; -1: other error: 1: table full
//
static inline int update_hash_entry(key_hash_table table, int size, struct key_hash_entry* entry) {

    int index = -1;

    if (!entry) {
        return -1;
    }
    
    index = hash_entry_index(table, size, entry->key);

    if (index < 0 || index >= size) {
        return index < 0 ? -1 : 1;
    }

    table[index].key = entry->key;

    {
        unsigned long* pl1 = (unsigned long*)table[index].data;
        unsigned long* pl2 = (unsigned long*)entry->data;
        int i = sizeof(entry->data) / sizeof(unsigned long);

        // fast copy
        while (i-- > 0) {
            *pl1++ = *pl2++;
        }

        // copy remains
        i = sizeof(entry->data) % sizeof(unsigned long);
        {
          char* pc1 = (char*)pl1;
          char* pc2 = (char*)pl2;
          while (i-- > 0) {
            *pc1++ = *pc2++;
          }
        }
    }

    return 0;
}


#endif // _KEY_HASH_TABLE_H