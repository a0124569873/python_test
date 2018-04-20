#ifndef __DDOS_GC_H__
#define __DDOS_GC_H__

#include "fpn.h"
#include "fpn-dpdk.h"
#include "fp-log.h"
#include "ddos_hash_table.h"

struct ad_gc_status {
    const char* file;
    const char* func;
    int line_no;
    int64_t size;
    int64_t count;
};

#define GC_STATUS_TABLE_SIZE (1<<10)
extern struct ad_gc_status gc_status_table[GC_STATUS_TABLE_SIZE];

struct ad_free_obj {
    FPN_SLIST_ENTRY(ad_free_obj) next;
    uint64_t timestamp; // for cycles use
    int no;
    int size;
} __attribute__((aligned(8)));

#define AD_ZALLOC(s) ({ \
    void *p = malloc(s); \
    if (p != NULL) { \
        struct ad_gc_status* gs = NULL; \
        bzero(p, s); \
        if (SEARCH_HASH_ARRAY(gc_status_table, GC_STATUS_TABLE_SIZE, __LINE__, gs, gs->line_no == 0 || gs->line_no == __LINE__)) { \
            if (gs->file == NULL) { \
                gs->file = __FILE__; \
                gs->func = __func__; \
                gs->line_no = __LINE__; \
            } \
 \
            gs->size += s; \
            gs->count ++; \
 \
            ((struct ad_free_obj*)p)->no = __LINE__; \
            ((struct ad_free_obj*)p)->size = s; \
        } \
    } \
    p; \
})

#define AD_FREE(a) ({ \
    int s = 0; \
    if (a != NULL) { \
        int key = ((struct ad_free_obj*)a)->no; \
        int size = ((struct ad_free_obj*)a)->size; \
        s = size; \
        struct ad_gc_status* gs = NULL; \
        if (key > 0 && SEARCH_HASH_ARRAY(gc_status_table, GC_STATUS_TABLE_SIZE, key, gs, gs->line_no == key)) { \
            gs->size -= size; \
            gs->count --; \
            if (gs->count <= 0) bzero(gs, sizeof(struct ad_gc_status)); \
        } \
        free(a); \
    } \
    a = NULL; \
    s; \
})

#define AD_FREE_OBJ_TIMESTAMP(m) ((m)->timestamp)

#endif // __DDOS_GC_H__