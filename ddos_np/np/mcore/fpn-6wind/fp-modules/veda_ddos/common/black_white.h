#ifndef __BLACK_WHITE_H__
#define __BLACK_WHITE_H__
#include "ddos_gc.h"
#define BLACK_WHITE_TABLE    (1 << 20)
#define BLACK_WHITE_NUM    (1 << 4)
#define TMP_BLACK_WHITE_TABLE    (1 << 20)

enum black_white_type {
	WHITE_TYPE,
	BLACK_TYPE,
};

struct black_white {
	uint32_t srcip;
	uint32_t dstip;
	uint16_t dport;
	enum black_white_type type;
}__attribute__((packed));


struct black_white_node {
    struct ad_free_obj gc;
	struct black_white  black_white;
	struct black_white_node *next;
}__attribute__((packed));

struct black_white_table {
	struct black_white_node *next;
}__attribute__((packed));

#endif /* __BLACK_WHITE_H__ */