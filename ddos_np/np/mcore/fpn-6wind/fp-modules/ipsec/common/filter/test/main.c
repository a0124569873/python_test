/*
 * Copyright(c) 2007 6WIND
 */
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "fpn.h"

#include "filter.h"
#include "test_file.h"
#include "trie.h"

//#define CONFIG_EGTPC 1
//#define CONFIG_CLASSIF 1
#define CONFIG_RFC 1

#ifdef CONFIG_EGTPC
#include "egt-pc/egt-pc.h"
#define trie_init   egtpc_init
#define trie_update egtpc_update
#define trie_final  egtpc_final
#define trie_lookup egtpc_lookup
#endif
#ifdef CONFIG_CLASSIF
#include "classif/classif_ipv4.h"
#define trie_init classif_init
#define trie_update classif_update
#define trie_final classif_final
#define trie_lookup classif_lookup
#endif

#ifdef CONFIG_RFC
#include "rfc/rfc.h"
#define trie_init rfc_init
#define trie_update rfc_update
#define trie_final rfc_final
#define trie_lookup rfc_lookup
#endif

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static void WriteFilter(FILE* writeTo, struct FILTER *wF)
{
	/* write the filter */
	fprintf(writeTo,"id=%d vr=%d %u.%u.%u.%u/%d %u.%u.%u.%u/%d %d/0x%x %d/0x%x %i\n",
			wF->filtId,
			wF->vrfid,
			NIPQUAD(wF->src), wF->src_plen,
			NIPQUAD(wF->dst), wF->dst_plen,
			ntohs(wF->srcport), ntohs(wF->srcport_mask),
			ntohs(wF->dstport), ntohs(wF->dstport_mask),
			wF->ul_proto);
}

int main(int argc, char *argv[])
{
	struct FILTSET *filtset;

	void *ctx;
	int match;
	uint32_t id = 0;
	uint32_t i;

	uint32_t ip_dst, ip_src;
	uint16_t sport, dport;
	uint8_t ip_p;

	uint32_t memsize = 32 << 20;
	void * memstart = malloc(memsize);

	filtset = malloc(sizeof(struct FILTSET));

	if (filtset == 0) {
		printf("caouldnt allocate filter set\n");
		exit(1);
	}

	if (argc !=2 && argc != 3) {
		printf("usage:%s <filename>\n", argv[0]);
		exit(1);
	}

	if (LoadFilters_from_file(argv[1], filtset, MAXFILTERS) < 0 ) {
		printf("Couldnt load filters\n");
		exit (1);
	}

#if 0
	for (i = 0; i < filtset->numFilters; i++)
		WriteFilter(stdout, &filtset->filtArr[i]);
#endif

	ctx = trie_init(memstart, memsize);
	for (i = 0; i < filtset->numFilters; i++)
		(void)trie_update(&filtset->filtArr[i], ctx);
	(void)trie_final(ctx);
#ifdef CONFIG_EGTPC
	egtpc_pool_left(ctx);
#endif

	if (argc == 3) {
		FILE *fpt = fopen(argv[2], "r");
		uint32_t rule_id = 0;
		int header[5];
		uint32_t fid = 0;
		int error = 0;
		int verbose = 1;
		int index = 0;

		if (!fpt) exit(1); 

		while(fscanf(fpt,"%u %u %d %d %d %d\n", &header[0], &header[1], &header[3], &header[4], &header[2], &fid) != -1) {
			index++;
			if (verbose > 1) {
				uint32_t src, dst;
				src = htonl(header[0]);
				dst = htonl(header[1]);
				printf("Looking for %u.%u.%u.%u -> %u.%u.%u.%u %d (%d,%d) expecting rule %d\n",
						NIPQUAD(src),
						NIPQUAD(dst),
						header[2],
						header[3],
						header[4], fid);

			}
			match = trie_lookup(ctx, htonl((uint32_t)header[0]), htonl((uint32_t)header[1]), (uint8_t)header[2], htons((uint16_t)header[3]), htons((uint16_t)header[4]), 0, &rule_id);
			if (match != 0) {
				if (verbose) printf("No rule matches packet %d\n", index);
				error++;
			}  else if(rule_id != fid-1) {
				if (verbose) printf("Match rule %d, should be %d\n", rule_id, fid-1);
				error++;
			}
			if (error) exit(1);

		}
		if (error) printf("Match fails (%d errors)\n", error);
		else printf("Match OK (nb=%d)\n",index);
	} else {
		//
		//ip_src= htonl(0x0a120001);
		//ip_dst= htonl(0x0a140001);
		ip_src= htonl(0x0b000001);
		ip_dst= htonl(0x15000001);

		ip_p = 6;
		sport = htons(2100);
		dport = htons(1000);

		printf("Looking %u.%u.%u.%u -> %u.%u.%u.%u proto=%d sport=%d dport=%d \n",
				NIPQUAD(ip_src), NIPQUAD(ip_dst), ip_p, ntohs(sport), ntohs(dport));
		match = trie_lookup(ctx, ip_src, ip_dst, ip_p, sport, dport, 0, &id);

		if (match==0) {
			printf("Match id = %u\n", id);
			WriteFilter(stdout, &(filtset->filtArr[id]));
		} else
			printf("no match\n");

	}
	return 0;
}
