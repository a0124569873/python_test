#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#ifdef PRINT_STAT
#include <math.h>
#endif

#include "fpn.h"
#include "rfc.h"
#include "dheap.h"

#include <sys/time.h>

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static FILE *fpr;       // ruleset file
static FILE *fpt;       // test trace file
static int verbose = 0;
static struct timeval tv_start, tv_end;

static inline uint64_t GetTickCount()
{   
    uint64_t x;
#if defined(__GNUC__) && defined(__i386)
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
#else
	x = 0;
#endif
    return x;
}

static int loadrule(FILE *fp, struct pc_rule *rule){

	int tmp;
	unsigned sip1, sip2, sip3, sip4, siplen;
	unsigned dip1, dip2, dip3, dip4, diplen;
	unsigned proto, protomask;
	int i = 0;
	int nb;

	while(1){

		nb = fscanf(fp,"@%d.%d.%d.%d/%d %d.%d.%d.%d/%d %d : %d %d : %d %x/%x\n",
				&sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen,
				&rule[i].field[3].low, &rule[i].field[3].high, &rule[i].field[4].low, &rule[i].field[4].high,
				&proto, &protomask);
		if (nb == -1)
			break;
		if (nb != 16) {
			printf("error: fscanf reads %d\n", nb);
			break;
		}
		if(siplen == 0){
			rule[i].field[0].low = 0;
			rule[i].field[0].high = 0xFFFFFFFF;
		}else if(siplen > 0 && siplen <= 8){
			tmp = sip1<<24;
			rule[i].field[0].low = tmp;
			rule[i].field[0].high = rule[i].field[0].low + (1<<(32-siplen)) - 1;
		}else if(siplen > 8 && siplen <= 16){
			tmp = sip1<<24; tmp += sip2<<16;
			rule[i].field[0].low = tmp; 	
			rule[i].field[0].high = rule[i].field[0].low + (1<<(32-siplen)) - 1;	
		}else if(siplen > 16 && siplen <= 24){
			tmp = sip1<<24; tmp += sip2<<16; tmp +=sip3<<8;
			rule[i].field[0].low = tmp; 	
			rule[i].field[0].high = rule[i].field[0].low + (1<<(32-siplen)) - 1;			
		}else if(siplen > 24 && siplen <= 32){
			tmp = sip1<<24; tmp += sip2<<16; tmp += sip3<<8; tmp += sip4;
			rule[i].field[0].low = tmp;
			rule[i].field[0].high = rule[i].field[0].low + (1<<(32-siplen)) - 1;	
		}else{
			printf("Src IP length exceeds 32\n");
			return 0;
		}
		if(diplen == 0){
			rule[i].field[1].low = 0;
			rule[i].field[1].high = 0xFFFFFFFF;
		}else if(diplen > 0 && diplen <= 8){
			tmp = dip1<<24;
			rule[i].field[1].low = tmp;
			rule[i].field[1].high = rule[i].field[1].low + (1<<(32-diplen)) - 1;
		}else if(diplen > 8 && diplen <= 16){
			tmp = dip1<<24; tmp +=dip2<<16;
			rule[i].field[1].low = tmp; 	
			rule[i].field[1].high = rule[i].field[1].low + (1<<(32-diplen)) - 1;	
		}else if(diplen > 16 && diplen <= 24){
			tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8;
			rule[i].field[1].low = tmp; 	
			rule[i].field[1].high = rule[i].field[1].low + (1<<(32-diplen)) - 1;			
		}else if(diplen > 24 && diplen <= 32){
			tmp = dip1<<24; tmp +=dip2<<16; tmp+=dip3<<8; tmp +=dip4;
			rule[i].field[1].low = tmp; 	
			rule[i].field[1].high = rule[i].field[1].low + (1<<(32-diplen)) - 1;	
		}else{
			printf("Dest IP length exceeds 32\n");
			return 0;
		}
		if(protomask == 0xFF){
#if 0
			rule[i].field[2].low = proto;
			rule[i].field[2].high = proto;
#else
			rule[i].field[2].low =
			rule[i].field[2].high = rfc_make_vrproto(0, rfc_proto_compress(proto));
#endif
		}else if(protomask == 0){
#if 0
			rule[i].field[2].low = 0;
			rule[i].field[2].high = 0xFFFF;
#else
			rule[i].field[2].low = rfc_make_vrproto(0, 0);
			rule[i].field[2].high = rfc_make_vrproto(0, RFC_5BIT_PROTO_MAX);
#endif
		}else{
			printf("Protocol mask error (%d)\n", protomask);
			return 0;
		}
		rule[i].filtId = i;
		rule[i].cost = 0;
		i++;
	}

	return i;
}

static void parseargs(int argc, char *argv[]) {
	int	c;
	int ok = 1;
	while ((c = getopt(argc, argv, "vr:t:h")) != -1) {
		switch (c) {
			case 'r':
				fpr = fopen(optarg, "r");
				break;
			case 't':
				fpt = fopen(optarg, "r");
				break;
			case 'h':
				printf("rfc [-r ruleset][-t trace][-h]\n");
				exit(1);
				break;
			case 'v':
				verbose++;
				break;
			default:
				ok = 0;
		}
	}

	if(fpr == NULL){
		printf("can't open ruleset file\n");
		ok = 0;
	}
	if (!ok || optind < argc) {
		fprintf (stderr, "rfc [-r ruleset][-t trace][-h]\n");
		exit(1);
	}
}

int main(int argc, char* argv[]){
  int done;
  struct trie_rfc *t;
  void *ctx;

  unsigned char *mem;
  int memsize;
  uint64_t classifyTime;

  memsize = 30 << 20;
  mem = (unsigned char *)malloc(memsize);

  ctx = rfc_init(mem, memsize);

  /* rfc update */
  parseargs(argc, argv);
  t = (struct trie_rfc *)ctx;
  t->numrules = loadrule(fpr, t->rule);

  rfc_final(t);

#ifdef PRINT_STAT
  printf("the number of rules = %d\n", t->numrules);
  printf("trie_rfc: %d\n", (int)sizeof(struct trie_rfc));
  printf("fblocks: %d\n", (int)(t->fb.pc - t->fb.start));
#endif
  //perform packet classification
  if(fpt != NULL){
    done = 1;
    int index = 0;
    uint32_t rule_id = 0;
    int header[MAXDIMENSIONS];
    uint32_t fid;
    int error = 0;
    int match;
	uint64_t lookup_time;
#if 0
    long long t1, t2;

    __asm__ volatile ("RDTSC" : "=A" (t1));
#endif
    gettimeofday(&tv_start, NULL);
	classifyTime = 0;
	/* The values in this file are host order */
    while(fscanf(fpt,"%u %u %d %d %d %d\n", &header[0], &header[1], &header[3], &header[4], &header[2], &fid) != -1) {
      index ++;

    if (verbose) {
	    uint32_t src, dst;
		/* NIPQUAD is using network order */
	    src = htonl(header[0]);
	    dst = htonl(header[1]);
	    printf("Looking for %u.%u.%u.%u -> %u.%u.%u.%u %d (%d,%d) expecting rule %d\n",
			NIPQUAD(src),
			NIPQUAD(dst),
			header[2],
			header[3],
			header[4], fid);

    }

	lookup_time = GetTickCount();
    match = rfc_lookup(t, htonl((uint32_t)header[0]), htonl((uint32_t)header[1]), (uint8_t)header[2], htons((uint16_t)header[3]), htons((uint16_t)header[4]), 0, &rule_id);
	classifyTime+= (GetTickCount() - lookup_time);
    if (match != 0) {
	    if (verbose) printf("No rule matches packet %d\n", index);
	    error++;
    }  else if(rule_id != fid-1) {
	    if (verbose) printf("Match rule %d, should be %d\n", rule_id, fid-1);
	    error++;
    }
    }
	printf("Classify time RFC total %" PRId64 " cycles, %" PRId64 " avg cycles/packet (%d rules, %d packets, %d errors)\n", classifyTime, classifyTime/index, t->numrules, index, error);
    gettimeofday(&tv_end, NULL);
    if (tv_end.tv_usec < tv_start.tv_usec) {
	    tv_end.tv_sec -= 1;
	    tv_end.tv_usec += 1000000;
    }
    printf(" Duration: %d ms\n", (int)((tv_end.tv_sec - tv_start.tv_sec)*1000 + (tv_end.tv_usec - tv_start.tv_usec)/1000));
    if (error == 0)
	    printf("Match OK.\n");
    else
	    printf("Match fails (%d errors)\n", error);
  }
  free(t);
  return 0;
}
