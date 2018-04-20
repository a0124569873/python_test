/*
 * Copyright(c) 2007 6WIND
 */
/***************************************
   chunk_id  chunk_size  header-field
       0         16       s.ip[15:0]
       1         16       s.ip[31:16]
       2         16       d.ip[15:0]
       3         16       d.ip[31:16]
       4         8        proto
       5         16       s.port
       6         16       d.port
****************************************/
#include "fpn.h"

#ifdef PRINT_STAT
#include <math.h>
#endif
#include "rfc.h"

#include "filter.h"

#ifdef PRINT_STAT
static int size = 0;
static int mem_access = 0;
#define DEBUG 1
#endif

#ifdef DEBUG
#include <stdio.h>
#define ASSERT(x) do { if (!(x)) { \
	printf("fail at %d \n", __LINE__); \
	exit(1); }} while(0)
#define TRACE_RFC(fmt, args...) do {\
	printf("rfc:" fmt "\n", ## args); \
} while (0)
#else
#define ASSERT(x)
#define TRACE_RFC(x...)
#endif

/* protocol compression table */
FPN_DEFINE_SHARED(uint8_t, rfc_protocomptab[256]);
static FPN_DEFINE_SHARED(int, rfc_protocomptab_built) = 0;
static void rfc_protocomptab_build(void);

static inline int *rfc_calloc(struct fblock *fb, int n, int s)
{
	int *p = (int *)fblock_pop(fb, (n * s));
	if (p == NULL)
		return NULL;
	memset(p, 0, (n * s));
	return p;
}

static inline void rfc_free(struct fblock *fb, int n, int s)
{
	(void)fblock_push(fb, (n * s));
}

static int preprocessing_2chunk(struct eq *a, int na, struct eq *b, int nb, struct eq *x, int **p_table, struct trie_rfc *trie){
  int i, j, k, r;
  int current_numrules;
  int *current_rule_list = NULL;
  int current_eq_id;
  int match;

  int pass;
  int p2_size = 0;
  int *tb = NULL;
  struct fblock *fb = &trie->fb;
  unsigned char *fb_start = fb->pc;

  for (pass = 1; pass <=2 ; pass++) {

  current_eq_id = -1;
  current_rule_list = NULL;

  for(i=0; i<na; i++){
    for(j=0; j<nb; j++){
      // get the intersection rule set
      if(a[i].numrules == 0 || b[j].numrules == 0) {
      	current_numrules = 0;
        current_rule_list = NULL;
      } else {

        k=0; r=0;
        current_numrules = 0;
        current_rule_list = NULL;
        while(k < a[i].numrules && r < b[j].numrules){
          if(a[i].rulelist[k] == b[j].rulelist[r]){
            current_numrules ++;
            k++; r++;
          }else if(a[i].rulelist[k] > b[j].rulelist[r]){
            r++;
          }else{
            k++;
          }
        }

	if (current_numrules == 0)
		goto done;
	
        current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
	if (current_rule_list == NULL)
		return -1;
        k=0; r=0;
        current_numrules = 0;
        while(k < a[i].numrules && r < b[j].numrules){
          if(a[i].rulelist[k] == b[j].rulelist[r]){
              current_rule_list[current_numrules] = a[i].rulelist[k];
              current_numrules ++;
              k++; r++;
          }else if(a[i].rulelist[k] > b[j].rulelist[r]){
              r++;
          }else{
              k++;
          }
        }

      }
done:
      /* end intersection */

      //set the equivalence classes
      match = 0;
      for(k=0; k<=current_eq_id; k++){
        if(current_numrules == x[k].numrules){
          match = 1;
          for(r=0; r<current_numrules; r++){
            if(x[k].rulelist[r] != current_rule_list[r]){
              match = 0;
              break;
            }
          }
          if(match == 1){
	    if (pass == 1) {
	       if (p2_size < (i*nb + j))
		    p2_size = i*nb + j;
            } else
               tb[i*nb +j] = k;
            break;
          }
        }
      }
      if(match == 0){
        current_eq_id ++;
        x[current_eq_id].numrules = current_numrules;
        x[current_eq_id].rulelist = current_rule_list;
	/* save first rule id - JMG. */
	if (current_rule_list)
        	x[current_eq_id].first_rule_id = trie->rule[current_rule_list[0]].filtId;

	if (pass == 1) {
	   if (p2_size < (i*nb + j))
	       p2_size = i*nb + j;
	} else
           tb[i*nb +j] = current_eq_id;
      } else {
	/* rule list is not used */
	if (current_rule_list)
		rfc_free(fb, current_numrules, sizeof(int));
	current_rule_list = NULL;
      }
    }
  }

  /* end of pass 1 */
  if (pass == 1) {
	  /* rewind fblock to free all rule lists */
	  fb->pc = fb_start;
	  for (k=0; k <= current_eq_id; k++)
		x[k].numrules = 0;
	  p2_size++;
	  p2_size *= sizeof(int);
	  TRACE_RFC("p2 p2_size = %d\n", p2_size);
	  tb = (int *)fblock_pop(fb, p2_size);
	  if (tb == NULL)
		  return -1;
	  memset(tb, 0, p2_size);
	  *p_table = tb;
  }
  } /* next pass */

  return current_eq_id+1;
}

static int preprocessing_3chunk(struct eq *a, int na, struct eq *b, int nb, struct eq *c, int nc, struct eq *x, int **p_table, struct trie_rfc *trie){
  int i, j, s, k, r, t;
  int current_numrules;
  int *current_rule_list = NULL;
  int current_eq_id;
  int match;

  int pass;
  int p3_size = 0;
  int *tb = NULL;
  struct fblock *fb = &trie->fb;
  unsigned char *fb_start = fb->pc;

  for (pass = 1; pass <=2 ; pass++) {

  current_eq_id = -1;

  for(i=0; i<na; i++){
    for(j=0; j<nb; j++){
      for(s=0; s<nc; s++){

        //get the intersection list
        if(a[i].numrules == 0 || b[j].numrules == 0 || c[s].numrules == 0) {
          current_numrules = 0;
	  current_rule_list = NULL;
        }else{
          k=0; r=0; t=0;
          current_numrules = 0;
          while(k < a[i].numrules && r < b[j].numrules && t < c[s].numrules){
            if(a[i].rulelist[k] == b[j].rulelist[r] && a[i].rulelist[k] == c[s].rulelist[t]){
              current_numrules ++;
              k++; r++; t++;
            }else if(a[i].rulelist[k] <= b[j].rulelist[r] && a[i].rulelist[k] <= c[s].rulelist[t]){
              k++;
            }else if(b[j].rulelist[r] <= a[i].rulelist[k] && b[j].rulelist[r] <= c[s].rulelist[t]){
              r++;
            }else{
              t++;
            }
          }
	  if (current_numrules != 0) {
            current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
	    if (current_rule_list == NULL)
		    return -1;
            k=0; r=0; t=0;
            current_numrules = 0;
            while(k < a[i].numrules && r < b[j].numrules && t < c[s].numrules){
              if(a[i].rulelist[k] == b[j].rulelist[r] && a[i].rulelist[k] == c[s].rulelist[t]){
                current_rule_list[current_numrules] = a[i].rulelist[k];
                current_numrules ++;
                k++; r++; t++;
              }else if(a[i].rulelist[k] <= b[j].rulelist[r] && a[i].rulelist[k] <= c[s].rulelist[t]){
                k++;
              }else if(b[j].rulelist[r] <= a[i].rulelist[k] && b[j].rulelist[r] <= c[s].rulelist[t]){
                r++;
              }else{
                t++;
              }
            }
          }
        }
        //set the equivalent classes
        match = 0;
        for(k=0; k<=current_eq_id; k++){
          if(current_numrules == x[k].numrules){
            match = 1;
            for(r=0; r<current_numrules; r++){
              if(x[k].rulelist[r] != current_rule_list[r]){
                match = 0;
                break;
              }
            }
            if(match == 1){
 	      if (pass == 1) {
	      	if (p3_size < i*nb*nc +j*nc +s)
		      p3_size = i*nb*nc +j*nc +s;
	      } else
                tb[i*nb*nc +j*nc +s] = k;
              break;
            }
          }
        }
        if(match == 0){
          current_eq_id ++;
          x[current_eq_id].numrules = current_numrules;
          x[current_eq_id].rulelist = current_rule_list;
	  /* save first rule id - JMG. */
	  if (current_rule_list)
        	x[current_eq_id].first_rule_id = trie->rule[current_rule_list[0]].filtId;
	  if (pass == 1) {
		  if (p3_size < i*nb*nc +j*nc +s)
			  p3_size = i*nb*nc +j*nc +s;
	  } else
             tb[i*nb*nc +j*nc +s] = current_eq_id;
        } else {
		if (current_rule_list != NULL)
			rfc_free(fb, current_numrules, sizeof(int));
		current_rule_list = NULL;
	}
      }
    }
  }

  /* end of pass 1 */
  if (pass == 1) {
	  /* rewind fblock to free all rule lists */
	  fb->pc = fb_start;
	  for (k=0; k <= current_eq_id; k++)
		  x[k].numrules = 0;
	  p3_size++;
	  p3_size *= sizeof(int);
	  TRACE_RFC("p3 p3_size = %d\n", p3_size);
	  tb = (int *)fblock_pop(fb, p3_size);
	  if (tb == NULL)
		  return -1;
	  memset(tb, 0, p3_size);
	  *p_table = tb;
  }
  } /* next pass */

  return current_eq_id+1;
}

static int preprocessing_phase0(int chunk_id, struct pc_rule *rule, int numrules, struct trie_rfc *t) {

  int i,j,k;
  struct dheap *H;
  int match;
  int current_eq_id;
  unsigned long current_end_point;
  int current_numrules = 0;
  int *current_rule_list = NULL;
  int npoints;
  item cur_min;
  struct fblock *fb = &t->fb;

  H = &t->dheap;
  dheap_reset(H, 2);

  //sort the end points
  if(chunk_id == 0){
    for(i=0; i<numrules; i++){
      //printf("%d --> %d:%d\n", i, rule[i].field[0].low & 0xFFFF, rule[i].field[0].high & 0xFFFF);
      dheap_insert(H, i, rule[i].field[0].low & 0xFFFF);
      dheap_insert(H, numrules+i, rule[i].field[0].high & 0xFFFF);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }else if(chunk_id == 1){
    for(i=0; i<numrules; i++){
      //printf("%d --> %d:%d\n", i, (rule[i].field[0].low >> 16) & 0xFFFF, (rule[i].field[0].high >> 16) & 0xFFFF);
      dheap_insert(H, i, (rule[i].field[0].low >> 16) & 0xFFFF);
      dheap_insert(H, numrules+i, (rule[i].field[0].high >> 16) & 0xFFFF);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }else if(chunk_id == 2){
    for(i=0; i<numrules; i++){
      dheap_insert(H, i, rule[i].field[1].low & 0xFFFF);
      dheap_insert(H, numrules+i, rule[i].field[1].high & 0xFFFF);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }else if(chunk_id == 3){
    for(i=0; i<numrules; i++){
      dheap_insert(H, i, (rule[i].field[1].low >> 16) & 0xFFFF);
      dheap_insert(H, numrules+i, (rule[i].field[1].high >> 16) & 0xFFFF);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }else if(chunk_id == 4){
    for(i=0; i<numrules; i++){
      dheap_insert(H, i, rule[i].field[2].low);
      dheap_insert(H, numrules+i, rule[i].field[2].high);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }else if(chunk_id == 5){
    for(i=0; i<numrules; i++){
      dheap_insert(H, i, rule[i].field[3].low);
      dheap_insert(H, numrules+i, rule[i].field[3].high);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }else{
    for(i=0; i<numrules; i++){
      dheap_insert(H, i, rule[i].field[4].low);
      dheap_insert(H, numrules+i, rule[i].field[4].high);
    }
    dheap_insert(H, 2*numrules, 0);
    dheap_insert(H, 2*numrules+1, 65535);
  }

  //assign equivalence classes
  current_eq_id = -1;
  current_end_point = 0;
  npoints = 1;

  while(1) {

    cur_min = dheap_findmin(H);

    if (cur_min == -1)
	    break;

    while (cur_min != -1 && current_end_point == dheap_key(H, cur_min)) {
      dheap_deletemin(H);
      cur_min = dheap_findmin(H);
    }

    //printf("current end point %d\n", current_end_point);
    current_numrules = 0;
    k = 0;
    if(chunk_id == 0){
      for(i=0; i<numrules; i++){
        if((rule[i].field[0].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[0].high & 0xFFFF) >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if((rule[i].field[0].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[0].high & 0xFFFF) >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 1){
      for(i=0; i<numrules; i++){
        if(((rule[i].field[0].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[0].high >> 16) & 0xFFFF) >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(((rule[i].field[0].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[0].high >> 16) & 0xFFFF) >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 2){
      for(i=0; i<numrules; i++){
        if((rule[i].field[1].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[1].high & 0xFFFF) >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if((rule[i].field[1].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[1].high & 0xFFFF) >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 3){
      for(i=0; i<numrules; i++){
        if(((rule[i].field[1].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[1].high >> 16) & 0xFFFF) >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(((rule[i].field[1].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[1].high >> 16) & 0xFFFF) >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 4){
      for(i=0; i<numrules; i++){
        if(rule[i].field[2].low <= current_end_point &&
           rule[i].field[2].high >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(rule[i].field[2].low <= current_end_point &&
           rule[i].field[2].high >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 5){
      for(i=0; i<numrules; i++){
        if(rule[i].field[3].low <= current_end_point &&
           rule[i].field[3].high >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(rule[i].field[3].low <= current_end_point &&
           rule[i].field[3].high >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else{
      for(i=0; i<numrules; i++){
        if(rule[i].field[4].low <= current_end_point &&
           rule[i].field[4].high >= current_end_point){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(rule[i].field[4].low <= current_end_point &&
           rule[i].field[4].high >= current_end_point){
          current_rule_list[k] = i;
          k++;
        }
      }
    }

done:
    //printf("current num rules %d\n", current_numrules);

    match = 0;
    for(i=0; i<=current_eq_id; i++){
      if(current_numrules == t->p0_eq[chunk_id][i].numrules){
        match = 1;
        for(j=0; j<current_numrules; j++){
          if(t->p0_eq[chunk_id][i].rulelist[j] != current_rule_list[j]){
            match = 0;
            break;
          }
        }
        if(match == 1){
	  ASSERT(current_end_point < 65536);
          t->p0_table[chunk_id][current_end_point] = i;
          break;
        }
      }
    }
    if(match == 0){
      current_eq_id ++;
      ASSERT(current_eq_id < 2*MAXRULES);
      ASSERT(current_end_point < 65536);
      t->p0_eq[chunk_id][current_eq_id].numrules = current_numrules;
      t->p0_eq[chunk_id][current_eq_id].rulelist = current_rule_list;
      /* save first rule id - JMG. */
      if (current_rule_list)
         t->p0_eq[chunk_id][current_eq_id].first_rule_id = t->rule[current_rule_list[0]].filtId;
      t->p0_table[chunk_id][current_end_point] = current_eq_id;
    }

    /* Stop as soon as H is empty -JMG. */
    if (cur_min == -1)
	    break;

    current_numrules = 0;
    k = 0;
    if(chunk_id == 0){
      for(i=0; i<numrules; i++){
        if((rule[i].field[0].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[0].high & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if((rule[i].field[0].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[0].high & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 1){
      for(i=0; i<numrules; i++){
        if(((rule[i].field[0].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[0].high >> 16) & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(((rule[i].field[0].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[0].high >> 16) & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 2){
      for(i=0; i<numrules; i++){
        if((rule[i].field[1].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[1].high & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if((rule[i].field[1].low & 0xFFFF) <= current_end_point &&
           (rule[i].field[1].high & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 3){
      for(i=0; i<numrules; i++){
        if(((rule[i].field[1].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[1].high >> 16) & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(((rule[i].field[1].low >> 16) & 0xFFFF) <= current_end_point &&
           ((rule[i].field[1].high >> 16) & 0xFFFF) >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 4){
      for(i=0; i<numrules; i++){
        if(rule[i].field[2].low <= current_end_point &&
           rule[i].field[2].high >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(rule[i].field[2].low <= current_end_point &&
           rule[i].field[2].high >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else if(chunk_id == 5){
      for(i=0; i<numrules; i++){
        if(rule[i].field[3].low <= current_end_point &&
           rule[i].field[3].high >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(rule[i].field[3].low <= current_end_point &&
           rule[i].field[3].high >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }else{
      for(i=0; i<numrules; i++){
        if(rule[i].field[4].low <= current_end_point &&
           rule[i].field[4].high >= dheap_key(H, dheap_findmin(H))){
          current_numrules ++;
        }
      }
      if (current_numrules == 0)
	      goto done2;
      current_rule_list = (int *)rfc_calloc(fb, current_numrules, sizeof(int));
      if (current_rule_list == NULL)
	      return -1;
      for(i=0; i<numrules; i++){
        if(rule[i].field[4].low <= current_end_point &&
           rule[i].field[4].high >= dheap_key(H, dheap_findmin(H))){
          current_rule_list[k] = i;
          k++;
        }
      }
    }

done2:
    //printf("current num rules %d\n", current_numrules);

#if 0 // OK
    if (H->n == 0) {
	    printf("H is empty, return\n");
	    break;
    }
#endif

    match = 0;
    for(i=0; i<=current_eq_id; i++){
      if(current_numrules == t->p0_eq[chunk_id][i].numrules){
        match = 1;
        for(j=0; j<current_numrules; j++){
          if(t->p0_eq[chunk_id][i].rulelist[j] != current_rule_list[j]){
            match = 0;
            break;
          }
        }
        if(match == 1){
          for(j=current_end_point+1; j<(int)dheap_key(H, dheap_findmin(H)); j++){
            ASSERT(j < 65536);
            t->p0_table[chunk_id][j] = i;
          }
          break;
        }
      }
    }
    if(match == 0){
      current_eq_id ++;
      ASSERT(current_eq_id < 2*MAXRULES);
      t->p0_eq[chunk_id][current_eq_id].numrules = current_numrules;
      t->p0_eq[chunk_id][current_eq_id].rulelist = current_rule_list;
      /* save first rule id - JMG. */
      if (current_rule_list)
         t->p0_eq[chunk_id][current_eq_id].first_rule_id = t->rule[current_rule_list[0]].filtId;
      for(i=current_end_point+1; i<(int)dheap_key(H, dheap_findmin(H)); i++){
        ASSERT(i < 65536);
        t->p0_table[chunk_id][i] = current_eq_id;
      }
    }

    current_end_point = dheap_key(H, dheap_findmin(H));
    npoints ++;
  }

  //printf("%d end points in total\n", npoints);
  return current_eq_id+1;
}

void *rfc_init(void *memstart, uint32_t memsize)
{
  struct trie_rfc *t;
  int i, j;
  unsigned char *mem = (unsigned char *)memstart;

  t = (struct trie_rfc *)mem;
  memset(t, 0, sizeof(struct trie_rfc));
  mem += sizeof(struct trie_rfc);
  memsize -= sizeof(struct trie_rfc);

  dheap_init(&t->dheap, mem, 2*MAXRULES+2);
  mem += dheap_size(2*MAXRULES+2);
  memsize -= dheap_size(2*MAXRULES+2);

  fblock_init(&t->fb, mem, memsize);

  for(i=0; i<7; i++){
    t->p0_neq[i] = 0;
    for(j=0; j<=65535; j++) t->p0_table[i][j] = 0;
    for(j=0; j<2*MAXRULES; j++) {
      t->p0_eq[i][j].numrules = 0;
      t->p0_eq[i][j].rulelist = NULL;
    }
  }
  for(i=0; i<4; i++){
    t->p1_neq[i] = 0;
    for(j=0; j<2*MAXRULES; j++) {
      t->p1_eq[i][j].numrules = 0;
      t->p1_eq[i][j].rulelist = NULL;
    }
  }
  for(i=0; i<2; i++){
    t->p2_neq[i] = 0;
    for(j=0; j<2*MAXRULES; j++) {
      t->p2_eq[i][j].numrules = 0;
      t->p2_eq[i][j].rulelist = NULL;
    }
  }
  t->p3_neq = 0;
  for(j=0; j<2*MAXRULES; j++) {
    t->p3_eq[j].numrules = 0;
    t->p3_eq[j].rulelist = NULL;
  }

  if (unlikely(!rfc_protocomptab_built))
    rfc_protocomptab_build();

  return (void *)t;
}

#ifdef DEBUG_RULES
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]


void rfc_print_rule(int i, struct pc_rule *rule)
{

	printf("Rule(%d) fid=%d src %u.%u.%u.%u - %u.%u.%u.%u dst %u.%u.%u.%u - %u.%u.%u.%u proto= %d - %d srcport %d - %d dstport %d - %d\n",
			i,
			rule->filtId,
			NIPQUAD(rule->field[0].low),
			NIPQUAD(rule->field[0].high),
			NIPQUAD(rule->field[1].low),
			NIPQUAD(rule->field[1].high),
			rule->field[2].low,
			rule->field[2].high,
			rule->field[3].low,
			rule->field[3].high,
			rule->field[4].low,
			rule->field[4].high);
}

void rfc_print_rules(struct trie_rfc *t)
{
	int i;

	for (i = 0 ; i < t->numrules; i++)
		rfc_print_rule(i, &t->rule[i]);
}
#endif

int rfc_update(struct FILTER *f, void *user_ctx)
{
	struct trie_rfc *t = (struct trie_rfc *)user_ctx;
	int i = t->numrules;
	struct pc_rule *rule;

	/* RFC rule
	 * 0 src range
	 * 1 dst range
	 * 2 protocol range (/32 or /0)
	 * 3 src port range
	 * 4 dst port range
	 */

	if (i >= MAXRULES)
		return -1;
	rule = &t->rule[i];
	rule->field[0].low =  ntohl(f->src & f->src_mask);
	rule->field[0].high =  ntohl(f->src | ~f->src_mask);
	rule->field[1].low =  ntohl(f->dst & f->dst_mask);
	rule->field[1].high =  ntohl(f->dst | ~f->dst_mask);

	if (f->ul_proto == FILTER_ULPROTO_ANY) {
		rule->field[2].low = rfc_make_vrproto(f->vrfid, 0);
		rule->field[2].high = rfc_make_vrproto(f->vrfid, RFC_5BIT_PROTO_MAX);
	} else {
		uint8_t proto = rfc_proto_compress(f->ul_proto);
		if (proto == RFC_5BIT_PROTO_UNKNOWN)
			proto = RFC_5BIT_PROTO_INVALID;
		rule->field[2].low =
		rule->field[2].high = rfc_make_vrproto(f->vrfid, proto);
	}

	rule->field[3].low = ntohs(f->srcport & f->srcport_mask) & 0xffff;
	rule->field[3].high = ntohs(f->srcport | ~f->srcport_mask) & 0xffff;

	rule->field[4].low = ntohs(f->dstport & f->dstport_mask) & 0xffff;
	rule->field[4].high = ntohs(f->dstport | ~f->dstport_mask) & 0xffff;

	rule->filtId = f->filtId;
	rule->cost = f->cost;

	t->numrules++;
	return 0;
}


int rfc_final(void *ctx)
{
  int i;
  struct trie_rfc *t = (struct trie_rfc *)ctx;
#ifdef PRINT_STAT
  int tmp;
#endif

  if (ctx == 0)
	  return -1;
#ifdef DEBUG_RULES
  rfc_print_rules(t);
#endif
  //phase 0 preprocessing
  for(i=0; i<7; i++){
    if((t->p0_neq[i] = preprocessing_phase0(i, t->rule, t->numrules, t)) < 0)
      return -1;
#ifdef PRINT_STAT
    printf("Chunk %d has %d equivalence classes\n", i, t->p0_neq[i]);
    if(i == 4) {
      tmp = (int)((log(t->p0_neq[i])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * 256;
    }else if(t->p0_neq[i] > 2) {
      tmp = (int)((log(t->p0_neq[i])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * 65536;
    }
    printf("size = %d, mem_access = %d\n", size, mem_access);
#endif
  }

#if RFC_PHASE == 4
      //**********************************************************************************************************************
      //phase 1 network
#ifdef PRINT_STATS
      printf("\nstart phase 1:\n");
#endif
      t->p1_neq[0] = preprocessing_2chunk(t->p0_eq[0], t->p0_neq[0], t->p0_eq[1], t->p0_neq[1], t->p1_eq[0], &t->p1_table[0], t);
      t->p1_neq[1] = preprocessing_2chunk(t->p0_eq[2], t->p0_neq[2], t->p0_eq[3], t->p0_neq[3], t->p1_eq[1], &t->p1_table[1], t);
      t->p1_neq[2] = preprocessing_3chunk(t->p0_eq[4], t->p0_neq[4], t->p0_eq[5], t->p0_neq[5], t->p0_eq[6], t->p0_neq[6], t->p1_eq[2], &t->p1_table[2], t);

#ifdef PRINT_STATS
      printf("phase 1 table (%d, %d), (%d, %d), (%d, %d)\n",
              t->p1_neq[0], t->p0_neq[0]*t->p0_neq[1],
              t->p1_neq[1], t->p0_neq[2]*t->p0_neq[3],
              t->p1_neq[2], t->p0_neq[4]*t->p0_neq[5]*t->p0_neq[6]);

      tmp = (int)((log(t->p1_neq[0])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p0_neq[0]*t->p0_neq[1];

      tmp = (int)((log(t->p1_neq[1])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p0_neq[2]*t->p0_neq[3];

      tmp = (int)((log(t->p1_neq[2])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p0_neq[4]*t->p0_neq[5]*t->p0_neq[6];

      printf("size = %d, mem_access = %d\n", size, mem_access);
#endif
      //phase 2 network
#ifdef PRINT_STATS
      printf("\nstart phase 2:\n");
#endif
      t->p2_neq[0] = preprocessing_2chunk(t->p1_eq[0], t->p1_neq[0], t->p1_eq[1], t->p1_neq[1], t->p2_eq[0], &t->p2_table[0], t);

#ifdef PRINT_STATS
      printf("phase 2 table (%d, %d)\n", t->p2_neq[0], t->p1_neq[0]*t->p1_neq[1]);

      tmp = (int)((log(t->p2_neq[0])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p1_neq[0]*t->p1_neq[1];

      printf("size = %d, mem_access = %d\n", size, mem_access);
#endif
      //phase 3 network
#ifdef PRINT_STATS
      printf("\nstart phase 3:\n");
#endif
      t->p3_neq = preprocessing_2chunk(t->p1_eq[2], t->p1_neq[2], t->p2_eq[0], t->p2_neq[0], t->p3_eq, &t->p3_table, t);

#ifdef PRINT_STATS
      printf("phase 3 table (%d, %d)\n", t->p3_neq, t->p1_neq[2]*t->p2_neq[0]);

      mem_access += 2;
      size += 2 * t->p1_neq[2]*t->p2_neq[0];
      printf("size = %d, mem_access = %d\n", size, mem_access);
#endif

#else /* PHASE 3 */

      //configuration 1--> 2,2,3;3
      //phase 1 network
      //printf("\nstart phase 1:\n");
      t->p1_neq[0] = preprocessing_2chunk(t->p0_eq[0], t->p0_neq[0], t->p0_eq[1], t->p0_neq[1], t->p1_eq[0], &t->p1_table[0], t);
      t->p1_neq[1] = preprocessing_2chunk(t->p0_eq[2], t->p0_neq[2], t->p0_eq[3], t->p0_neq[3], t->p1_eq[1], &t->p1_table[1], t);
      t->p1_neq[2] = preprocessing_3chunk(t->p0_eq[4], t->p0_neq[4], t->p0_eq[5], t->p0_neq[5], t->p0_eq[6], t->p0_neq[6], t->p1_eq[2], &t->p1_table[2], t);

#ifdef PRINT_STATS
      printf("phase 1 table (%d, %d), (%d, %d), (%d, %d)\n",
              t->p1_neq[0], t->p0_neq[0]*t->p0_neq[1],
              t->p1_neq[1], t->p0_neq[2]*t->p0_neq[3],
              t->p1_neq[2], t->p0_neq[4]*t->p0_neq[5]*t->p0_neq[6]);

      tmp = (int)((log(t->p1_neq[0])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p0_neq[0]*t->p0_neq[1];

      tmp = (int)((log(t->p1_neq[1])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p0_neq[2]*t->p0_neq[3];

      tmp = (int)((log(t->p1_neq[2])/log(2))/8)+1;
      mem_access += tmp;
      size += tmp * t->p0_neq[4]*t->p0_neq[5]*t->p0_neq[6];

      printf("size = %d, mem_access = %d\n", size, mem_access);
#endif
      //phase 2 network
#ifdef PRINT_STAT
      printf("\nstart phase 2:\n");
#endif
      t->p2_neq[0] = preprocessing_3chunk(t->p1_eq[0], t->p1_neq[0], t->p1_eq[1], t->p1_neq[1], t->p1_eq[2], t->p1_neq[2], t->p2_eq[0], &t->p2_table[0], t);

#ifdef PRINT_STAT
      printf("phase 2 table (%d, %d)\n", t->p2_neq[0], t->p1_neq[0]*t->p1_neq[1]*t->p1_neq[2]);

      mem_access += 2;
      size += 2 * t->p1_neq[0]*t->p1_neq[1]*t->p1_neq[2];
      printf("size = %d, mem_access = %d\n", size, mem_access);
#endif
      //**********************************************************************************************************************
#endif

#ifdef PRINT_STAT
  printf("\n%10.1f bytes/filter, %d bytes per packet lookup\n", (float)size/t->numrules+FILTERSIZE, mem_access);
#endif
  return 0;
}

/* build the protocol 8-to-5-bit compression table */
static void rfc_protocomptab_build(void)
{
	/* protocol numbers for ICMP, IGMP, IPV4, TCP, UDP, IPV6, RSVP, GRE,
	 * ESP, AH, OSPF, PIM, VRRP, ISIS, SCTP, UDPLITE */
	uint8_t proto[]={1,2,4,6,17,41,46,47,50,51,89,103,112,124,132,136};
	uint8_t i;

	memset(rfc_protocomptab, RFC_5BIT_PROTO_UNKNOWN, sizeof(rfc_protocomptab));
	for (i=0; i<FPN_ARRAY_SIZE(proto); i++)
		rfc_protocomptab[proto[i]] = i;
	
	rfc_protocomptab_built = 1;
}
