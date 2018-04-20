/*
 * Copyright(c) 2007 6WIND
 */
#include "fpn.h"
#include "dheap.h"

// parent of item, leftmost and rightmost children
#define p(H, x) (((x)+(H->d-2))/H->d)
#define left(H, x) (H->d*((x)-1)+2)
#define right(H, x) (H->d*(x)+1)

// Return the position of the child of the item at position x
// having minimum key.
static int minchild(struct dheap *H, int x) {
	int y, minc;
	if ((minc = left(H, x)) > H->n) return -1;
	for (y = minc + 1; y <= right(H, x) && y <= H->n; y++) {
		if (H->kvec[H->h[y]] < H->kvec[H->h[minc]]) minc = y;
	}
	return minc;
}

static void siftup(struct dheap *H, item i, int x) {
	// Shift i up from position x to restore heap order.
	int px = p(H, x);
	while (x > 1 && H->kvec[H->h[px]] > H->kvec[i]) {
		H->h[x] = H->h[px]; H->pos[H->h[x]] = x;
		x = px; px = p(H, x);
	}
	H->h[x] = i; H->pos[i] = x;
}

static void siftdown(struct dheap *H, item i, int x) {
	// Shift i down from position x to restore heap order.
	int cx = minchild(H, x);
	while (cx != -1 && H->kvec[H->h[cx]] < H->kvec[i]) {
		H->h[x] = H->h[cx]; H->pos[H->h[x]] = x;
		x = cx; cx = minchild(H, x);
	}
	H->h[x] = i; H->pos[i] = x;
}

void dheap_remove(struct dheap *H, item i)
{
	int j;

	H->n--;
	j = H->h[H->n];
	if (i != j && H->kvec[j] <= H->kvec[i])
		siftup(H, j, H->pos[i]);
	else if (i != j && H->kvec[j] > H->kvec[i])
		siftdown(H, j, H->pos[i]);
	H->pos[i] = -1;
}

int dheap_deletemin(struct dheap *H) {
	item i;
	// Remove and return item with smallest key.
	if (H->n == 0)
		return -1;
	i = H->h[1];
	dheap_remove(H, H->h[1]);
	return i;
}

// size and initialization of dheap internal arrays:
//
// N:   maximum number of items in dheap
// i:   item identifier, ranging from 0 to N-1
// x:   position in dheap array, ranging from 1 to N (0 is unused)
// key: item priority (used for sorting items)
//
// i   = H->h[x]    => h    array size = N+1
// x   = H->pos[i]  => pos  array size = N
// key = H->kvec[i] => kvec array size = N

unsigned int dheap_size(int N1)
{
	unsigned int len;

	len = (N1+1) * sizeof(item);
	len += N1 * sizeof(int);
	len += N1 * sizeof(keytyp);

	return len;
}

void dheap_init(struct dheap *H, unsigned char *p, int N1)
{
	H->N = N1;
	H->h = (item *)p;
	p += (N1+1) * sizeof(item);
	H->pos = (int *)p;
	p += N1 * sizeof(int);
	H->kvec = (keytyp *)p;
	// p += N1 * sizeof(keytyp);
}

void dheap_reset(struct dheap *H, int d1)
{
	int i;
	int N1 = H->N;

	H->n = 0;
	H->d = d1;

	memset(H->h, 0, (N1+1) * sizeof(item));

	for (i = 0; i < N1; i++)
		H->pos[i] = -1;

	memset(H->kvec, 0, N1 * sizeof(keytyp));
}

void dheap_insert(struct dheap *H, item i, keytyp k)
{
	H->kvec[i] = k;
	H->n++;
	siftup(H, i, H->n);
}


void dheap_changekey(struct dheap *H, item i, keytyp k) {
// Change the key of i and restore heap order.
	keytyp ki = H->kvec[i]; H->kvec[i] = k;
	     if (k < ki) siftup(H, i, H->pos[i]);
	else if (k > ki) siftdown(H, i, H->pos[i]);
}

// Print the contents of the heap.
void dheap_print(struct dheap *H) {
	int x;
	int n = H->n;
	fpn_printf("   h:");
	for (x = 1; x <= n; x++) fpn_printf(" %2d",H->h[x]);
	fpn_printf("\nkvec:");
	for (x = 1; x <= n; x++) fpn_printf(" %8lx",H->kvec[H->h[x]]);
	fpn_printf("\n pos:");
	for (x = 1; x <= n; x++) fpn_printf(" %2d",H->pos[H->h[x]]);
	fpn_printf("\n");
}
