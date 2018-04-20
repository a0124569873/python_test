/*
 * Copyright(c) 2008 6WIND, All rights reserved.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "fp.h"
#include "fp-var.h"
#include "fp-bpf.h"

static fp_bpf_filter_t *fp_bpf_find(fp_bpf_filter_t *req)
{
	fp_bpf_filter_t *fp_bpf;
	uint32_t ifuid = req->ifuid;
	uint32_t i, j;
	fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);

	if (!ifp)
		ifp = &fp_shared->ifnet.table[0];

	if (req->num > FP_BPF_MAXFILTERS)
		return NULL;

	for (i = 0; i < FP_BPF_MAXINSTANCE; i++) {
		fp_bpf = &fp_ifnet2bpf(ifp)[i];

		if (req->status == BPF_FILTER_PERMANENT &&
		    fp_bpf->status != BPF_FILTER_PERMANENT)
			continue;

		if (fp_bpf->num && fp_bpf->num == req->num) {
			for (j = 0; j < fp_bpf->num ; j++)
				if (!(fp_bpf->filters[j].code == req->filters[j].code &&
				      fp_bpf->filters[j].jt == req->filters[j].jt &&
				      fp_bpf->filters[j].jf == req->filters[j].jf &&
				      fp_bpf->filters[j].k == req->filters[j].k))
					break;
			if (j == fp_bpf->num)
				return fp_bpf;
		}
	}

	return NULL;
}

uint32_t fp_bpf_create(fp_bpf_filter_t *req)
{
	fp_bpf_filter_t *fp_bpf;
	uint32_t ifuid = req->ifuid;
	uint32_t i, j;
	fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);

	if (!ifp)
		ifp = &fp_shared->ifnet.table[0];
	if (req->num > FP_BPF_MAXFILTERS)
		return -1;

	/* Check if the filter already exists */
	fp_bpf = fp_bpf_find(req);
	if (fp_bpf) {
		if (fp_bpf->status != BPF_FILTER_PERMANENT)
			fp_bpf->status = BPF_FILTER_ACTIVE;
		return 0;
	}

	for (i = 0; i < FP_BPF_MAXINSTANCE; i++) {
		fp_bpf = &fp_ifnet2bpf(ifp)[i];

		if (likely(!fp_bpf->num)) {
			fp_bpf->num = req->num;
			fp_bpf->status = req->status;

			for (j = 0; j < fp_bpf->num; j++) {
				fp_bpf->filters[j].code = req->filters[j].code;
				fp_bpf->filters[j].jt = req->filters[j].jt;
				fp_bpf->filters[j].jf = req->filters[j].jf;
				fp_bpf->filters[j].k = req->filters[j].k;
			}

			fp_shared->conf.s.do_tap = 1;
			return 0;
		}
	}

	return -1;
}

static void fp_bpf_update_do_tap(void)
{
	uint32_t idx, i;

	for (idx = 0; idx < FP_MAX_IFNET; idx++)
		for (i = 0; i < FP_BPF_MAXINSTANCE; i++)
			if (fp_shared->fp_bpf_filters[idx][i].num)
				return;

	fp_shared->conf.s.do_tap = 0;
}

uint32_t fp_bpf_del(fp_bpf_filter_t *req)
{
	fp_bpf_filter_t *fp_bpf;

	fp_bpf = fp_bpf_find(req);
	if (fp_bpf) {
		fp_bpf->num = 0;
		fp_bpf_update_do_tap();
		return 0;
	}

	return -1;
}
