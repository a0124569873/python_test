/*
 * Copyright 2013 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <event.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fp.h"
#include "fp-bpf.h"

static void fpm_bpf_start_timer(void);

static struct event bpf_gc;

static void fpm_bpf_gc(int sock, short evtype, void *data)

{
	fp_bpf_filter_t *fp_bpf;
	uint32_t idx, i;
	int do_tap = 0;

	for (idx = 0; idx < FP_MAX_IFNET; idx++)
		for (i = 0; i < FP_BPF_MAXINSTANCE; i++) {
			fp_bpf = &fp_shared->fp_bpf_filters[idx][i];

			if (!fp_bpf->num)
				continue;

			if (fp_bpf->status == BPF_FILTER_CHECK_ACTIVE)
				fp_bpf->num = 0;
			else if (fp_bpf->status == BPF_FILTER_ACTIVE) {
				fp_bpf->status = BPF_FILTER_CHECK_ACTIVE;
				do_tap = 1;
			} else /* BPF_FILTER_PERMANENT */
				do_tap = 1;
		}

	fp_shared->conf.s.do_tap = do_tap ? 1 : 0;
	fpm_bpf_start_timer();
}

void fpm_bpf_start_timer(void)
{
	struct timeval tv;

	tv.tv_sec = 1; /* one per second */
	tv.tv_usec = 0;
	evtimer_set(&bpf_gc, &fpm_bpf_gc, NULL);
	evtimer_add(&bpf_gc, &tv);
	return;
}

static int fpm_bpf_create(const uint8_t *request, const struct cp_hdr *hdr)
{
	uint32_t i;
	fp_bpf_filter_t fp_bpf;
	struct cp_bpf *cp_bpf = (struct cp_bpf *)request;

	fp_bpf.ifuid = cp_bpf->ifuid;
	fp_bpf.num = ntohl(cp_bpf->num);
	fp_bpf.status = BPF_FILTER_ACTIVE;

	for (i = 0; i < fp_bpf.num; i++) {
		fp_bpf.filters[i].code = ntohs(cp_bpf->filters[i].code);
		fp_bpf.filters[i].jt = cp_bpf->filters[i].jt;
		fp_bpf.filters[i].jf = cp_bpf->filters[i].jf;
		fp_bpf.filters[i].k = ntohl(cp_bpf->filters[i].k);
	}

	return fp_bpf_create(&fp_bpf);
}

static void fpm_bpf_init(__attribute__((unused)) int graceful)
{
	fpm_register_msg(CMD_BPF_CREATE, fpm_bpf_create, NULL);
	fpm_bpf_start_timer();
}

static struct fpm_mod fpm_bpf_mod = {
	.name = "bpf",
	.init = fpm_bpf_init,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_bpf_mod);
}
