/*
 * Copyright 2014 6WIND S.A.
 */
#ifndef __FPM_VRF_H__
#define __FPM_VRF_H__

#include <sys/queue.h>

typedef void (*fpm_vrf_handler_t)(const uint16_t vrfid);

struct fpm_vrf_handler {
	TAILQ_ENTRY(fpm_vrf_handler)	link;
	char				*name;
	fpm_vrf_handler_t		del;
};

int fpm_vrf_register(struct fpm_vrf_handler *handler);
#endif /* __FPM_VRF_H__ */
