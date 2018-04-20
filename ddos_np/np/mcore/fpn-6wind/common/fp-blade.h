/*
 * Copyright 2007 6WIND, All rights reserved.
 */

#ifndef __FP_BLADE_H__
#define __FP_BLADE_H__

#define FP_BLADEID_MAX   15

#ifdef CONFIG_MCORE_MULTIBLADE
typedef struct fp_blade {
	uint8_t blade_active:1;
	uint8_t blade_mac[6];
} fp_blade_t;

uint32_t fp_add_blade(uint8_t id, uint8_t flag, const uint8_t mac[6]);
uint32_t fp_delete_blade(uint8_t id, uint8_t flag);
uint32_t fp_set_fpib_ifuid(uint32_t ifuid, int auto_thresh);
#endif

uint32_t fp_set_active_cpid(uint8_t id);

#endif
