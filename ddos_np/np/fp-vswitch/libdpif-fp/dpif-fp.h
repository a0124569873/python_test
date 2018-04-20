/*
 * Copyright (c) <2014>, 6WIND
 * All rights reserved.
 */

#ifndef _DPIF_FAST_PATH_H
#define _DPIF_FAST_PATH_H

int dpif_fp_port_get(uint32_t ovsport, struct ovs_vport_stats *stats);

int dpif_fp_flow_put(const struct nlattr *key, size_t key_len,
		     const struct nlattr *mask, size_t mask_len,
		     const struct nlattr *actions, size_t actions_len,
		     uint8_t create);

int dpif_fp_flow_del(const struct nlattr *key, size_t key_len);

int dpif_fp_flow_get(const struct nlattr *key, size_t key_len,
		     const struct nlattr *mask, size_t mask_len,
		     struct ovs_flow_stats *stats, uint8_t *tcp_flags,
		     uint64_t *used, uint64_t time);

int dpif_fp_flow_flush(void);

#endif
