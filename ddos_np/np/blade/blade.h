/*
 * Copyright (C) 2013 6WIND, All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* 6WIND_GPL */

#ifndef _BLADE_H
#define _BLADE_H

#include <linux/genetlink.h>
#include <linux/if_ether.h>

#define BLADE_FAMILY_NAME "blade"

/* attributes */
enum {
	BLADE_A_FP_UNSPEC = 0,
	BLADE_A_FP_INFO,
	__BLADE_A_FP_MAX,
};
#define BLADE_A_FP_MAX (__BLADE_A_FP_MAX - 1)

/* commands */
enum {
	BLADE_C_UNSPEC = 0,
	BLADE_C_FP_DUMP,
	BLADE_C_FP_NEW,
	BLADE_C_FP_DEL,
	__BLADE_C_MAX,
};
#define BLADE_C_MAX (__BLADE_C_MAX + 1)

#define BLADE_MAX_FPID 15

struct blade_fpinfo {
	unsigned char id;
	unsigned char mac[ETH_ALEN];
};

#endif
