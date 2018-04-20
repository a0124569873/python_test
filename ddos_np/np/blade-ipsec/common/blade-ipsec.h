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

#ifndef __BLADE_IPSEC_H
#define __BLADE_IPSEC_H

#include <linux/genetlink.h>

#define BLADE_IPSEC_FAMILY_NAME "blade-ipsec"

/* attributes */
enum {
	BLADE_IPSEC_A_UNSPEC = 0,
	BLADE_IPSEC_A_TYPE,
	BLADE_IPSEC_A_SA_ID,
	BLADE_IPSEC_A_SRC_FP,
	BLADE_IPSEC_A_COUNTER,
	BLADE_IPSEC_A_DST_FP,
	BLADE_IPSEC_A_GAP,
	BLADE_IPSEC_A_VRFID,
	__BLADE_IPSEC_A_MAX,
};
#define BLADE_IPSEC_A_MAX (__BLADE_IPSEC_A_MAX - 1)

/* commands */
enum {
	BLADE_IPSEC_C_UNSPEC = 0,
	BLADE_IPSEC_C_MIGRATE,
	__BLADE_IPSEC_C_MAX,
};
#define BLADE_IPSEC_C_MAX (__BLADE_IPSEC_C_MAX + 1)

#define BLADE_IPSEC_MIG_SINGLE       1
#define BLADE_IPSEC_MIG_BULK_BY_FP   2

#endif
