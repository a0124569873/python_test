/*
 * Copyright 2012-2013 6WIND S.A.
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

#ifndef CALLOUT_H_
#define CALLOUT_H_

#include <linux/workqueue.h>

struct callout {
	struct delayed_work dw;
	void (*handler)(void *);
	void *arg;
};

extern int callout_init(struct callout *callout);
extern int callout_stop(struct callout *callout);
extern void callout_stop_sync(struct callout *callout);
extern int callout_reset(struct callout *callout, unsigned int hz,
			 void (*handler)(void *), void *arg);
extern int callout_pending(struct callout *callout);

#endif /* CALLOUT_H_ */
