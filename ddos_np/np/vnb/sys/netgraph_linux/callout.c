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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/workqueue.h>
#include <netgraph_linux/callout.h>

static void callout_dw(struct work_struct *work)
{
	struct delayed_work *dw = to_delayed_work(work);
	struct callout *callout = container_of(dw, struct callout, dw);

	callout->handler(callout->arg);
}

int callout_init(struct callout *callout)
{
	INIT_DELAYED_WORK(&callout->dw, callout_dw);
	return 0;
}

EXPORT_SYMBOL(callout_init);

int callout_stop(struct callout *callout)
{
	return !cancel_delayed_work(&callout->dw);
}

EXPORT_SYMBOL(callout_stop);

void callout_stop_sync(struct callout *callout)
{
	cancel_delayed_work_sync(&callout->dw);
}

EXPORT_SYMBOL(callout_stop_sync);

int callout_reset(struct callout *callout, unsigned int hz,
		  void (*handler)(void *), void *arg)
{
	BUG_ON(handler == NULL);
	cancel_delayed_work(&callout->dw);
	callout->handler = handler;
	callout->arg = arg;
	return ((schedule_delayed_work(&callout->dw, hz) == 0) ? 0 : -1);
}

EXPORT_SYMBOL(callout_reset);

int callout_pending(struct callout *callout)
{
	return delayed_work_pending(&callout->dw);
}

EXPORT_SYMBOL(callout_pending);
