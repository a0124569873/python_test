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
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

void vnb_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head))
{
	call_rcu(head, func);
}
EXPORT_SYMBOL(vnb_call_rcu);

void vnb_rcu_read_lock(void)
{
	rcu_read_lock();
}
EXPORT_SYMBOL(vnb_rcu_read_lock);

void vnb_rcu_read_unlock(void)
{
	rcu_read_unlock();
}
EXPORT_SYMBOL(vnb_rcu_read_unlock);
