/*
 * Copyright 2011-2013 6WIND S.A.
 */

/*	$NetBSD: ieee8023_tlv.c,v 1.3 2007/02/21 23:00:06 thorpej Exp $	*/

/*-
 * Copyright (c)2005 YAMAMOTO Takashi,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(__LinuxKernelVNB__) /* __VnbLinuxKernel__ */

#include <linux/version.h>

#include <linux/errno.h>
#include <linux/types.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif /* CONFIG_KMOD */

#elif defined(__FastPath__) /* __FastPath__ */

#include "fp-netgraph.h"

#else  /* __FastPath__ */

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#endif /* __LinuxKernelVNB__ */

#include <netgraph/ieee8023_tlv.h>

int
tlv_check(const void *p, size_t size, const struct tlvhdr *tlv,
    const struct tlv_template *tmpl, int check_type)
{

	while (1) {
		if ((const char *)tlv - (const char *)p + sizeof(*tlv) > size) {
			return EINVAL;
		}
		if ((check_type && tlv->tlv_type != tmpl->tmpl_type) ||
		    tlv->tlv_length != tmpl->tmpl_length) {
			return EINVAL;
		}
		if (tmpl->tmpl_type == 0) {
			break;
		}
		tlv = (const struct tlvhdr *)
		    ((const char *)tlv + tlv->tlv_length);
		tmpl++;
	}

	return 0;
}

