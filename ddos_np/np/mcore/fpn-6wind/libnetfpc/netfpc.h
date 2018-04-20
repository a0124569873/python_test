/*
 * Copyright(c) 2007 6WIND
 * $Id: netfpc.h,v 1.2 2007-06-25 13:10:33 guerin Exp $
 */
#ifndef _NETFPC_H_
#define _NETFPC_H_

#include "netfpc_var.h"

/* Must not be used in socket.h flags */
#define MSG_NO_TIMEOUT 0x80000000

ssize_t netfpc_recv(int s, void *data, size_t len, int flags, uint16_t *type);
int netfpc_send(int s, const void *buf, size_t len, int flags, uint16_t type);
int netfpc_open(const char *ifname);

#endif
