/*
 * Copyright (c) 2004, 2006 6WIND
 */

/*
 ***************************************************************
 *
 *     CM miscellaneous functions and constants
 *     needing kernel includes
 *
 * $Id: if_linux.c,v 1.4 2008-10-22 16:37:06 gouault Exp $
 *
 ***************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#ifdef ARPHRD_SVTI
const unsigned short CM_ARPHRD_SVTI = ARPHRD_SVTI;
#else
const unsigned short CM_ARPHRD_SVTI = 0;
#endif

