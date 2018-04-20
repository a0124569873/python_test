/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                socket miscellaneous functions
 *
 * $Id: sockmisc.h,v 1.4 2009-05-06 08:20:41 dichtel Exp $
 ***************************************************************
 */
#ifndef __SOCKMISC_H_
#define __SOCKMISC_H_

struct sockaddr_generic {
	sa_family_t sgen_family;
	char sgen_pad[128 - sizeof(sa_family_t)];
};

extern int newsock(int family, int type, int proto, int flags, int bufsize,
	char *sockname);
extern void setsock(int sock, int flags, int bufsize, char *sockname);
extern int sockaddr_len(struct sockaddr *sa);
extern int dump_sockaddr(char *buffer, const struct sockaddr *sa);
extern int set_sockaddr_unix(struct sockaddr *sa, size_t socklen, const char *spec);
extern int set_sockaddr_tcp(struct sockaddr *sa, size_t socklen, const char *spec);

#define SIN6ADDR(sa) (((struct sockaddr_in6*)(sa))->sin6_addr)
#define SIN6PORT(sa) (((struct sockaddr_in6*)(sa))->sin6_port)
#define SIN6SCOPE(sa) (((struct sockaddr_in6*)(sa))->sin6_scope_id)
#define SIN6LEN sizeof(struct sockaddr_in6)

#define SINADDR(sa) (((struct sockaddr_in*)(sa))->sin_addr)
#define SINPORT(sa) (((struct sockaddr_in*)(sa))->sin_port)
#define SINLEN sizeof(struct sockaddr_in)

#define SGENLEN sizeof(struct sockaddr_generic)

#endif /* __SOCKMISC_H_ */

