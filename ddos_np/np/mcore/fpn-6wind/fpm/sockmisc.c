/*
 * Copyright (c) 2013 6WIND
 */
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include <net/if.h>
#include <netinet/in.h>

#include "sockmisc.h"
#include "fpm_common.h"

#define SUNLEN sizeof(struct sockaddr_un)
#define SUNPATH(sa) (((struct sockaddr_un*)(sa))->sun_path)
#define SUNPATHLEN sizeof(SUNPATH(0))

void
setsock(int sock, int flags, int bufsize, char *sockname)
{
	int optval;
	socklen_t optlen;

	/* Set flags, if any */
	if (flags && (fcntl (sock, F_SETFL, flags) < 0)) {
		if (sockname)
			syslog(LOG_ERR, "%s: Could not set %s socket flags to %08x: %s\n",
				__FUNCTION__, sockname, flags, strerror(errno));
	}

	optval = bufsize;
	optlen = sizeof(optval);

	/* Set buffer size */
	if (bufsize &&
	    (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &optval, optlen) < 0)) {
		if (sockname)
			syslog(LOG_ERR, "%s: Could not set %s socket send buffer size to %d: %s\n",
				__FUNCTION__, sockname, bufsize, strerror(errno));
	} else {
		if (sockname) {
			if (getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &optval, &optlen))
				syslog(LOG_ERR, "%s: Could not read %s socket send buffer size: %s\n",
					__FUNCTION__, sockname, strerror(errno));
		}
	}

	if (bufsize &&
	    (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &optval, optlen) < 0)) {
		if (sockname)
			syslog(LOG_ERR, "%s: Could not set %s socket recv buffer size to %d: %s\n",
				__FUNCTION__, sockname, bufsize, strerror(errno));
	} else {
		if (sockname) {
			if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &optval, &optlen))
				syslog(LOG_ERR, "%s: Could not read %s socket recv buffer size: %s\n",
					__FUNCTION__, sockname, strerror(errno));
		}
	}
}

int
newsock(int family, int type, int proto, int flags, int bufsize, char *sockname)
{
	int sock;

	/* Create socket */
	sock = socket(family, type, proto);
	if (sock < 0) {
		if (sockname)
			syslog(LOG_ERR, "%s: Could not open %s socket: %s\n", __FUNCTION__, sockname, strerror(errno));
		goto end;
	}

	setsock(sock, flags, bufsize, sockname);

end:
	return sock;
}

int
sockaddr_len(struct sockaddr *sa)
{
	int len = 0;

	switch(sa->sa_family) {
	case AF_INET6:
		len = sizeof(struct sockaddr_in6);
		break;
	case AF_INET:
		len = sizeof(struct sockaddr_in);
		break;
	case AF_LOCAL:
		len = sizeof(struct sockaddr_un);
		break;
	default:
		break;
	}

	return len;
}

int
dump_sockaddr(char *buffer, const struct sockaddr *sa)
{
	char straddr[INET6_ADDRSTRLEN];
	int addr_len = 0;

	switch(sa->sa_family) {
	case AF_INET6: {
			const struct sockaddr_in6 *sin6 = (void*)sa;
			char scopestr[IFNAMSIZ+1]="%";
			char *scope = "";
			inet_ntop(AF_INET6, (char*)&sin6->sin6_addr, straddr, SIN6LEN);
			if (sin6->sin6_scope_id) {
				(void)if_indextoname(sin6->sin6_scope_id, scopestr+1);
				scope = scopestr;
			}

			addr_len = sprintf(buffer, "tcp6 addr=%s%s port=%hu\n", straddr, scope,
				ntohs(sin6->sin6_port));
		}
		break;
	case AF_INET: {
			const struct sockaddr_in *sin = (void*)sa;
			inet_ntop(AF_INET, (char*)&sin->sin_addr, straddr, SINLEN);
			addr_len = sprintf(buffer, "tcp addr=%s port=%hu\n", straddr, ntohs(sin->sin_port));
		}
		break;
	case AF_UNIX: {
			const struct sockaddr_un *sun = (void*)sa;
			addr_len = sprintf(buffer, "unix path=%s\n", sun->sun_path);
		}
		break;
	default:
		addr_len = sprintf(buffer, "unknown family\n");
		break;
	}

	return addr_len;
}

int
set_sockaddr_unix(struct sockaddr *sa, size_t socklen, const char *spec0)
{
	size_t speclen;

	if (socklen < SUNLEN) {
		syslog(LOG_ERR, "%s: sockaddr too short\n", __FUNCTION__);
		return -1;
	}

	speclen = strlen(spec0) + 1;

	if (speclen > SUNPATHLEN) {
		syslog(LOG_ERR, "%s: socket path too long\n", __FUNCTION__);
		return -1;
	}

	memset(sa, 0, socklen);

	sa->sa_family = AF_UNIX;
	strcpy(SUNPATH(sa), spec0);

	return 0;
}

/*
 * spec: addr[port]
 */
int
set_sockaddr_tcp(struct sockaddr *sa, size_t socklen, const char *spec0)
{
	char *port_p, *scope_p;
	char *end = NULL;
	unsigned short port;
	char specbuf[INET6_ADDRSTRLEN + 1 + IFNAMSIZ + 1 + 5];
	char *spec = &specbuf[0];
	size_t speclen;
	int ret = -1;

	/* create a writable copy of spec0 */
	speclen = strlen(spec0) + 1;

	if (speclen > sizeof(specbuf)) {
		spec = malloc(speclen);
		if (spec == NULL) {
			syslog(LOG_ERR, "%s: could not alloc memory\n", __func__);
			return -1;
		}
	}

	memcpy(spec, spec0, speclen);

	memset(sa, 0, socklen);

	/* find port start */
	port_p = strrchr(spec, ':');
	if (port_p == NULL) {
		syslog(LOG_ERR, "%s: requires port\n", __FUNCTION__);
		goto end;
	}
	*port_p++ = 0;

	/* read port */
	port = (unsigned short)strtoul(port_p, &end, 0);
	if ((end == NULL) || (*end != 0) || (port == 0)) {
		syslog(LOG_ERR, "%s: port %s is invalid\n", __FUNCTION__, port_p);
		goto end;
	}

	/* scope? */
	scope_p = strchr(spec, "%"[0]);
	if (scope_p) {
		if (scope_p >port_p) {
			syslog(LOG_ERR, "%s: misplaced %% character\n", __FUNCTION__);
			goto end;
		}
		*scope_p++ = 0;
	}

	if ((socklen >= SIN6LEN) && inet_pton(AF_INET6, spec, &SIN6ADDR(sa)) > 0) {
		sa->sa_family = AF_INET6;
		SIN6PORT(sa) = htons(port);
		if (IN6_IS_ADDR_LINKLOCAL(&SIN6ADDR(sa))) {
			if (scope_p)
				SIN6SCOPE(sa) = if_nametoindex(scope_p);
			else {
				if (f_verbose)
					syslog(LOG_DEBUG, "%s: link local address, scope is required\n", __FUNCTION__);
				goto end;
			}
		}
	} else
	if ((socklen >= SINLEN) && inet_pton(AF_INET, spec, &SINADDR(sa)) > 0) {
		sa->sa_family = AF_INET;
		SINPORT(sa) = htons(port);
	} else {
		syslog(LOG_ERR, "address %s is invalid\n", spec);
		goto end;
	}

	ret = 0;

end:
	if (spec != &specbuf[0])
		free(spec);
	return ret;
}
