/*
 * Copyright (C) 2004 WIDE Project.
 * Copyright 2007-2012 6WIND S.A.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <event.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>

#include "command.h"
#include "util.h"

/* to enable remote IPv4 connection #define REMOTE_IPV4 1 */
#define REMOTE_IPV4 1
#ifdef REMOTE_IPV4
static struct sockaddr_in sin_ci;
#else
static struct sockaddr_in6 sin6_ci;
#endif
struct event evt_command;
char *prompt = "> ";

void command_help(int, char *, void *);
void got_interrupt(int, char *);
void quit_ui(int, char *, void *);
void command_in(int, short, void *);
void new_connection(int, short, void *);
#define disp_prompt(s) do { \
	if (write((s), prompt, strlen(prompt)) < 0) \
		DEBUG(LOG_ERR, "write() failed: %s\n", __FUNCTION__); \
	} while (0)
static void dispatch_command(int, char *, struct command_table *,void *);

struct command_table basic_command_table[] = {
	{"help", command_help, "Show help"},
	{"?", command_help, "Show help"},
	{"quit", quit_ui, "Quit the shell"},
};
struct command_table *commands;

int
command_init(p, cmdset, cmdset_size, port, sock_name)
	char *p;
	struct command_table *cmdset;
	size_t cmdset_size;
	u_short port;
	char *sock_name;
{
	int i, s;
	int s_optval = 1;
	struct command_table *c;
	struct sockaddr_un servAddr;

	if (sock_name == NULL)
#ifdef REMOTE_IPV4
		s = socket(PF_INET, SOCK_STREAM, 0);
#else
		s = socket(PF_INET6, SOCK_STREAM, 0);
#endif
	else
		s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("command: socket");
		return (-1);
	}

	if (sock_name != NULL) {
		/* bind */
		bzero(&servAddr, sizeof(servAddr));
		servAddr.sun_family = AF_UNIX;
		memcpy(servAddr.sun_path, sock_name , strlen(sock_name));

		unlink(sock_name);
		if(bind(s, (struct sockaddr *) &servAddr, sizeof(servAddr))<0) {
			perror("cannot bind port");
			return (-1);
		}
	} else {
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
					&s_optval, sizeof(s_optval)) == -1) {
			perror("command: setsockopt");
			return (-1);
		}

#ifdef REMOTE_IPV4

		/* Configuration channel is bound to only IPv4 */
		bzero(&sin_ci, sizeof(sin_ci));
		sin_ci.sin_family = AF_INET;
#ifndef __linux__
		sin_ci.sin_len = sizeof(sin_ci);
#endif
		sin_ci.sin_port = htons(port);
		if (bind(s, (struct sockaddr *)&sin_ci, sizeof(sin_ci)) < 0) {
			perror("command: bind");
			goto bad;
		}

#else

		/* Configuration channel is bound to only IPv6 */
		bzero(&sin6_ci, sizeof(sin6_ci));
		sin6_ci.sin6_family = AF_INET6;
#ifndef __linux__
		sin6_ci.sin6_len = sizeof(sin6_ci);
#endif
		sin6_ci.sin6_addr = in6addr_loopback;
		sin6_ci.sin6_port = htons(port);
		if (bind(s, (struct sockaddr *)&sin6_ci, sizeof(sin6_ci)) < 0) {
			perror("command: bind");
			goto bad;
		}
#endif
	}
	if (listen(s, 1) < 0) {
		perror("command: listen");
		goto bad;
	}

	commands = malloc((cmdset_size + sizeof(basic_command_table) / sizeof(struct command_table) + 1) * sizeof(struct command_table));
	if (commands == NULL) {
		DEBUG(LOG_ERR, "Not enough memory\n");
		goto bad;
	}
	c = commands;
	for (i = 0; i < sizeof(basic_command_table) / sizeof(struct command_table); i++)
		*c++ = basic_command_table[i];
	for (i = 0; i < cmdset_size; i++)
		*c++ = cmdset[i];
	bzero(c, sizeof(struct command_table));

	event_set(&evt_command, s, EV_READ | EV_PERSIST, new_connection, NULL);
	event_add(&evt_command, NULL);
	prompt = p;

	return (s);

 bad:
	close(s);
	return (-1);
}

void
new_connection(int s, __attribute__ ((unused))short event, __attribute__ ((unused))void *arg)
{
	int ss;
	struct sockaddr_in6 sin6;
	socklen_t sin6len;
	struct event *evt_connection;

	sin6len = sizeof(struct sockaddr_in6);
	if ((ss = accept(s, (struct sockaddr *)&sin6, &sin6len)) < 0) {
		DEBUG(LOG_ERR, "accept() failed\n");
		return;
	}

	evt_connection = (struct event *)malloc(sizeof(struct event));
	event_set(evt_connection, ss, EV_READ | EV_PERSIST, command_in, (void *)evt_connection);
	event_add(evt_connection, NULL);
	disp_prompt(ss);
	return;
}

int
command_stdin_init(p, cmdset, cmdset_size)
	char *p;
	struct command_table *cmdset;
	size_t cmdset_size;
{
	int i;
	struct command_table *c;
	struct event *evt_connection;

	commands = malloc((cmdset_size + sizeof(basic_command_table) / sizeof(struct command_table) + 1) * sizeof(struct command_table));
	if (!commands) {
		DEBUG(LOG_ERR, "Not enough memory\n");
		return -1;
	}
	c = commands;
	for (i = 0; i < sizeof(basic_command_table) / sizeof(struct command_table); i++)
		*c++ = basic_command_table[i];
	for (i = 0; i < cmdset_size; i++)
		*c++ = cmdset[i];
	bzero(c, sizeof(struct command_table));
	prompt = p;

	evt_connection = (struct event *)malloc(sizeof(struct event));
	event_set(evt_connection, 0, EV_READ | EV_PERSIST, command_in, (void *)evt_connection);
	event_add(evt_connection, NULL);
	disp_prompt(0);

	return 0;
}

void
command_in(s, event, arg)
	int s;
	short event;
	void *arg;
{
	int bytes;
	char buffer[2048];
	static char history[2048] = "help";

	bytes = read(s, buffer, 2048);

	/* XXX quick hack for an interrupt, <IAC IP IAC DO TM> */
	if (memcmp(buffer, "\xff\xf4\xff\xfd\x06", 5) == 0) {
		got_interrupt(s, buffer);
		disp_prompt(s);
		return;
	}

	buffer[bytes] = '\0';
	while (strlen(buffer) && isspace(buffer[strlen(buffer) - 1]))
		buffer[strlen(buffer) - 1] = '\0';
	if (!strcmp(buffer, "!!")) {
		if (write(s, history, strlen(history)) < 0)
			DEBUG(LOG_ERR, "write() failed: %s\n", __FUNCTION__);
		if (write(s, "\n", strlen("\n")) < 0)
			DEBUG(LOG_ERR, "write() failed: %s\n", __FUNCTION__);
		strcpy(buffer, history);
	} else if (strlen(buffer) > 0)
		strcpy(history, buffer);
	if (strlen(buffer) > 0)
		dispatch_command(s, buffer, commands, arg);

	disp_prompt(s);

	return;
}

static void
dispatch_command(s, command_line, command_table, evt)
	int s;
	char *command_line;
	struct command_table *command_table;
	void *evt;
{
	char *arg;
	struct command_table *ctbl;
	char *errmsg = "??? unknown command\n";

	if ((strncmp(command_line, "help", 4) == 0) ||
	    (strncmp(command_line, "?", 1) == 0)) {
		command_help(s, (char *)command_table, evt);
		return;
	}

	for (ctbl = command_table; ctbl->command != NULL; ctbl++) {
		if ((strncmp(ctbl->command, command_line, strlen(ctbl->command)) != 0))
			continue;

		arg = command_line + strlen(ctbl->command);

		while (isspace(*arg))
			arg++;

		if (ctbl->sub_cmds) {
			if (*arg == '\0')
				command_help(s, (char *)ctbl->sub_cmds, evt);
			else
				dispatch_command(s, arg, ctbl->sub_cmds, evt);
		} else {
			(*ctbl->cmdfunc)(s, arg, evt);
		}
		return;
	}

	if (write(s, errmsg, strlen(errmsg)) < 0)
		DEBUG(LOG_ERR, "write() failed: %s\n", __FUNCTION__);
	return;
}

void
command_printf(int s, const char *fmt, ...)
{
	va_list ap;
	char buffer[512];

	va_start(ap, fmt);
	vsnprintf(buffer, 512, fmt, ap);
	va_end(ap);
	if (write(s, buffer, strlen(buffer)) <0)
		DEBUG(LOG_ERR, "write() failed: %s\n", __FUNCTION__);
}

void
command_help(s, line, evt)
	int s;
	char *line;
	void *evt;
{
	struct command_table *ctbl, *base;

	base =(struct command_table *)line;

	for (ctbl = base; ctbl->command != NULL; ctbl++) {
		command_printf(s, "%-10s - %s\n",
			       ctbl->command, ctbl->helpmsg);
	}
}

void
quit_ui(s, line, arg)
	int s;
	char *line;
	void *arg;
{
	struct event *evt = (struct event *)arg;

	command_printf(s, "bye bye\n");
	event_del(evt);
	free(evt);
	close(s);
}

void got_interrupt(s, line)
	int s;
	char *line;
{
	char *buffer="\xff\xfc\x06\xff\xf2\n";

	if (write(s, buffer, 6) < 0)
		DEBUG(LOG_ERR, "write() failed: %s\n", __FUNCTION__);
}
