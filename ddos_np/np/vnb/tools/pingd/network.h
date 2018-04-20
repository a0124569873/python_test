/*
 * Copyright 2007 6WIND S.A.
 */

#ifndef _NETWORK_H_
#define _NETWORK_H_

extern uint32_t stats_request_snd;
extern uint32_t stats_request_rcv;
extern uint32_t stats_reply_rcv;

extern void check_carrier(int sock, __attribute__ ((unused))short event,
		__attribute__ ((unused))void *arg);
extern void csock_input(int sock, __attribute__ ((unused))short event,
		__attribute__ ((unused))void *arg);
extern void dsock_input(int sock, __attribute__ ((unused))short event, void *arg);
extern void send_echorequest_event(int sock, __attribute__ ((unused))short event, void *arg);

#endif /* _NETWORK_H_ */
