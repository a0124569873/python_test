/*
 * Copyright 2009 6WIND, All rights reserved.
 */
extern int routed_loglevel;
#define ROUTED_LOG(prio, fmt, args...) \
do { \
	if ((prio) <= routed_loglevel) \
		syslog((prio), "%s: " fmt "\n", __FUNCTION__, ##args); \
} while (0)
