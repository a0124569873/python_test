/*
 * Copyright(c) 2013 6WIND
 */

#ifndef __LOG_H__
#define __LOG_H__

/* PLUGIN_NAME must be defined before including this header */
#define PLUGIN_ERR(fmt, ...) \
	fprintf(stderr, PLUGIN_NAME ": " fmt, ##__VA_ARGS__);
#define PLUGIN_INFO(fmt, ...) \
	fprintf(stdout, PLUGIN_NAME ": " fmt, ##__VA_ARGS__);

#endif
