/*
 * Copyright 2007-2010 6WIND S.A.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <netdb.h>
#include <time.h>
#include <sys/types.h>

#include "util.h"

int log_output_stderr = 0;
int debug_thresh = LOG_DEBUG;

void setloglevel(int debuglevel)
{
	if (log_output_stderr)
		switch(debuglevel) {
		case 0:
			debug_thresh = LOG_ERR;
			break;
		case 1:
			debug_thresh = LOG_INFO;
			break;
		default:
			debug_thresh = LOG_DEBUG;
			break;
		}
	else
		switch(debuglevel) {
		case 0:
			setlogmask(LOG_UPTO(LOG_ERR));
			break;
		case 1:
			setlogmask(LOG_UPTO(LOG_INFO));
			break;
		}
}

#ifndef LINE_MAX
#define LINE_MAX 2048
#endif

void dbg_printf(int level, const char *fname, const char *fmt, ...)
{
	va_list ap;
	char logbuf[LINE_MAX];
	int printfname = 1;

	va_start(ap, fmt);
	vsnprintf(logbuf, sizeof(logbuf), fmt, ap);

	if (*fname == '\0')
		printfname = 0;

	if (log_output_stderr && debug_thresh >= level) {
		time_t now;
		struct tm tm_default;
		struct tm *tm_now;
		const char *month[] = {
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
		};

		if ((now = time(NULL)) < 0) {
			memset(&tm_default, 0, sizeof(struct tm));
			tm_default.tm_year = 79;
			tm_default.tm_mon = 11;
			tm_default.tm_mday = 23;
			tm_now = &tm_default;
		}
		tm_now = localtime(&now);
		fprintf(stderr, "%3s/%02d/%04d %02d:%02d:%02d %s%s%s",
				month[tm_now->tm_mon], tm_now->tm_mday,
				tm_now->tm_year + 1900,
				tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
				fname, printfname ? ": " : "", logbuf);
	} else
		syslog(level, "%s%s%s", fname, printfname ? ": " : "", logbuf);
}

uint32_t ascii2addr(char *ascii)
{
	int i;
	char *cp;
	union {
		uint8_t  bytes[4];
		uint32_t inaddr;
	} addr;

        for (cp = ascii, i = 0, addr.inaddr = 0; *cp; cp++) {
                if (*cp <= '9' && *cp >= '0') {
                        addr.bytes[i] = 10 * addr.bytes[i] + (*cp - '0');
                        continue;
                }
                if (*cp == '.' && ++i <= 3)
                        continue;

		DEBUG(LOG_ERR, "fail to parse %s\n", ascii);
		return 0;
        }

	/* Address is already in network order */
	return addr.inaddr;
}
