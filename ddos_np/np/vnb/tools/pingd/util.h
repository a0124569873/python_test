/*
 * Copyright 2007-2010 6WIND S.A.
 */

#ifndef _PINGD_UTIL_H_
#define _PINGD_UTIL_H_

/* Debug */
#ifdef HAVE_ANSI_FUNC
#define DEBUG(x, y, z...) do { dbg_printf(x, __func__, y, ## z); } while(0)
#elif defined (HAVE_GCC_FUNCTION)
#define DEBUG(x, y, z...) do { dbg_printf(x, __FUNCTION__, y, ## z); } while(0)
#else
#define DEBUG(x, y, z...) do { dbg_printf(x, "", y, ## z); } while(0)
#endif
extern int log_output_stderr;
extern void setloglevel(int debuglevel);
extern void dbg_printf(int level, const char *fname, const char *fmt, ...);
extern uint32_t ascii2addr(char *ascii);
#endif /* _PINGD_UTIL_H_ */
