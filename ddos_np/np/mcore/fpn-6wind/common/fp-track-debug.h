#ifndef __FP_TRACK_DEBUG_H__
#define __FP_TRACK_DEBUG_H__

/* Use FPN-SDK tracking if MCORE_DEBUG is set */
#if defined(CONFIG_MCORE_DEBUG) && defined(__FastPath__)
#define FPN_TRACK FPN_RECORD_TRACK
#else
#define FPN_TRACK() do {} while (0)
#endif

#endif
