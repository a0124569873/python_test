/*
 * Copyright(c) 2011 6WIND, All rights reserved.
 */

#ifndef _FPN_MBUF_TRACK_H_
#define _FPN_MBUF_TRACK_H_

#ifndef CONFIG_MCORE_FPN_MBUF_TRACK

struct m_track;

#define m_track_init() ((void)0)
#define m_track_untrack(m) ((void)0)
#define m_track(m, fi, fu, l, g) ((void)0)
#define m_track_update_seg(m, inc) ((void)0)

#else /* CONFIG_MCORE_FPN_MBUF_TRACK */

#ifndef CONFIG_MCORE_MBUF_TRACK_SIZE
#define CONFIG_MCORE_MBUF_TRACK_SIZE 32768
#endif

struct mbuf;
struct m_track {
	char file[64]; /* __FILE__ */
	char func[64]; /* __func__ */
	char group[16];
	int32_t line; /* __LINE__ */
	uint64_t mbuf_hits;    /* total number of mbuf hits for this entry */
	int32_t  mbuf_tracked; /* current number of mbufs tracked by this entry,
	                          signed in order to help underflow detection */
	uint64_t seg_hits;     /* total number of hits for this entry */
	int32_t  seg_tracked;  /* current number of mbuf segments tracked by this entry,
	                          signed in order to help underflow detection */
};

extern void m_track_init(void);
extern void m_track_untrack(struct mbuf *m);
extern void m_track_update_seg(struct mbuf *m, int32_t inc);
extern void m_track(struct mbuf *m, const char *file, const char *func,
		    int32_t line, const char *group);

#endif /* CONFIG_MCORE_FPN_MBUF_TRACK */

#define M_TRACK_INIT() (m_track_init())
#define M_TRACK_UNTRACK(mbuf) (m_track_untrack(mbuf))
#define M_TRACK_UPDATE_SEG(mbuf, inc) (m_track_update_seg(mbuf, inc))
#define M_TRACK(mbuf, group)					\
	(m_track(mbuf, __FILE__, __func__, __LINE__, (group)))

#endif /* _FPN_MBUF_TRACK_H_ */
