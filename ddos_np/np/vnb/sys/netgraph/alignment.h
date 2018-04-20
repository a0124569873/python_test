/*
 * Copyright 2008-2012 6WIND S.A.
 */

#ifndef __ALIGNMENT_H__
#define __ALIGNMENT_H__

typedef union {
    u_int16_t val16;
    u_int32_t val32;
    u_int64_t val64;
} __attribute__ ((packed)) unaligned_uint_t;


typedef union {
    int16_t val16;
    int32_t val32;
    int64_t val64;
} __attribute__ ((packed)) unaligned_int_t;


#define UNALIGNED_UINT16(p)     (((unaligned_uint_t *)((char *)p))->val16)
#define UNALIGNED_UINT32(p)     (((unaligned_uint_t *)((char *)p))->val32)
#define UNALIGNED_UINT64(p)     (((unaligned_uint_t *)((char *)p))->val64)

#define UNALIGNED_INT16(p)     (((unaligned_int_t *)((char *)p))->val16)
#define UNALIGNED_INT32(p)     (((unaligned_int_t *)((char *)p))->val32)
#define UNALIGNED_INT64(p)     (((unaligned_int_t *)((char *)p))->val64)

#define NEED_PACKED

#ifdef NEED_PACKED
#define ALIGN_ATTRIB         __attribute__((packed))

#else
#define ALIGN_ATTRIB

#endif	/* NEED_PACKED */

#endif	/* __ALIGNMENT_H__ */

