/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013 Nicira, Inc.
 * Copyright 2014 6WIND S.A.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _FPVS_HASH_H
#define _FPVS_HASH_H

static inline uint32_t
hash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

/* Murmurhash by Austin Appleby,
 * from http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp.
 *
 * The upstream license there says:
 *
 * // MurmurHash3 was written by Austin Appleby, and is placed in the public
 * // domain. The author hereby disclaims copyright to this source code.
 *
 * See hash_words() for sample usage. */
/* Returns the hash of the 'n' bytes at 'p', starting from 'basis'. */

static inline uint32_t mhash_add__(uint32_t hash, uint32_t data)
{
    data *= 0xcc9e2d51;
    data = hash_rot(data, 15);
    data *= 0x1b873593;
    return hash ^ data;
}

static inline uint32_t mhash_add(uint32_t hash, uint32_t data)
{
    hash = mhash_add__(hash, data);
    hash = hash_rot(hash, 13);
    return hash * 5 + 0xe6546b64;
}

static inline uint32_t mhash_finish(uint32_t hash, size_t n_bytes)
{
    hash ^= n_bytes;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

static inline uint32_t
hash_bytes_masked(const void *p_, const void *m_,
	   size_t n, uint32_t basis)
{
    const uint32_t *p = p_;
    const uint32_t *m = m_;
    size_t orig_n = n;
    uint32_t hash;
    uint32_t tmp = 0;

    hash = basis;
    while (n >= 4) {
        hash = mhash_add(hash, (*p) & (*m));
        n -= 4;
        p += 1;
        m += 1;
    }

    switch (3 - (orig_n & 0x03)) {
        case 0:
            tmp |= *((const uint8_t *)p + 2) << 16;
            tmp &= *((const uint8_t *)m + 2) << 16;
            /* Fallthrough */
        case 1:
            tmp |= *((const uint8_t *)p + 1) << 8;
            tmp &= *((const uint8_t *)m + 1) << 8;
            /* Fallthrough */
        case 2:
            tmp |= *((const uint8_t *)p);
            tmp &= *((const uint8_t *)p);
            hash = mhash_add__(hash, tmp);
        default:
            break;
    }

    return mhash_finish(hash, orig_n);
}

#endif /* _FPVS_HASH_H */
