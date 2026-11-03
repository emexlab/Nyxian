/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

#ifndef NX_LIBPATCHFIND_H
#define NX_LIBPATCHFIND_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define NXPF_BASE_ABI 1u
#define NXPF_END UINT64_MAX
#define NXPF_MAX_WORDS 4096u
#define NXPF_MAX_BYTES (NXPF_MAX_WORDS * 16u + 28u)
#define NXPF_SWITZACH_SCHEMA 0x53575a31u
#define NXPF_SWITZACH_ABI 1u

enum {
    kDyldPtrOpen = 0, kDyldPtrFcntl, kDyldPtrFstat64, kDyldPtrStat64,
    kDyldPtrOpenat, kDyldLockUnlockFunc, kDyldNSGetExecutablePathVTFN,
    kDyldProgramSDKAtLeastVTFN, kDyldGetProgramSDKVersionVTFN,
    kCFBundleMainOffset, kCFBundleMainInitedOffset, kNSBundleMainOffset,
    kDyldPtrCount
};
enum { kEDyldExpandPathFunc, kEDyldLoaderPathFunc, kEDyldLoaderRunInitializers, kEDyldPtrCount };

typedef struct {
    const unsigned char *base, *extra;
    size_t base_count, extra_count;
    uint32_t abi, extra_schema, extra_abi;
} nxpf_cache_view;

/* Wire order (little endian): base u64[], MAX, ABI u32, MAX,
 * extension schema u32, extension ABI u32, extension u64[] to EOF.
 * memcpy avoids alignment/packing assumptions around the u32 ABI field. */
static inline bool nxpf_cache_decode(const void *bytes, size_t length, nxpf_cache_view *view)
{
    if(!bytes || !view || length > NXPF_MAX_BYTES) return false;
    nxpf_cache_view parsed = {0};
    const unsigned char *p = (const unsigned char *)bytes;
    size_t offset = 0;
    uint64_t word = 0;
    for(; parsed.base_count <= NXPF_MAX_WORDS; parsed.base_count++, offset += 8) {
        if(offset > length || length - offset < 8) return false;
        memcpy(&word, p + offset, 8);
        if(word == NXPF_END) break;
    }
    if(word != NXPF_END || !parsed.base_count || parsed.base_count > NXPF_MAX_WORDS) return false;
    offset += 8;
    if(length - offset < 20) return false;
    memcpy(&parsed.abi, p + offset, 4); offset += 4;
    memcpy(&word, p + offset, 8); offset += 8;
    if(word != NXPF_END || !parsed.abi) return false;
    memcpy(&parsed.extra_schema, p + offset, 4); offset += 4;
    memcpy(&parsed.extra_abi, p + offset, 4); offset += 4;
    size_t extra_bytes = length - offset;
    if(extra_bytes % 8 || extra_bytes / 8 > NXPF_MAX_WORDS) return false;
    parsed.extra_count = extra_bytes / 8;
    if(parsed.extra_count && (!parsed.extra_schema || !parsed.extra_abi)) return false;
    if(!parsed.extra_count && (parsed.extra_schema || parsed.extra_abi)) return false;
    parsed.base = p; parsed.extra = p + offset;
    *view = parsed;
    return true;
}
static inline size_t nxpf_cache_encode(void *bytes, size_t capacity, const uint64_t *base, size_t base_count,
                                       uint32_t abi, uint32_t schema, uint32_t extra_abi,
                                       const uint64_t *extra, size_t extra_count)
{
    if(!bytes || !base || !base_count || base_count > NXPF_MAX_WORDS || extra_count > NXPF_MAX_WORDS ||
       !abi || (extra_count && (!extra || !schema || !extra_abi)) || (!extra_count && (schema || extra_abi))) return 0;
    for(size_t i = 0; i < base_count; i++) if(base[i] == NXPF_END) return 0;
    size_t length = base_count * 8 + 28 + extra_count * 8;
    if(capacity < length) return 0;
    unsigned char *p = (unsigned char *)bytes;
    uint64_t marker = NXPF_END;
    memcpy(p, base, base_count * 8); p += base_count * 8;
    memcpy(p, &marker, 8); p += 8;
    memcpy(p, &abi, 4); p += 4;
    memcpy(p, &marker, 8); p += 8;
    memcpy(p, &schema, 4); p += 4;
    memcpy(p, &extra_abi, 4); p += 4;
    if(extra_count) memcpy(p, extra, extra_count * 8);
    return length;
}

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) bool nxpf_resolve_base(uint32_t abi, uint64_t *out, size_t count);
__attribute__((visibility("default"))) void *nxpf_find_symbol(const char *image, const char *symbol);
typedef bool (*nxpf_resolve_base_fn)(uint32_t, uint64_t *, size_t);
typedef void *(*nxpf_find_symbol_fn)(const char *, const char *);
#ifdef __cplusplus
}
#endif
#endif
