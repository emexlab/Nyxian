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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <os/lock.h>
#include "patchfind_loader.h"
#include <LiveProcessLegacy/LPLVRoot.h>

#include <Frameworks/libpatchfind/libpatchfind.h>

#ifndef NXPF_CACHE_STORAGE
#define NXPF_CACHE_STORAGE
#endif /* NXPF_CACHE_STORAGE */

uint64_t actual_patchcache[kDyldPtrCount];

NXPF_CACHE_STORAGE uint64_t *patchcache = (uint64_t*)&actual_patchcache;
NXPF_CACHE_STORAGE uint64_t *epatchcache;
NXPF_CACHE_STORAGE size_t epatchcache_count;
NXPF_CACHE_STORAGE uint32_t epatchcache_schema, epatchcache_abi;

static bool g_have_ptrcache;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

NXPF_CACHE_STORAGE bool ksurface_user_patchcache_load(void)
{
    os_unfair_lock_lock(&g_lock);
    if(g_have_ptrcache)
    {
        os_unfair_lock_unlock(&g_lock);
        return true;
    }
    
    const char *root = liveshim_vroot();
    char path[PATH_MAX];
    int size = root ? snprintf(path, sizeof(path), "%s/boot/patchfinder.bin", root) : -1;
    int fd = size >= 0 && (size_t)size < sizeof(path) ? open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    unsigned char *bytes = NULL;
    nxpf_cache_view view = {0};
    bool valid = false;
    if(fd >= 0)
    {
        struct stat st;
        if(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= NXPF_MAX_BYTES)
        {
            size_t length = (size_t)st.st_size, done = 0;
            bytes = malloc(length);
            while(bytes && done < length)
            {
                ssize_t n = read(fd, bytes + done, length - done);
                if(n > 0)
                {
                    done += (size_t)n;
                }
                else if(n < 0 && errno == EINTR)
                {
                    continue;
                }
                else
                {
                    break;
                }
            }
            unsigned char extra;
            valid = bytes && done == length && read(fd, &extra, 1) == 0 && nxpf_cache_decode(bytes, length, &view);
        }
        close(fd);
    }
    uint64_t base[kDyldPtrCount] = {0};
    bool have_base = valid && view.abi == NXPF_BASE_ABI && view.base_count >= kDyldPtrCount;
    if(have_base)
    {
        memcpy(base, view.base, sizeof(base));
        for(size_t i = 0; i < kDyldPtrCount; i++) if(!base[i] || base[i] == NXPF_END) have_base = false;
    }
    if(!have_base)
    {
        void *library = nxpf_open_library(root);
        nxpf_resolve_base_fn resolve = library ? (nxpf_resolve_base_fn)dlsym(library, "nxpf_resolve_base") : NULL;
        have_base = resolve && resolve(NXPF_BASE_ABI, base, kDyldPtrCount);
    }
    uint64_t *extras = NULL;
    if(have_base && valid && view.extra_count)
    {
        extras = malloc(view.extra_count * sizeof(uint64_t));
        if(extras)
        {
            memcpy(extras, view.extra, view.extra_count * sizeof(uint64_t));
        }
        else have_base = false;
    }
    if(have_base)
    {
        memcpy(patchcache, base, sizeof(base));
        epatchcache = extras;
        epatchcache_count = valid ? view.extra_count : 0;
        epatchcache_schema = valid ? view.extra_schema : 0;
        epatchcache_abi = valid ? view.extra_abi : 0;
        g_have_ptrcache = true;
    }
    else
    {
        free(extras);
    }
    
    free(bytes);
    os_unfair_lock_unlock(&g_lock);
    return have_base;
}
