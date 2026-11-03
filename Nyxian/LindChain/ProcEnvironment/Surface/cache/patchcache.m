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

#import <Foundation/Foundation.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <LindChain/ProcEnvironment/Surface/cache/patchcache.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#include <dlfcn.h>

kern_return_t ksurface_patchcache_emit(void)
{
    NSURL *binary = [NSBundle.mainBundle.privateFrameworksURL URLByAppendingPathComponent:@"libpatchfind.dylib"];
    void *library = dlopen(binary.path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    if(library == NULL)
    {
        klog_log("patchfinder:emit", "could not load the bundled libpatchfind: %s", dlerror() ?: "unknown error");
        return KERN_FAILURE;
    }
    
    /* the library says how large the base table is: the kernel just passes all of it on */
    uint64_t *base = NULL;
    size_t count = 0;
    nxpf_resolve_fn resolve = (nxpf_resolve_fn)dlsym(library, "nxpf_resolve");
    if(resolve != NULL)
    {
        count = resolve(NULL, 0);
        base = (count > 0 && count <= NXPF_MAX_WORDS) ? calloc(count, sizeof(uint64_t)) : NULL;
        if(base == NULL || resolve(base, count) != count)
        {
            count = 0;
        }
    }
    else
    {
        /* a bundled library from before nxpf_resolve: the table this kernel knows */
        nxpf_resolve_base_fn resolveBase = (nxpf_resolve_base_fn)dlsym(library, "nxpf_resolve_base");
        base = calloc(kDyldPtrCount, sizeof(uint64_t));
        count = (base != NULL && resolveBase != NULL && resolveBase(NXPF_BASE_ABI, base, kDyldPtrCount)) ? kDyldPtrCount : 0;
    }
    if(count == 0)
    {
        klog_log("patchfinder:emit", "the bundled libpatchfind could not resolve the base table");
        free(base);
        return KERN_FAILURE;
    }
    
    /* upstream KSurface has no extras; a kernel that needs some appends them (nxpf_find_symbol) */
    size_t capacity = count * sizeof(uint64_t) + 28;
    unsigned char *bytes = malloc(capacity);
    size_t length = bytes ? nxpf_cache_encode(bytes, capacity, base, count, NXPF_BASE_ABI, 0, 0, NULL, 0) : 0;
    free(base);
    if(length == 0)
    {
        free(bytes);
        return KERN_FAILURE;
    }
    
    NSData *data = [NSData dataWithBytesNoCopy:bytes length:length freeWhenDone:YES];
    NSURL *url = [NXBootstrap.shared.rootURL URLByAppendingPathComponent:@"mntfs/bootfs/patchfinder.bin"];
    NSError *error = nil;
    if(![data writeToURL:url options:NSDataWritingAtomic error:&error])
    {
        klog_log("patchfinder:emit", "could not write patchfinder cache: %s", error.localizedDescription.UTF8String ?: "unknown error");
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}
