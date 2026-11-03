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

#include "NXLiveProcessABI.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int NXLiveProcessSelectPathV1(const char *mode,
                              const char *version)
{
    if(!mode || !mode[0])
    {
        return version && version[0] ? -EINVAL : 0;
    }
    if(!strcmp(mode, "legacy"))
    {
        return !version || !version[0] || !strcmp(version, "1") ? 0 : -EPROTONOSUPPORT;
    }
    if(strcmp(mode, NX_LIVEPROCESS_LIBSYSTEM_MODE))
    {
        return -ENOTSUP;
    }
    return version && !strcmp(version, "1") ? 1 : -EPROTONOSUPPORT;
}

int NXLiveProcessValidateModuleV1(const NXLiveProcessSimulatorModuleDescriptorV1 *module)
{
    if(!module || module->version != NX_LIVEPROCESS_ABI_VERSION || module->size < sizeof(*module))
    {
        return EPROTONOSUPPORT;
    }
    if(module->flags != NX_LIVEPROCESS_MODULE_OWNS_RUNTIME || !module->main)
    {
        return EINVAL;
    }
    return 0;
}

static int validateFile(const char *path,
                        const char *expected,
                        struct stat *original)
{
    if(!path || path[0] != '/' || !expected || strlen(expected) != 64)
    {
        return EINVAL;
    }
    for(unsigned i = 0; i < 64; ++i)
    {
        if(!((expected[i] >= '0' && expected[i] <= '9') || (expected[i] >= 'a' && expected[i] <= 'f')))
        {
            return EINVAL;
        }
    }
    
    char canonical[PATH_MAX];
    if(!realpath(path, canonical))
    {
        return errno;
    }
    
    if(strcmp(path, canonical))
    {
        return ELOOP;
    }
    
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0)
    {
        return errno;
    }
    int error = fstat(fd, original) ? errno : 0;
    if(!error && (!S_ISREG(original->st_mode) || original->st_size < 32))
    {
        error = EINVAL;
    }
    
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    unsigned char buffer[16384], digest[CC_SHA256_DIGEST_LENGTH];
    while(!error)
    {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if(count < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            error = errno;
            break;
        }
        if(!count)
        {
            break;
        }
        CC_SHA256_Update(&hash, buffer, (CC_LONG)count);
    }
    close(fd);
    if(error)
    {
        return error;
    }
    CC_SHA256_Final(digest, &hash);
    static const char hex[] = "0123456789abcdef";
    for(unsigned i = 0; i < sizeof(digest); ++i)
    {
        if(expected[i * 2] != hex[digest[i] >> 4] || expected[i * 2 + 1] != hex[digest[i] & 15])
        {
            return EAUTH;
        }
    }
    return 0;
}

int NXLiveProcessRunLibSystemV1(const char *path,
                                const char *sha256,
                                const NXLiveProcessStartV1 *start,
                                int *moduleStatus)
{
    if(!start || start->version != 1 || start->size < sizeof(*start) || start->flags || !moduleStatus)
    {
        return EINVAL;
    }
    struct stat original, after;
    int error = validateFile(path, sha256, &original);
    if(error)
    {
        return error;
    }
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if(!handle)
    {
        return ENOEXEC;
    }
    
    if(lstat(path, &after) || original.st_dev != after.st_dev || original.st_ino != after.st_ino || original.st_size != after.st_size || original.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || original.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec)
    {
        return ESTALE;
    }
    
    NXLiveProcessSimulatorModuleQueryV1 query = (NXLiveProcessSimulatorModuleQueryV1)dlsym(handle, NX_LIVEPROCESS_MODULE_SYMBOL);
    Dl_info queryImage = {0}, mainImage = {0};
    char provider[PATH_MAX];
    if(!query || !dladdr((void *)query, &queryImage) || !queryImage.dli_fname || !realpath(queryImage.dli_fname, provider) || strcmp(provider, path))
    {
        return ENOEXEC;
    }
    
    const NXLiveProcessSimulatorModuleDescriptorV1 *module = query(1, sizeof(*start));
    error = NXLiveProcessValidateModuleV1(module);
    if(error)
    {
        return error;
    }
    
    if(!dladdr((void *)module->main, &mainImage) || mainImage.dli_fbase != queryImage.dli_fbase)
    {
        return EXDEV;
    }
    
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if(task_threads(mach_task_self(), &threads, &count))
    {
        return EIO;
    }
    
    for(mach_msg_type_number_t i = 0; i < count; ++i)
    {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    if(count != 1)
    {
        return EBUSY;
    }
    *moduleStatus = module->main(start);
    return 0;
}
