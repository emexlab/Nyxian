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

#ifndef NXCOWCACHE_H
#define NXCOWCACHE_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static inline int NXCoWCloneFile(const char *source,
                                 const char *destination)
{
    if(!source || !destination || source[0] != '/' || destination[0] != '/')
    {
        return EINVAL;
    }
    
    char canonical[PATH_MAX], parent[PATH_MAX], lockName[NAME_MAX + 1], temporary[64] = {0};
    if(!realpath(source, canonical))
    {
        return errno;
    }
    if(strcmp(source, canonical))
    {
        return ELOOP;
    }
    
    if(strlen(destination) >= sizeof(parent))
    {
        return ENAMETOOLONG;
    }
    
    strcpy(parent, destination);
    char *separator = strrchr(parent, '/');
    if(!separator || separator == parent)
    {
        return EINVAL;
    }
    
    const char *leaf = destination + (separator - parent) + 1;
    if(!leaf[0] || !strcmp(leaf, ".") || !strcmp(leaf, ".."))
    {
        return EINVAL;
    }
    *separator = 0;
    if(!realpath(parent, canonical))
    {
        return errno;
    }
    if(strcmp(parent, canonical))
    {
        return ELOOP;
    }
    int sourceFD = open(source, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if(sourceFD < 0)
    {
        return errno;
    }
    int directoryFD = -1, lockFD = -1, cloneFD = -1, error = 0;
    struct stat metadata;
    if(fstat(sourceFD, &metadata))
    {
        error = errno;
        goto done;
    }
    
    if(!S_ISREG(metadata.st_mode))
    {
        error = EINVAL;
        goto done;
    }
    
    directoryFD = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if(directoryFD < 0)
    {
        error = errno;
        goto done;
    }
    
    int length = snprintf(lockName, sizeof(lockName), ".%s.nxlock", leaf);
    if(length < 0 || (size_t)length >= sizeof(lockName))
    {
        error = ENAMETOOLONG;
        goto done;
    }
    
    lockFD = openat(directoryFD, lockName, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if(lockFD < 0 || flock(lockFD, LOCK_EX))
    {
        error = errno;
        goto done;
    }
    
    if(!fstatat(directoryFD, leaf, &metadata, AT_SYMLINK_NOFOLLOW))
    {
        if(!S_ISREG(metadata.st_mode))
        {
            error = ELOOP;
            goto done;
        }
    } else if(errno != ENOENT)
    {
        error = errno;
        goto done;
    }
    
    snprintf(temporary, sizeof(temporary), ".nxclone-%d-%08x", getpid(), arc4random());
    if(fclonefileat(sourceFD, directoryFD, temporary, CLONE_NOOWNERCOPY))
    {
        error = errno; temporary[0] = 0;
        goto done;
    }
    cloneFD = openat(directoryFD, temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if(cloneFD < 0)
    {
        error = errno;
        goto done;
    }
    if(fchmod(cloneFD, 0500) || renameat(directoryFD, temporary, directoryFD, leaf))
    {
        error = errno;
        goto done;
    }
    temporary[0] = 0;
done:
    
    if(temporary[0] && directoryFD >= 0)
    {
        unlinkat(directoryFD, temporary, 0);
    }
    if(cloneFD >= 0)
    {
        close(cloneFD);
    }
    if(lockFD >= 0)
    {
        close(lockFD);
    }
    if(directoryFD >= 0)
    {
        close(directoryFD);
    }
    close(sourceFD);
    return error;
}

static inline int NXCoWCacheInDocuments(const char *source,
                                        const char *home,
                                        char *output,
                                        size_t capacity)
{
    if(!source || !home || !output || !capacity || home[0] != '/')
    {
        return EINVAL;
    }
    char physical[PATH_MAX], documents[PATH_MAX];
    if(!realpath(home, physical))
    {
        return errno;
    }
    int length = snprintf(documents, sizeof(documents), "%s/Documents", physical);
    if(length < 0 || (size_t)length >= sizeof(documents))
    {
        return ENAMETOOLONG;
    }
    if(mkdir(documents, 0700) && errno != EEXIST)
    {
        return errno;
    }
    const char *leaf = strrchr(source, '/');
    if(!leaf || !leaf[1])
    {
        return EINVAL;
    }
    length = snprintf(output, capacity, "%s/%s", documents, leaf + 1);
    if(length < 0 || (size_t)length >= capacity)
    {
        return ENAMETOOLONG;
    }
    return NXCoWCloneFile(source, output);
}

#endif /* NXCOWCACHE_H */
