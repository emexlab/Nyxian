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

#include <LindChain/ProcEnvironment/Surface/libkern/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <os/lock.h>
#include <assert.h>
#include <string.h>

#define KSURFACE_VERSION_LENGTH 4

static int ksurface_version_buffer[KSURFACE_VERSION_LENGTH] = { 0, 11, 6, 3 };

int ksurface_version_get_length(void)
{
    return KSURFACE_VERSION_LENGTH;
}

const char *ksurface_version_get_string(void)
{
    /* need to be locked */
    static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
    static char *version_str = NULL;
    
    /* now we enter the lock */
    os_unfair_lock_lock(&lock);
    
    if(version_str != NULL)
    {
        /* fast path */
        os_unfair_lock_unlock(&lock);
        return version_str;
    }
    
    /* first we query the size needed */
    size_t needed_size = 1;
    for(int index = 0; index < KSURFACE_VERSION_LENGTH; index++)
    {
        if(index != 0)
        {
            /* acounting for the dot */
            needed_size++;
        }
        needed_size += (size_t)snprintf(NULL, 0, "%d", ksurface_version_buffer[index]);
    }
    
    /* now we allocate the string */
    version_str = malloc(needed_size);
    if(version_str == NULL)
    {
        os_unfair_lock_unlock(&lock);
        return NULL;
    }
    
    size_t written_size = 0;
    for(int index = 0; index < KSURFACE_VERSION_LENGTH; index++)
    {
        if(index != 0)
        {
            written_size += (size_t)snprintf(version_str + written_size, needed_size, ".");
        }
        written_size += (size_t)snprintf(version_str + written_size, needed_size, "%d", ksurface_version_buffer[index]);
    }
    
    os_unfair_lock_unlock(&lock);
    
    return version_str;
}

kern_return_t ksurface_version_get_buffer(int *buffer,
                                          size_t *size)
{
    if(buffer == NULL || size == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    /* size query? */
    bool buffer_fits = *size >= KSURFACE_VERSION_LENGTH;
    *size = KSURFACE_VERSION_LENGTH;    /* caller always gets length to query size */
    if(!buffer_fits)
    {
        return KERN_NO_SPACE;
    }
    
    /* write buffer */
    memcpy(buffer, ksurface_version_buffer, KSURFACE_VERSION_LENGTH);
    
    return KERN_SUCCESS;
}
