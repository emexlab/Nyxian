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

#ifndef PATCHFIND_LOADER_H
#define PATCHFIND_LOADER_H

#include <dlfcn.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

static inline void *nxpf_open_library(const char *root)
{
    if(!root)
    {
        return NULL;
    }

    char path[PATH_MAX];
    int size = snprintf(path, sizeof(path), "%s/boot/bootloader/Frameworks/libpatchfind.dylib", root);
    if(size < 0 || (size_t)size >= sizeof(path))
    {
        return NULL;
    }
    
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

#endif /* PATCHFIND_LOADER_H */
