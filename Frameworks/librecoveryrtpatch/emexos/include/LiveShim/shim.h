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

#ifndef LIVESHIM_SHIM_H
#define LIVESHIM_SHIM_H

#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <LiveShim/LiveShimSyscall.h>
#include <LiveShim/fileport.h>
#include <ksurface_abi.h>

#define INTERPOSE(_replacement, _replacee)                          \
    __attribute__((used))                                           \
    static struct {                                                 \
        const void *replacement;                                    \
        const void *replacee;                                       \
    } _interpose_##_replacee                                        \
    __attribute__((section("__DATA,__interpose"))) = {              \
        (const void *)(unsigned long)&_replacement,                 \
        (const void *)(unsigned long)&_replacee                     \
    }

struct interpose_pair {
    const void *replacement;
    const void *replacee;
};

#endif /* LIVESHIM_SHIM_H */
