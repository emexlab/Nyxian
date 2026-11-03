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

#import "NXBootArgumentsHost.h"
#include <os/lock.h>
#include <stdlib.h>
#include <string.h>

static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static const char *g_arguments = "";

void NXBootArgumentsHostSet(NSString *arguments)
{
    const char *copy = strdup(arguments.UTF8String ?: "");
    if(copy == NULL)
    {
        return;
    }
    os_unfair_lock_lock(&g_lock);
    /* the previous copy is never freed: a ROM may still hold the pointer NXBootGetArguments() gave it */
    g_arguments = copy;
    os_unfair_lock_unlock(&g_lock);
}

/* Host export (0.11.6.2+), ROMs resolve it through NXBootArgsCopy() (dlsym(RTLD_DEFAULT, ...)). */
__attribute__((used, visibility("default"))) const char *NXBootGetArguments(void)
{
    os_unfair_lock_lock(&g_lock);
    const char *arguments = g_arguments;
    os_unfair_lock_unlock(&g_lock);
    return arguments;
}
