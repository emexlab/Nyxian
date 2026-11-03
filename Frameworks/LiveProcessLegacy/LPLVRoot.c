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

#include <LiveProcessLegacy/LPLVRoot.h>
#include <LiveProcessLegacy/LPLSyscall.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ksurface_abi.h>
#include <os/lock.h>
#include <stdlib.h>
#include <string.h>

const char *liveshim_vroot(void)
{
    /* store location for vroot */
    static char vroot[PATH_MAX];
    static bool got_vroot = false;
    
    /* lock so this critical section won't run concurrent */
    static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
    os_unfair_lock_lock(&lock);
    
    if(got_vroot)
    {
        os_unfair_lock_unlock(&lock);
        goto got_vroot_already;
    }
    
    /* asking ksurface using it's own API for the vroot path */
    if(liveshim_syscall(SYS_vroot, vroot) == 0 && vroot[0] != '\0')
    {
        got_vroot = true;
    }
    else
    {
        os_unfair_lock_unlock(&lock);
        return NULL;
    }
    
    os_unfair_lock_unlock(&lock);
    
got_vroot_already:
    return vroot;
}
