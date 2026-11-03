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

#include <LiveProcessLegacy/LPLShim.h>
#include <Broadpatch/Broadpatch.h>

static inline kern_return_t __task_for_pid(mach_port_name_t tp_in,
                                           pid_t pid,
                                           mach_port_name_t *tp_out,
                                           bool name_port)
{
    if(tp_out == NULL)
    {
        return KERN_FAILURE;
    }
    
    *tp_out = MACH_PORT_NULL;   /* SYS_gettask may not zero it out on failure */
    int64_t ret = liveshim_syscall(SYS_task_for_pid, pid, name_port, tp_out);
    if(ret == -1 || *tp_out == MACH_PORT_NULL)
    {
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

LIBKERN_PATCH(kern_return_t, task_for_pid, (mach_port_name_t tp_in,
                                            pid_t pid,
                                            mach_port_name_t *tp_out),
{
    return __task_for_pid(tp_in, pid, tp_out, false);
});

LIBKERN_PATCH(kern_return_t, task_name_for_pid, (mach_port_name_t tp_in,
                                                 pid_t pid,
                                                 mach_port_name_t *tp_out),
{
    return __task_for_pid(tp_in, pid, tp_out, true);
});

/* NEED PATCHES FOR READ AND INSPECT */

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(task_for_pid);
    LIBKERN_INSTALL_PATCH(task_name_for_pid);
}
