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

#include <LindChain/ProcEnvironment/Surface/surface.h>
#include <LindChain/ProcEnvironment/Surface/tty/lookup.h>
#include <LindChain/ProcEnvironment/Surface/libkern/bsd/proc_info.h>

kern_return_t tty_for_port(fileport_t port,
                           ksurface_tty_t **tty)
{
    /* sanity check */
    assert(tty != NULL);
    
    /* getting file descriptor */
    int fd = fileport_makefd(port);
    if(fd < 0)
    {
        return KERN_INVALID_RIGHT;
    }
    
    /* getting unique object pointer */
    struct socket_fdinfo si;
    int ret = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
    close(fd);
    if(ret <= 0)
    {
        return KERN_FAILURE;
    }
    
    /* tty tree lookup */
    tty_table_rdlock();
    ksurface_tty_t *found = radix_lookup(&(ksurface->tty_info.tty), si.psi.soi_proto.pri_kern_ctl.kcsi_id);
    if(found == NULL)
    {
        tty_table_unlock();
        return KERN_NOT_FOUND;
    }
    
    /*
     * caller expects retained tty object, so
     * attempting to retain it and if it doesnt work
     * returning with an error.
     */
    bool retained = kvo_retain(found);
    tty_table_unlock();
    if(!retained)
    {
        return KERN_FAILURE;
    }
    
    *tty = found;
    
    return KERN_SUCCESS;
}
