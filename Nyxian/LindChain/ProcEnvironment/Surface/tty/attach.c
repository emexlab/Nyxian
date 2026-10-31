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

#include <LindChain/ProcEnvironment/Surface/tty/attach.h>

bool tty_proc_event_handler(kvobject_event_type_t type,
                            uint64_t value,
                            kvobject_event_t *event)
{
    switch(type)
    {
        case kvObjEventDeinit:
        {
            return true;
        }
        case kvObjEventUnregister:
        {
            ksurface_tty_t *tty = (ksurface_tty_t*)(event->ctx);
            kvo_release(tty);
            return true;
        }
        default:
            return false;
    }
}

kern_return_t tty_hold_proc(ksurface_proc_t *proc,
                            ksurface_tty_t *tty)
{
    if(!kvo_retain(proc))
    {
        return KERN_FAILURE;
    }
    
    kern_return_t kr = kvo_event_register(proc, 0, tty_proc_event_handler, tty, NULL);
    kvo_release(proc);
    return kr;
}

kern_return_t tty_attach_proc(ksurface_proc_t *proc,
                              ksurface_tty_t *tty)
{
    kern_return_t kr = tty_hold_proc(proc, tty);
    if(kr != KERN_SUCCESS)
    {
        return kr;
    }
    
    pid_t sid;
    pid_t pgid;
    
    kvo_wrlock(proc);
    sid = proc_getsid(proc);
    pgid = proc_getpgid(proc);
    proc->bsd.kp_proc.p_flag |= P_CONTROLT;
    proc->bsd.kp_eproc.e_tpgid = pgid;
    kvo_unlock(proc);
    
    kvo_wrlock(tty);
    tty->sid = sid;
    tty->pgrp = pgid;
    kvo_unlock(tty);
    
    return KERN_SUCCESS;
}
