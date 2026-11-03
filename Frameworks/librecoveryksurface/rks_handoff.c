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

#include "rks.h"
#include <mach/exc.h>
#include <mach/thread_status.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

typedef struct {
    union {
        __Request__exception_raise_t v;
        uint8_t pad[1024];
    };
} rks_exception_request_t;

kern_return_t rks_task_handoff_receive(mach_port_t exception_port, task_t *task)
{
    *task = MACH_PORT_NULL;
    
    rks_exception_request_t request;
    memset(&request, 0, sizeof(request));
    request.v.Head.msgh_local_port = exception_port;
    request.v.Head.msgh_size = (mach_msg_size_t)sizeof(request);
    mach_msg_return_t mr = mach_msg(&request.v.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(request), exception_port, 1000, MACH_PORT_NULL);
    if(mr != MACH_MSG_SUCCESS)
    {
        rks_logf("handoff: no exception message (0x%x)", mr);
        return KERN_FAILURE;
    }
    
    kern_return_t kr = KERN_FAILURE;
    if((request.v.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 ||
       request.v.msgh_body.msgh_descriptor_count != 2 ||
       request.v.thread.type != MACH_MSG_PORT_DESCRIPTOR ||
       request.v.task.type != MACH_MSG_PORT_DESCRIPTOR)
    {
        rks_logf("handoff: malformed exception message");
        goto reply;
    }
    
    /* step over the brk #1 so the guest continues behind it */
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(request.v.thread.name, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    if(kr != KERN_SUCCESS)
    {
        goto reply;
    }
    /* arm64 slice only (like the bootloader), the thread state is not opaque there */
    state.__pc += 4;
    kr = thread_set_state(request.v.thread.name, ARM_THREAD_STATE64, (thread_state_t)&state, count);
    if(kr != KERN_SUCCESS)
    {
        goto reply;
    }
    
    kr = mach_port_mod_refs(mach_task_self(), request.v.task.name, MACH_PORT_RIGHT_SEND, 1);
    if(kr == KERN_SUCCESS)
    {
        *task = request.v.task.name;
    }
    
reply:
    {
        __Reply__exception_raise_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request.v.Head.msgh_bits), 0);
        reply.Head.msgh_id = request.v.Head.msgh_id + 100;
        reply.Head.msgh_remote_port = request.v.Head.msgh_remote_port;
        reply.Head.msgh_size = sizeof(reply);
        reply.NDR = NDR_record;
        reply.RetCode = kr;
        if(mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS)
        {
            request.v.Head.msgh_remote_port = MACH_PORT_NULL;
        }
        mach_msg_destroy(&request.v.Head);
    }
    return *task == MACH_PORT_NULL ? KERN_FAILURE : KERN_SUCCESS;
}

int64_t rks_sys_handoffep(rks_call_t *call)
{
    if(call->in_count < 1 || call->in_ports == NULL || call->in_disposition != MACH_MSG_TYPE_MOVE_RECEIVE ||
       !MACH_PORT_VALID(call->in_ports[0]))
    {
        RKS_FAIL(call, EINVAL);
    }
    
    pthread_mutex_lock(&rks_proc_lock);
    if(call->proc->task != MACH_PORT_NULL)
    {
        /* once per process lifetime */
        pthread_mutex_unlock(&rks_proc_lock);
        RKS_FAIL(call, EPERM);
    }
    call->proc->handoff_pending = true;
    pthread_mutex_unlock(&rks_proc_lock);
    
    /* keep the receive right, reply first: the guest executes brk only after the syscall returned */
    mach_port_t exception_port = call->in_ports[0];
    call->in_ports[0] = MACH_PORT_NULL;
    rks_send_reply(call->buffer, 0, NULL, 0, 0);
    call->buffer = NULL;
    
    task_t task = MACH_PORT_NULL;
    kern_return_t kr = rks_task_handoff_receive(exception_port, &task);
    mach_port_mod_refs(mach_task_self(), exception_port, MACH_PORT_RIGHT_RECEIVE, -1);
    
    pid_t pid = -1;
    if(kr != KERN_SUCCESS || pid_for_task(task, &pid) != KERN_SUCCESS || pid != call->proc->pid)
    {
        if(task != MACH_PORT_NULL)
        {
            mach_port_deallocate(mach_task_self(), task);
        }
        rks_logf("handoff of pid %d failed, killing it", call->proc->pid);
        pthread_mutex_lock(&rks_proc_lock);
        call->proc->handoff_pending = false;
        pthread_mutex_unlock(&rks_proc_lock);
        rks_proc_signal(call->proc, SIGKILL);
        return 0;
    }
    
    rks_proc_set_task(call->proc, task);
    return 0;
}
