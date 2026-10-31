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

#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#include <LindChain/ProcEnvironment/Surface/libkern/task_handoff.h>
#include <ksurface_abi.h>
#include <assert.h>
#include <mach/exc.h>

int64_t liveshim_syscall(uint32_t syscall_num, ...);

void task_normalize(void)
{
    /* tools like reveil love to pretend they can detect it for ever */
    mach_port_urefs_t refs = 0;
    kern_return_t err;
    err = mach_port_get_refs(mach_task_self(), mach_task_self(), MACH_PORT_RIGHT_SEND, &refs);
    if(err != KERN_SUCCESS)
    {
        return;
    }
    while(refs > 2)
    {
        err = mach_port_deallocate(mach_task_self(), mach_task_self());
        if(err != KERN_SUCCESS)
        {
            break;
        }
        err = mach_port_get_refs(mach_task_self(), mach_task_self(), MACH_PORT_RIGHT_SEND, &refs);
        if(err != KERN_SUCCESS)
        {
            break;
        }
    }
}

typedef struct {
    union {
        __Request__exception_raise_t v;
        uint8_t pad[1024];
    };
} __Request__exception_raise_large_t;

kern_return_t task_handoff(mach_port_t exceptionPort,
                           task_t *task)
{
    kern_return_t kr = KERN_FAILURE;
    
#if !HOST_ENV
    bool success = false;
    bool needs_restore = false;
    
    /*
     * constructing the exception port and
     * setting it to our task for the host,
     * to receive the IKOT_TASK of the guest
     * through it, therefore receiving full
     * power over the guest.
     */
    mach_port_options_t opt = {
        .flags =  MPO_PORT | MPO_INSERT_SEND_RIGHT
    };
    
    thread_t thread = mach_thread_self();
    mach_msg_type_number_t old_count = 0;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_ports[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    needs_restore = thread_get_exception_ports(thread, EXC_MASK_BREAKPOINT, old_masks, &old_count, old_ports, old_behaviors, old_flavors) == KERN_SUCCESS;
    
    kr = mach_port_construct(mach_task_self(), &opt, 0, &exceptionPort);
    if(kr != KERN_SUCCESS)
    {
        mach_port_deallocate(mach_task_self(), thread);
        return KERN_FAILURE;
    }
    
    kr = thread_set_exception_ports(thread, EXC_MASK_BREAKPOINT, exceptionPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    if(kr != KERN_SUCCESS)
    {
        goto out_dealloc;
    }
    
    /* handing off receive right to host environment */
    if(liveshim_syscall(SYS_handoffep, exceptionPort) != 0)
    {
        goto out_dealloc;
    }
    
    /*
     * this causes EXC_BREAKPOINT, which causes
     * a mach exception which will be sent to the
     * exception port which the host now holds the
     * receive right of meaning the host will
     * handle this pseudo exception.
     */
    __asm__ volatile ("brk #1" ::: "memory");   /* no Duy I haven't copied this from you if you use the same ASM, I use it so the compiler stops stripping away "success = true" */
    success = true; /* handoff should have succeeded */
    
out_dealloc:
    /*
     * task kernel port has been handoffed
     * since the exception port was moved to
     * the host process we just need one dealloc.
     */
    if(needs_restore)
    {
        for(mach_msg_type_number_t i = 0; i < old_count; i++)
        {
            thread_set_exception_ports(thread, old_masks[i], old_ports[i], old_behaviors[i], old_flavors[i]);
            mach_port_deallocate(mach_task_self(), old_ports[i]);
        }
    }
    else
    {
        thread_set_exception_ports(thread, EXC_MASK_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    }
    
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), exceptionPort);
    task_normalize();
    if(success)
    {
        liveshim_syscall(SYS_waittask, getpid());
    }
    return success ? KERN_SUCCESS : KERN_FAILURE;
    
#else
    assert(task != NULL);
    
    /* preinitilize so the MACH_PORT_NULL sentinel always works */
    *task = MACH_PORT_NULL;
    
    /* will carry request buffer */
    __Request__exception_raise_large_t request;
    
    /* receiving pseudo exception caused by guest */
    request.v.Head.msgh_local_port = exceptionPort;
    request.v.Head.msgh_size = (mach_msg_size_t)sizeof(request);
    mach_msg_return_t mr = mach_msg(&(request.v.Head), MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(request), exceptionPort, 1000, MACH_PORT_NULL);
    if(mr != MACH_MSG_SUCCESS)
    {
        klog_log("task_handoff", "failed to receive task port right: %s", mach_error_string(mr));
        return KERN_FAILURE;
    }
    
    /* validating message header */
    if((request.v.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 ||
       (request.v.Head.msgh_bits & MACH_MSGH_BITS_PORTS_MASK) != MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, MACH_MSG_TYPE_PORT_SEND))
    {
        klog_log("task_handoff", "malformed mach message header");
        goto out_failure;
    }
    
    /* validate message descriptors */
    if(request.v.msgh_body.msgh_descriptor_count != 2 ||
       request.v.thread.type != MACH_MSG_PORT_DESCRIPTOR ||
       request.v.task.type != MACH_MSG_PORT_DESCRIPTOR)
    {
        klog_log("task_handoff", "malformed mach message body");
        goto out_failure;
    }
    
    /* task port validation */
    ipc_info_object_type_t task_type;
    mach_vm_address_t address;
    kr = mach_port_kobject(mach_task_self(), request.v.task.name, &task_type, &address);
    if(kr != KERN_SUCCESS)
    {
        klog_log("task_handoff", "failed getting the task kobject type: %s", mach_error_string(kr));
        goto out_failure;
    }
    
    ipc_info_object_type_t thread_type;
    kr = mach_port_kobject(mach_task_self(), request.v.thread.name, &thread_type, &address);
    if(kr != KERN_SUCCESS)
    {
        klog_log("task_handoff", "failed getting the thread kobject type: %s", mach_error_string(kr));
        goto out_failure;
    }
    
    /* checking for ipc object type */
    if(task_type != IPC_OTYPE_TASK_CONTROL)  /* also known as IKOT_TASK.. aka kernel task port */
    {
        klog_log("task_handoff", "port %d backed by ipc object with type %d is not a IKOT_TASK ipc object", request.v.task.name, task_type);
        goto out_failure;
    }
    
    if(thread_type != IPC_OTYPE_THREAD_CONTROL)
    {
        klog_log("task_handoff", "port %d backed by ipc object with type %d is not a thread ipc object", request.v.thread.name, thread_type);
        goto out_failure;
    }
    
    /*
     * now manipulate thread state of the thread
     * in the guest that has the exception, because
     * its a pseudo exception and if we wont skip
     * over the pseudo exception it will reexecute
     * it or crash.
     */
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(request.v.thread.name, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    if(kr != KERN_SUCCESS)
    {
        klog_log("task_handoff", "failed to get thread state of guest: %s", mach_error_string(kr));
        goto out_failure;
    }
    
    /* skipping over __builtin_trap */
    state.__pc += 4;
    
    kr = thread_set_state(request.v.thread.name, ARM_THREAD_STATE64, (thread_state_t)&state, count);
    if(kr != KERN_SUCCESS)
    {
        klog_log("task_handoff", "failed to restore thread state of guest: %s", mach_error_string(kr));
        goto out_failure;
    }
    
    kr = mach_port_mod_refs(mach_task_self(), request.v.task.name, MACH_PORT_RIGHT_SEND, 1);
    if(kr != KERN_SUCCESS)
    {
        klog_log("task_handoff", "failed to increment task port send right: %s", mach_error_string(kr));
        goto out_failure;
    }
    
    *task = request.v.task.name;
    kr = KERN_SUCCESS;
    
out_destroy_request:
    {
        /* after replying the kernel will happily continue executing the task */
        __Reply__exception_raise_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request.v.Head.msgh_bits), 0);
        reply.Head.msgh_id = request.v.Head.msgh_id + 100;
        reply.Head.msgh_local_port = MACH_PORT_NULL;
        reply.Head.msgh_remote_port = request.v.Head.msgh_remote_port;
        reply.Head.msgh_size = sizeof(reply);
        reply.NDR = NDR_record;
        reply.RetCode = kr;
        mr = mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(mr == MACH_MSG_SUCCESS)
        {
            request.v.Head.msgh_remote_port = MACH_PORT_NULL;
        }
        else
        {
            klog_log("task_handoff", "failed to reply back to kernel: %s", mach_error_string(mr));
        }
        
        mach_msg_destroy(&(request.v.Head));
        return *task == MACH_PORT_NULL ? KERN_FAILURE : KERN_SUCCESS;
    }
out_failure:
    /* preventing state of handoff leakage */
    kr = KERN_FAILURE;
    goto out_destroy_request;
#endif /* HOST_ENV */
}
