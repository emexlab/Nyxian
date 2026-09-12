/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab
 Copyright (C) 2026 semvis123

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#include <LindChain/ProcEnvironment/Surface/libkern/sys/worker.h>
#include <LindChain/ProcEnvironment/Surface/libkern/sys/core.h>
#include <LindChain/ProcEnvironment/Surface/proc/proc.h>
#import <LindChain/ProcEnvironment/Utils/kpanic.h>
#include <LindChain/ProcEnvironment/Utils/klog.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

/*
 * To ensure safety in nyxian we rely on the XNU kernel,
 * as asking processes for their pid is extremely stupid.
 * so we ensure nothing can be tempered.
 */
static ksurface_proc_snapshot_t *syscall_get_caller_proc_snapshot(mach_msg_header_t *msg)
{
    /*
     * The XNU kernel gurantees a trailer if asked
     * and syscall_worker was engineered to ask that lol ^^.
     */
    mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)((uint8_t *)msg + round_msg(msg->msgh_size));
    
    /*
     * we aren't paranoid to validate what XNU gave us,
     * since XNU gave it to us.
     */
    audit_token_t *token = &trailer->msgh_audit;
    pid_t xnu_pid = (pid_t)token->val[5];
    int xnu_pidv = (int)token->val[7];
    
    /* getting process of caller */
    ksurface_proc_t *proc = NULL;
    kern_return_t ret = proc_for_pid_with_pidv(xnu_pid, xnu_pidv, &proc);
    if(ret != KERN_SUCCESS)
    {
        return NULL;
    }
    
    /*
     * creating process snapshot with process reference consumed
     * kvo_snapshot with that configuration consumes the objects
     * reference on failure aswell.
     */
    return kvo_snapshot(proc, kvObjSnapConsumeReference);
}

/*
 * This is the symbol that sends the result from the syscall back to the guest process
 */
void syscall_send_reply(mach_msg_header_t *request,
                        int64_t result,
                        mach_port_t *out_ports,
                        uint32_t out_ports_cnt,
                        bool release_req,
                        errno_t err)
{
    /* stack allocating  */
    syscall_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    
    /*
     * writing basic syscall reply message for the
     * client.
     */
    reply.header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_MOVE_SEND_ONCE);
    reply.header.msgh_remote_port = request->msgh_remote_port;
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_id = request->msgh_id + 100;
    reply.result = result;
    reply.err = err;
    
    /*
     * this is the ports descriptor used to hand
     * mach ports to the client, such as task ports
     * file ports and more.
     */
    if(out_ports &&
       out_ports_cnt > 0)
    {
        reply.header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
        reply.body.msgh_descriptor_count = 1;
        reply.oolp.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        reply.oolp.disposition = MACH_MSG_TYPE_MOVE_SEND;
        reply.oolp.address = out_ports;
        reply.oolp.count = out_ports_cnt;
        reply.oolp.copy = MACH_MSG_PHYSICAL_COPY;
        reply.oolp.deallocate = TRUE;
    }
    
    /*
     * attempt to send reply to the child process
     * as we dont receive anything no timeout needed.
     * unless you prove me otherwise obviously.
     */
    mach_msg_return_t mr = mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(mr != MACH_MSG_SUCCESS)
    {
        mach_msg_destroy(&(reply.header));
    }
    
    /*
     * releasing request resources of the client, so
     * the stuff the client did send to us.
     */
    mach_msg_destroy(request);
    
    /*
     * if the request was taken by the syscall, then
     * the syscall will want it to be released, memory
     * wise.
     */
    if(release_req)
    {
        vm_deallocate(mach_task_self(), (vm_address_t)request, sizeof(recv_buffer_t));
    }
}

/*
 * This is similar to an kernel worker thread, it works for our "userspace" to
 * process syscalls, unlike XPC this shitty framework that can easily be poisoned
 * this is the proper way for an kernel virtualisation layer to do it,
 * because we can control raw mach to 100%
 */
void* syscall_worker(void *ctx)
{
    assert(ctx != NULL);
    
    /* getting the server */
    syscall_server_t *server = (syscall_server_t *)ctx;
    
    /* receive buffer to receive request from guest */
    recv_buffer_t *buffer = NULL;
    
    /*
     * setting options, this is what XPC cannot really give us
     * we simply tell XNU to always give us the identity of the process
     * requesting.
     */
    mach_msg_option_t options = MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    
    /* worker thread request loop */
    for(;;)
    {
        /* allocating new buffer if applicable */
        if(buffer == NULL)
        {
            kern_return_t kr = vm_allocate(mach_task_self(), (vm_address_t*)&buffer, sizeof(recv_buffer_t), VM_FLAGS_ANYWHERE);
            if(kr != KERN_SUCCESS)
            {
                /* ohh no, spin spin :c */
                continue;
            }
        }
        
        /* variables prepared for the caller  */
        int64_t result = 0;                 /* the return value of the syscall */
        mach_port_t *out_ports = NULL;      /* the outports the syscall exports to the caller */
        uint32_t out_ports_cnt = 0;         /* the amount of outports the syscall exports to the caller */
        task_t task = MACH_PORT_NULL;       /* the mach task of the caller */
        errno_t err = 0;                    /* the errno value */
        
        /* waiting for the syscall client to invoke its syscall */
        mach_msg_return_t mr = mach_msg(&(buffer->header), options, 0, sizeof(recv_buffer_t), server->port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(mr != MACH_MSG_SUCCESS)
        {
            /* receive right is dead when the server stops */
            if(mr == MACH_RCV_PORT_DIED || mr == MACH_RCV_INVALID_NAME)
            {
                ksurface_panic("syscall server worker thread died unexpectedly, this is undefined behaviour. (mr = 0x%x)", mr);
            }
            continue;
        }
        
        /* getting request from receive buffer */
        ksurface_proc_snapshot_t *proc_snapshot = NULL;
        syscall_request_t *req = (syscall_request_t *)&(buffer->header);
        
        /* validating message header */
        if((req->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 ||
           (req->header.msgh_bits & MACH_MSGH_BITS_PORTS_MASK) != MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, MACH_MSG_TYPE_PORT_SEND))
        {
            err = EBADMSG;
            result = -1;
            goto cleanup;
        }
        
        /* validate message descriptor */
        if(req->body.msgh_descriptor_count != 1 ||
           req->oolp.type != MACH_MSG_OOL_PORTS_DESCRIPTOR ||
           req->oolp.count > 64)    /* 64 ports maximum for now */
        {
            err = EBADMSG;
            result = -1;
            goto cleanup;
        }
        
        /*
         * getting the callers identity from the payload,
         * since we cannot just trust the process identity
         * by just letting it send some pid, that would be
         * fragile and unsecure.
         */
        proc_snapshot = syscall_get_caller_proc_snapshot(&(buffer->header));
        if(proc_snapshot == NULL)
        {
            /* checking if proc copy is null */
            err = EAGAIN;
            result = -1;
            goto cleanup;
        }
        
        /*
         * getting task port, its not needed to
         * check for succession as task is still
         * MACH_PORT_NULL if this fails as
         * proc_task_for_proc(3) was engineered
         * to not overwrite the task port pointer
         * on failure paths.
         */
        kvo_rdlock((ksurface_proc_t*)(proc_snapshot->header.orig));
        proc_task_for_proc((ksurface_proc_t*)(proc_snapshot->header.orig), TASK_KERNEL_PORT, &task);
        kvo_unlock((ksurface_proc_t*)(proc_snapshot->header.orig));
        
        /* getting the syscall handler the kernel virtualisation layer previously has set */
        syscall_handler_t handler = NULL;
        
        /* checking syscall bounds */
        os_unfair_lock_lock(&server->lock);
        if(req->syscall_num < SYSCALL_HANDLERS_LIMIT)
        {
            handler = server->handlers[req->syscall_num];
        }
        os_unfair_lock_unlock(&server->lock);
        
        /* checking if the handler was set by the kernel virtualisation layer */
        if(!handler)
        {
            err = ENOSYS;
            result = -1;
            goto cleanup;
        }
        
        /* calling syscall handler */
        errno = 0;  /* starting with clean errno, to prevent errno leak from other syscalls */
        result = handler(task, proc_snapshot, &buffer, req->args, req->oolp, &out_ports, &out_ports_cnt, &err);
        
    cleanup:
        /* destroying snapshot of process */
        if(proc_snapshot != NULL)
        {
            /*
             * proc snapshot must be non-null
             * in order for the task port to be
             * non-null.
             */
            if(task != MACH_PORT_NULL)
            {
                mach_port_deallocate(mach_task_self(), task);
            }
            kvo_release(proc_snapshot);
        }
        
        /*
         * syscall can aquired buffer, we need
         * a new buffer now, syscalls may
         * aquired the buffer to reply
         * them selves, which is done for
         * none blocking later replies
         * like in SYS_wait4, otherwise
         * 8 waiting processes using SYS_wait4
         * would freeze up the syscalling on
         * a 8 core SoC.
         */
        if(buffer != NULL)
        {
            syscall_send_reply(&(req->header), result, out_ports, out_ports_cnt, false, err);
        }
    }
    
    return NULL;
}
