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
#include <ksurface_abi.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* mach_vm.h is marked unsupported in the iOS SDK */
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size,
                                            mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data,
                                   mach_msg_type_number_t dataCnt);

#define RKS_WORKERS 8

/* ----------------------------------------------------------------------
 *  guest memory
 * -------------------------------------------------------------------- */

bool rks_copy_in(task_t task, void *dst, uint64_t src, size_t size)
{
    if(task == MACH_PORT_NULL || src == 0 || dst == NULL)
    {
        return false;
    }
    if(size == 0)
    {
        return true;
    }
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)src, (mach_vm_size_t)size, (mach_vm_address_t)(uintptr_t)dst, &got);
    return kr == KERN_SUCCESS && got == size;
}

bool rks_copy_out(task_t task, uint64_t dst, const void *src, size_t size)
{
    if(task == MACH_PORT_NULL || dst == 0 || src == NULL)
    {
        return false;
    }
    if(size == 0)
    {
        return true;
    }
    return mach_vm_write(task, (mach_vm_address_t)dst, (vm_offset_t)(uintptr_t)src, (mach_msg_type_number_t)size) == KERN_SUCCESS;
}

/* page by page so a string close to the end of a mapping is still readable */
char *rks_copy_str_in(task_t task, uint64_t src, size_t max)
{
    if(task == MACH_PORT_NULL || src == 0 || max == 0)
    {
        return NULL;
    }
    char *buffer = malloc(max + 1);
    if(buffer == NULL)
    {
        return NULL;
    }
    size_t off = 0;
    while(off < max)
    {
        uint64_t address = src + off;
        size_t want = (size_t)(vm_page_size - (address & (vm_page_size - 1)));
        if(want > max - off)
        {
            want = max - off;
        }
        if(!rks_copy_in(task, buffer + off, address, want))
        {
            free(buffer);
            return NULL;
        }
        char *nul = memchr(buffer + off, '\0', want);
        if(nul != NULL)
        {
            return buffer;
        }
        off += want;
    }
    buffer[max] = '\0';
    return buffer;
}

/* ----------------------------------------------------------------------
 *  logging
 * -------------------------------------------------------------------- */

void rks_logf(const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if(rks.log != NULL)
    {
        rks.log(line);
    }
#if DEBUG
    fprintf(stderr, "[librecoveryksurface] %s\n", line);
#endif
}

/* ----------------------------------------------------------------------
 *  dispatch
 * -------------------------------------------------------------------- */

static rks_handler_t rks_handler_for(uint32_t num)
{
    switch(num)
    {
        /* identity: the recovery is root, every set* is accepted */
        case SYS_getuid:
        case SYS_geteuid:
        case SYS_getgid:
        case SYS_getegid:       return rks_sys_root_id;
        case SYS_setuid:
        case SYS_seteuid:
        case SYS_setgid:
        case SYS_setegid:
        case SYS_setreuid:
        case SYS_setregid:      return rks_sys_accept;
        case SYS_loginctl:      return rks_sys_loginctl;
        case SYS_groupctl:      return rks_sys_groupctl;

        /* sessions and process groups */
        case SYS_getppid:       return rks_sys_getppid;
        case SYS_getpgrp:       return rks_sys_getpgrp;
        case SYS_getpgid:       return rks_sys_getpgid;
        case SYS_setpgid:       return rks_sys_setpgid;
        case SYS_getsid:        return rks_sys_getsid;
        case SYS_setsid:        return rks_sys_setsid;

        /* processes */
        case SYS_kill:          return rks_sys_kill;
        case SYS_wait4:         return rks_sys_wait4;
        case SYS_waittask:      return rks_sys_waittask;
        case SYS_handoffep:     return rks_sys_handoffep;
        case SYS_task_for_pid:  return rks_sys_task_for_pid;
        case RKS_SYS_exitstatus: return rks_sys_exitstatus;
        case RKS_SYS_spawn:     return rks_sys_spawn;

        /* TTY */
        case SYS_ioctl:         return rks_sys_ioctl;
        case SYS_openpty:       return rks_sys_openpty;

        /* filesystem and code signing */
        case SYS_vroot:         return rks_sys_vroot;
        case SYS_sign:          return rks_sys_sign;
        case SYS_sign2:         return rks_sys_sign2;
        case SYS_pectl:         return rks_sys_pectl;

        /* sysctl, proc_info, ... answer ENOSYS: LiveShim falls back to the real call */
        default:                return NULL;
    }
}

void rks_send_reply(rks_recv_buffer_t *buffer,
                    int64_t result,
                    const mach_port_t *out_ports,
                    uint32_t out_count,
                    errno_t err)
{
    mach_msg_header_t *request = &buffer->header;

    rks_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.header.msgh_bits = MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_MOVE_SEND_ONCE);
    reply.header.msgh_remote_port = request->msgh_remote_port;
    request->msgh_remote_port = MACH_PORT_NULL;
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_id = request->msgh_id + 100;
    reply.result = result;
    reply.err = err;

    vm_address_t ports = 0;
    if(out_ports != NULL && out_count > 0 &&
       vm_allocate(mach_task_self(), &ports, out_count * sizeof(mach_port_t), VM_FLAGS_ANYWHERE) == KERN_SUCCESS)
    {
        memcpy((void *)ports, out_ports, out_count * sizeof(mach_port_t));
        reply.header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
        reply.body.msgh_descriptor_count = 1;
        reply.oolp.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        reply.oolp.disposition = MACH_MSG_TYPE_MOVE_SEND;
        reply.oolp.address = (void *)ports;
        reply.oolp.count = out_count;
        reply.oolp.copy = MACH_MSG_PHYSICAL_COPY;
        reply.oolp.deallocate = TRUE;
    }
    else
    {
        /* reply without ports: the rights we were going to move are ours to drop */
        for(uint32_t i = 0; out_ports != NULL && i < out_count; i++)
        {
            if(MACH_PORT_VALID(out_ports[i]))
            {
                mach_port_deallocate(mach_task_self(), out_ports[i]);
            }
        }
    }

    if(reply.header.msgh_remote_port != MACH_PORT_NULL)
    {
        mach_msg_return_t mr = mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(mr != MACH_MSG_SUCCESS)
        {
            mach_msg_destroy(&reply.header);
        }
    }
    else if(ports != 0)
    {
        mach_msg_destroy(&reply.header);
    }

    /* the rights and memory the guest sent us */
    mach_msg_destroy(request);
    free(buffer);
}

static bool rks_request_valid(rks_request_t *req)
{
    if((req->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0 ||
       (req->header.msgh_bits & MACH_MSGH_BITS_PORTS_MASK) != MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND_ONCE, MACH_MSG_TYPE_PORT_SEND))
    {
        return false;
    }
    if(req->header.msgh_size < offsetof(rks_request_t, trailer) ||
       req->body.msgh_descriptor_count != 1 ||
       req->oolp.type != MACH_MSG_OOL_PORTS_DESCRIPTOR ||
       req->oolp.count > 64)
    {
        return false;
    }
    return true;
}

static void *rks_worker(void *ctx)
{
    (void)ctx;
    pthread_setname_np("librecoveryksurface.syscall");

    const mach_msg_option_t options = MACH_RCV_MSG |
                                      MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
                                      MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);

    for(;;)
    {
        rks_recv_buffer_t *buffer = calloc(1, sizeof(rks_recv_buffer_t));
        if(buffer == NULL)
        {
            usleep(1000);
            continue;
        }

        mach_msg_return_t mr = mach_msg(&buffer->header, options, 0, sizeof(rks_recv_buffer_t), rks.port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(mr != MACH_MSG_SUCCESS)
        {
            free(buffer);
            if(mr == MACH_RCV_PORT_DIED || mr == MACH_RCV_INVALID_NAME)
            {
                rks_logf("syscall worker: receive right is gone (0x%x)", mr);
                return NULL;
            }
            continue;
        }

        rks_request_t *req = (rks_request_t *)&buffer->header;
        rks_call_t call;
        memset(&call, 0, sizeof(call));
        call.buffer = buffer;
        int64_t result = -1;

        if(!rks_request_valid(req))
        {
            call.err = EBADMSG;
            goto reply;
        }

        /* XNU tells us who is calling, the guest never gets to claim a pid */
        mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)((uint8_t *)&buffer->header + round_msg(buffer->header.msgh_size));
        pid_t caller = (pid_t)trailer->msgh_audit.val[5];

        call.proc = rks_proc_lookup(caller);
        if(call.proc == NULL)
        {
            /* not registered yet (the guest spins on SYS_getppid until it is) */
            call.err = EAGAIN;
            goto reply;
        }

        /* the task port arrives asynchronously (SYS_handoffep), give an early memory syscall a moment */
        for(int attempt = 0; attempt < 500; attempt++)
        {
            pthread_mutex_lock(&rks_proc_lock);
            bool pending = call.proc->handoff_pending && call.proc->task == MACH_PORT_NULL;
            if(!pending && call.proc->task != MACH_PORT_NULL &&
               mach_port_mod_refs(mach_task_self(), call.proc->task, MACH_PORT_RIGHT_SEND, 1) == KERN_SUCCESS)
            {
                call.task = call.proc->task;
            }
            pthread_mutex_unlock(&rks_proc_lock);
            if(!pending)
            {
                break;
            }
            usleep(100);
        }

        rks_handler_t handler = rks_handler_for(req->syscall_num);
        if(handler == NULL)
        {
            call.err = ENOSYS;
            goto reply;
        }

        call.args = req->args;
        call.in_ports = (mach_port_t *)req->oolp.address;
        call.in_count = req->oolp.count;
        call.in_disposition = req->oolp.disposition;
        errno = 0;
        result = handler(&call);

    reply:
        if(call.task != MACH_PORT_NULL)
        {
            mach_port_deallocate(mach_task_self(), call.task);
        }
        if(call.proc != NULL)
        {
            rks_proc_release(call.proc);
        }
        if(call.buffer != NULL)
        {
            rks_send_reply(call.buffer, result, call.out_ports, call.out_count, call.err);
        }
    }
    return NULL;
}

int rks_syscall_server_start(void)
{
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rks.port);
    if(kr != KERN_SUCCESS)
    {
        return ENOMEM;
    }
    kr = mach_port_insert_right(mach_task_self(), rks.port, rks.port, MACH_MSG_TYPE_MAKE_SEND);
    if(kr != KERN_SUCCESS)
    {
        mach_port_mod_refs(mach_task_self(), rks.port, MACH_PORT_RIGHT_RECEIVE, -1);
        rks.port = MACH_PORT_NULL;
        return ENOMEM;
    }
    mach_port_limits_t limits = { .mpl_qlimit = MACH_PORT_QLIMIT_LARGE };
    mach_port_set_attributes(mach_task_self(), rks.port, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT);

    for(int i = 0; i < RKS_WORKERS; i++)
    {
        pthread_t thread;
        if(pthread_create(&thread, NULL, rks_worker, NULL) != 0)
        {
            return EAGAIN;
        }
        pthread_detach(thread);
    }
    return 0;
}

/* ----------------------------------------------------------------------
 *  small handlers
 * -------------------------------------------------------------------- */

int64_t rks_sys_root_id(rks_call_t *call)
{
    (void)call;
    return 0;
}

int64_t rks_sys_accept(rks_call_t *call)
{
    (void)call;
    return 0;
}

int64_t rks_sys_vroot(rks_call_t *call)
{
    uint64_t buffer = (uint64_t)call->args[0];
    if(buffer == 0)
    {
        return PATH_MAX;
    }
    size_t length = strlen(rks.root) + 1;
    if(!rks_copy_out(call->task, buffer, rks.root, length))
    {
        RKS_FAIL(call, EFAULT);
    }
    return 0;
}

/* the login name is always root, setting it is accepted and forgotten */
int64_t rks_sys_loginctl(rks_call_t *call)
{
    static const char name[] = "root";
    switch((PELoginCTLAction)call->args[0])
    {
        case kPELoginCTLGetLength:
            return (int64_t)(sizeof(name) - 1);
        case kPELoginCTLGetWord:
        {
            uint64_t index = (uint64_t)call->args[1];
            uint64_t word = 0;
            size_t offset = (size_t)(index * sizeof(word));
            if(offset >= sizeof(name) - 1)
            {
                RKS_FAIL(call, EINVAL);
            }
            size_t count = (sizeof(name) - 1) - offset;
            memcpy(&word, name + offset, count > sizeof(word) ? sizeof(word) : count);
            return (int64_t)word;
        }
        case kPELoginCTLSetWord:
        case kPELoginCTLCommit:
        case kPELoginCTLClear:
            return 0;
        default:
            RKS_FAIL(call, EINVAL);
    }
}

/* supplementary groups: just wheel(0) */
int64_t rks_sys_groupctl(rks_call_t *call)
{
    switch((PEGroupCTLAction)call->args[0])
    {
        case kPEGroupCTLGetCount:
            return 1;
        case kPEGroupCTLGetAt:
            if(call->args[1] != 0)
            {
                RKS_FAIL(call, EINVAL);
            }
            return 0;
        case kPEGroupCTLSetAt:
        case kPEGroupCTLCommit:
        case kPEGroupCTLClear:
            return 0;
        default:
            RKS_FAIL(call, EINVAL);
    }
}

/*
 * No entitlements in recovery: dropping them always works, everything that
 * would need a ROM service (launch services, UI, kexts) does not exist here.
 * GetCDHash failing makes LCBootstrapMain fall back to a plain dlopen.
 */
int64_t rks_sys_pectl(rks_call_t *call)
{
    PECTLCategory category = (PECTLCategory)call->args[0];
    uint16_t action = (uint16_t)call->args[1];
    if(category == kPECTLCategoryCodeSigning && action == kPECTLCodeSigningDropAllEntitlements)
    {
        return 0;
    }
    if(category == kPECTLCategoryUserInterface && action == kPECTLUserInterfaceInit)
    {
        return 0;
    }
    RKS_FAIL(call, ENOSYS);
}

