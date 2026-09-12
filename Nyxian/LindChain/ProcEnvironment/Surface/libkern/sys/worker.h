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

#ifndef SYS_WORKER_H
#define SYS_WORKER_H

#include <LindChain/ProcEnvironment/Surface/libkern/sys/systm.h>
#include <LindChain/ProcEnvironment/Surface/proc/def.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#define SYSCALL_MAX_PAYLOAD     16384

/* safe snapshot */
#define sys_proc_snapshot_ proc_snapshot
#define sys_task_ task

/* reference for modification */
#define sys_proc_ ((ksurface_proc_t*)(sys_proc_snapshot_->header.orig))

/* helping macros for returns and checks */
#define sys_return_failure_with_errno(errval) \
    *err = errval; \
    return -1

#define sys_return_failure() return -1 \

#define sys_set_errno(errval) \
    *err = errval

#define sys_get_errno() \
    *err

#define sys_return \
    return 0

#define sys_need_in_ports(cnt, expected_disposition) \
    if(in_ports.address == VM_MIN_ADDRESS || \
       in_ports.count < cnt || \
       in_ports.disposition != expected_disposition) \
    { \
        sys_return_failure_with_errno(EINVAL); \
    }

#define sys_in_ports ((mach_port_t*)in_ports.address)

#define sys_export_port(port) \
    (*out_ports)[(*out_ports_cnt)++] = (port);
    

/* request message coming from the client */
typedef struct {
    mach_msg_header_t           header;         /* mach message header */
    mach_msg_body_t             body;           /* mach message body which holds information about descriptors */
    mach_msg_ool_ports_descriptor_t oolp;       /* mach message descriptor for arbitary amount of mach ports provided by the guest process */
    uint32_t                    syscall_num;    /* syscall the guest process wants to call */
    int64_t                     args[6];        /* syscall arguments for general purpose MARK: not for buffers! */
    mach_msg_max_trailer_t      trailer;        /* trailer in includes clients identity */
} syscall_request_t;

typedef struct {
    mach_msg_header_t header;
    uint8_t body[sizeof(syscall_request_t)];
    mach_msg_max_trailer_t trailer;
} recv_buffer_t;

/* reply message coming from the kernel virtualization layer */
typedef struct {
    mach_msg_header_t           header;         /* mach message header */
    mach_msg_body_t             body;           /* mach message body which holds information about descriptors */
    mach_msg_ool_ports_descriptor_t oolp;       /* mach message descriptor for arbitary amount of macg ports provided by the kernel virtualization layer */
    int64_t                     result;         /* syscall return value for the guest */
    errno_t                     err;            /* errno result value from the syscall */
} syscall_reply_t;

typedef int64_t (*syscall_handler_t)(
    /*
     * normal(absoloutely normal) IKOT_TASK port
     * of some process on iOS, yeah *smiles*
     */
    task_t                          task,
    
    /*
     * holds information about the process identity
     * that made the syscall
     * which is very important, because this is our security
     * ensurace
     */
    ksurface_proc_snapshot_t        *proc_snapshot,
                                     
    /* request header */
    recv_buffer_t                   **recv_buffer,

    /*
     * normal syscall arguments
     */
    int64_t                         *args,

    /* input and output ports */
    mach_msg_ool_ports_descriptor_t in_ports,
    mach_port_t                     **out_ports,
    uint32_t                        *out_ports_cnt,

    errno_t                         *err
);

#define DEFINE_SYSCALL_HANDLER(sysname) int64_t syscall_server_handler_##sysname( \
    task_t                          task, \
    ksurface_proc_snapshot_t        *proc_snapshot, \
    recv_buffer_t                   **recv_buffer, \
    int64_t                         *args, \
    mach_msg_ool_ports_descriptor_t in_ports, \
    mach_port_t                     **out_ports, \
    uint32_t                        *out_ports_cnt, \
    errno_t                         *err \
)

#define GET_SYSCALL_HANDLER(sysname) syscall_server_handler_##sysname

#define SYSCALL_HANDLER_REDIRECT_TO_HANDLER(sysname) syscall_server_handler_##sysname(task, proc_snapshot, recv_buffer, args, in_ports, out_ports, out_ports_cnt, err)

typedef struct syscall_server syscall_server_t;

void* syscall_worker(void *ctx);
void syscall_send_reply(mach_msg_header_t *request, int64_t result, mach_port_t *out_ports, uint32_t out_ports_cnt, bool release_req, errno_t err);

#endif /* SYS_WORKER_H */
