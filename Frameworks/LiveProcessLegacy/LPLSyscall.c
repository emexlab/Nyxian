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

#include <LiveProcessLegacy/LPLSyscall.h>
#include <LiveProcessLegacy/LPLFileport.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#if __has_include(<ksurface_config.h>)
#include <ksurface_config.h>
#endif /* __has_include(<ksurface_config.h>) */
#if __has_include(<ksurface_abi.h>)
#include <ksurface_abi.h>
#endif /* __has_include(<ksurface_abi.h>) */

syscall_client_t *syscallProxy = NULL;

typedef struct {
    mach_msg_header_t           header;         /* mach message header */
    mach_msg_body_t             body;           /* mach message body which holds information about descriptors */
    mach_msg_ool_ports_descriptor_t oolp;       /* mach message descriptor for arbitary amount of mach ports provided by the guest process */
    uint32_t                    syscall_num;    /* syscall the guest process wants to call */
    int64_t                     args[6];        /* syscall arguments for general purpose MARK: not for buffers! */
    mach_msg_max_trailer_t      trailer;        /* trailer in includes clients identity */
} syscall_request_t;

typedef struct {
    mach_msg_header_t           header;         /* mach message header */
    mach_msg_body_t             body;           /* mach message body which holds information about descriptors */
    mach_msg_ool_ports_descriptor_t oolp;       /* mach message descriptor for arbitary amount of macg ports provided by the kernel virtualization layer */
    int64_t                     result;         /* syscall return value for the guest */
    errno_t                     err;            /* errno result value from the syscall */
} syscall_reply_t;

struct syscall_client {
    mach_port_t server_port;
    pthread_key_t reply_port_key;
};

typedef struct {
    union {
        syscall_request_t req;
        syscall_reply_t   reply;
    };
    mach_msg_max_trailer_t trailer;
} syscall_msg_buffer_t;

/*
 * Syscalls in flight on this thread. mach_msg() retries an interrupted
 * receive, so a signal handler can run while the thread's reply port still
 * has a reply outstanding. A syscall from that handler (bash's SIGCHLD
 * handler calling waitpid, readline's SIGWINCH handler calling ioctl) must
 * not share the port: the two replies could be received crosswise and an
 * outer tcsetattr would return the handler's result, desyncing readline's
 * idea of the terminal from the TTY.
 */
static __thread volatile unsigned int syscall_depth = 0;

static mach_port_t make_reply_port(void)
{
    mach_port_options_t opts = {
        .flags = MPO_STRICT | MPO_REPLY_PORT
    };
    mach_port_t port = MACH_PORT_NULL;
    if(mach_port_construct(mach_task_self(), &opts, 0, &port) != KERN_SUCCESS)
    {
        return MACH_PORT_NULL;
    }
    return port;
}

static void reply_port_destructor(void *port_ptr)
{
    mach_port_t port = (mach_port_t)(uintptr_t)port_ptr;
    
    if(port != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), port);
    }
}

static mach_port_t get_thread_reply_port(syscall_client_t *client)
{
    assert(client != NULL);
    
    mach_port_t port = (mach_port_t)(uintptr_t)pthread_getspecific(client->reply_port_key);
    
    if(port == MACH_PORT_NULL)
    {
        port = make_reply_port();
        
        if(port == MACH_PORT_NULL)
        {
            return MACH_PORT_NULL;
        }
        
        /*
         * set port as associated data of the thread
         * so we can clean it up once the thread dies.
         */
        pthread_setspecific(client->reply_port_key, (void*)(uintptr_t)port);
    }
    
    return port;
}

syscall_client_t *liveshim_syscall_client_create(mach_port_t port)
{
    assert(port != MACH_PORT_NULL);
    
    syscall_client_t *client = malloc(sizeof(syscall_client_t));
    
    if(client == NULL)
    {
        return NULL;
    }
    
    client->server_port = port;
    
    /*
     * to make sure every thread gets the correct reply to its
     * syscall we create a pthread key so every thread gets
     * one syscall reply port, this port then gets cleaned up
     * when the thread dies. good and scalable!
     */
    if(pthread_key_create(&client->reply_port_key, reply_port_destructor) != 0)
    {
        free(client);
        return NULL;
    }
    
    return client;
}

int64_t liveshim_syscall_invoke(syscall_client_t *client,
                                uint32_t syscall_num,
                                int64_t *args,
                                mach_port_t *in_ports,
                                uint32_t in_ports_cnt,
                                mach_msg_type_name_t in_type,
                                mach_port_t **out_ports,
                                uint32_t out_ports_cnt)
{
    assert(client != NULL && args != NULL);
    
    /*
     * getting thread specific reply port to
     * use for environment syscalls, so there
     * wont be any ghost replies. a syscall
     * nested in a signal handler gets a port
     * of its own, see syscall_depth.
     */
    bool nested = syscall_depth != 0;
    mach_port_t reply_port = nested ? make_reply_port() : get_thread_reply_port(client);
    if(reply_port == MACH_PORT_NULL)
    {
        errno = EAGAIN;
        return -1;
    }
    
    /*
     * the request stack memory buffer for
     * the host.
     */
    syscall_msg_buffer_t buffer;
    bzero(&buffer, sizeof(buffer));
    
    /* setting up request >~< */
    buffer.req.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;
    buffer.req.header.msgh_remote_port = client->server_port;
    buffer.req.header.msgh_local_port = reply_port;
    buffer.req.header.msgh_size = sizeof(syscall_request_t);
    buffer.req.header.msgh_id = syscall_num;
    buffer.req.syscall_num = syscall_num;
    bcopy(args, buffer.req.args, sizeof(buffer.req.args));
    
    /*
     * this is used for mach and file descriptor
     * transmission, for simplicity, you cant
     * extract ports efficiently from the guest
     * using its task port, i attempted that
     * when i wrote copy_in and copy_out and
     * found that the soloutions are slow and
     * not feasible. on file descriptors there was
     * no other sulotion than directly using a ports
     * descriptor as mach is not BSD and file descriptors
     * is a bsd and not a mach concept but there is
     * a API called fileport that can be used to
     * on iOS convert a file descriptor into a
     * mach port which is like dup2 on a file
     * descriptor just that you create a mach port
     * which can restore the exact same file
     * descriptor later with the oppositing
     * fileport api.
     */
    buffer.req.body.msgh_descriptor_count = 1;
    buffer.req.oolp.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    buffer.req.oolp.disposition = in_type;
    buffer.req.oolp.address = in_ports;
    buffer.req.oolp.count = in_ports_cnt;
    buffer.req.oolp.copy = MACH_MSG_PHYSICAL_COPY;
    
    /*
     * now lets call da cutie >.<
     *
     * MARK: when using MACH_SEND_MSG | MACH_RCV_MSG together, the kernel
     * uses the same buffer for both operations. The receive buffer size
     * must be large enough to hold the reply plus any trailer.
     */
    syscall_depth++;
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    kern_return_t kr = mach_msg(&buffer.req.header, MACH_SEND_MSG | MACH_RCV_MSG, sizeof(syscall_request_t), sizeof(buffer), reply_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    syscall_depth--;
    if(nested)
    {
        mach_port_mod_refs(mach_task_self(), reply_port, MACH_PORT_RIGHT_RECEIVE, -1);
    }
    if(kr != KERN_SUCCESS)
    {
        errno = EBADMSG;
        return -1;
    }
    
    /*
     * the kernel can send ports back in a reply
     * which can contain file ports and mach ports
     * like task ports if the guest called SYS_gettask
     */
    if(buffer.reply.oolp.address != VM_MIN_ADDRESS)
    {
        mach_port_t *recv = (mach_port_t *)buffer.reply.oolp.address;
        uint32_t n = buffer.reply.oolp.count;
        for(uint32_t c = 0; c < n && c < out_ports_cnt; c++)
        {
            if(out_ports[c] != NULL)
            {
                *out_ports[c] = recv[c];
            }
        }
        vm_deallocate(mach_task_self(), (mach_vm_address_t)recv, n * sizeof(mach_port_t));
    }
    
    /*
     * the host usually provides a errno on failure
     * so we set it as usually and return with its
     * result.
     */
    errno = buffer.reply.err;
    return buffer.reply.result;
}

enum kESysType: uint8_t {
    kESysTypeNum = 0,
    kESysTypePortIn = 1,
    kESysTypePortOut = 2,
    kESysTypeRecvPortIn = 3,
    kESysTypeFDIn = 4,
    kESysTypeFileIn = 5,
    kESysTypeOptionalFDIn = 6,
};

typedef struct {
    uint32_t syscall_num;
    enum kESysType type[6];
} env_sys_entry_t;

/* macro to make our lives easier */
#define SYS_ENTRY(num, t0, t1, t2, t3, t4, t5) { .syscall_num = (num), .type = { (t0), (t1), (t2), (t3), (t4), (t5) } }

/* internal definitions of kESysType */
#define T_NUM       kESysTypeNum
#define T_PIN       kESysTypePortIn
#define T_POUT      kESysTypePortOut
#define T_RPIN      kESysTypeRecvPortIn
#define T_FIN       kESysTypeFDIn
#define T_FILEIN    kESysTypeFileIn
#define T_OFIN      kESysTypeOptionalFDIn

env_sys_entry_t sys_env_entries[] = {
#ifdef KSURFACE_CONFIG_H
    SYS_ENTRY(SYS_task_for_pid, T_NUM,  T_NUM,  T_POUT, T_NUM,  T_NUM,  T_NUM),
    SYS_ENTRY(SYS_handoffep,    T_RPIN, T_NUM,  T_NUM,  T_NUM,  T_NUM,  T_NUM),
    SYS_ENTRY(SYS_pectl,        T_NUM,  T_NUM,  T_NUM,  T_NUM,  T_PIN,  T_POUT),
    SYS_ENTRY(SYS_sign,         T_FIN,  T_NUM,  T_NUM,  T_NUM,  T_NUM,  T_NUM),
#endif /* KSURFACE_CONFIG_H */
    SYS_ENTRY(SYS_ioctl,        T_FIN,  T_NUM,  T_NUM,  T_NUM,  T_NUM,  T_NUM),
    SYS_ENTRY(SYS_open,         T_NUM,  T_NUM,  T_NUM,  T_POUT, T_NUM,  T_NUM),
    SYS_ENTRY(SYS_faccessat,    T_FIN,  T_NUM,  T_NUM,  T_NUM,  T_NUM,  T_NUM),
    SYS_ENTRY(SYS_openpty,      T_POUT, T_POUT, T_NUM,  T_NUM,  T_NUM,  T_NUM),
};

/* also making our lives easier */
#define SYS_ENV_ENTRIES_N (sizeof(sys_env_entries) / sizeof(sys_env_entries[0]))

static const env_sys_entry_t *find_syscall_entry(uint32_t syscall_num)
{
    /* iterating through all syscall environment entries */
    for(size_t i = 0; i < SYS_ENV_ENTRIES_N; i++)
    {
        /* matching it */
        if(sys_env_entries[i].syscall_num == syscall_num)
        {
            /* returning it lol ^^*/
            return &sys_env_entries[i];
        }
    }
    return NULL;
}

int64_t liveshim_syscall(uint32_t syscall_num, ...)
{
    if(syscallProxy == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    
    /* starting variadic argument parse */
    va_list args;
    va_start(args, syscall_num);
    
    /* parsing arguments */
    int64_t sys_args[6];
    for(uint8_t i = 0; i < 6; i++)
    {
        sys_args[i] = va_arg(args, int64_t);
    }
    
    /* ending parse */
    va_end(args);
    
    /* port shit */
    mach_port_t in_ports[6] = {};
    mach_port_t *out_ports[6] = {};
    uint32_t in_ports_cnt = 0;
    uint32_t out_ports_cnt = 0;
    mach_msg_type_name_t type = MACH_MSG_TYPE_COPY_SEND;
    
    /* decoding payloads if applicable */
    const env_sys_entry_t *entry = find_syscall_entry(syscall_num);
    if(entry != NULL)
    {
        /* iterating through systypes */
        for(int a = 0; a < 6; a++)
        {
            int64_t val = sys_args[a];
            
            /* decoding type for type */
            switch(entry->type[a])
            {
                case kESysTypePortIn:
                    in_ports[in_ports_cnt++] = (mach_port_t)val;
                    break;
                case kESysTypePortOut:
                    out_ports[out_ports_cnt++] = (mach_port_t *)val;
                    break;
                case kESysTypeRecvPortIn:
                    in_ports[in_ports_cnt++] = (mach_port_t)val;
                    type = MACH_MSG_TYPE_MOVE_RECEIVE;
                    break;
                case kESysTypeOptionalFDIn:
                {
                    fileport_t fileport = MACH_PORT_NULL;
                    if(fileport_makeport((int)val, &fileport) == 0)
                    {
                        in_ports[in_ports_cnt++] = fileport;
                    }
                    break;
                }
                case kESysTypeFDIn:
                {
                    if((int)val < 0)
                    {
                        break;
                    }
                    
                    fileport_t fileport = MACH_PORT_NULL;
                    if(fileport_makeport((int)val, &fileport) == 0)
                    {
                        in_ports[in_ports_cnt++] = fileport;
                    }
                    else
                    {
                        errno = EBADF;
                        return -1;
                    }
                    break;
                }
                case kESysTypeFileIn:
                {
                    const char *path = (char*)val;
                    
                    int fd = open(path, O_RDWR);
                    if(fd < 0)
                    {
                        errno = EINVAL;
                        return -1;
                    }
                    
                    fileport_t fileport = MACH_PORT_NULL;
                    if(fileport_makeport(fd, &fileport) == 0)
                    {
                        in_ports[in_ports_cnt++] = fileport;
                    }
                    else
                    {
                        close(fd);
                        errno = EBADF;
                        return -1;
                    }
                    
                    close(fd);
                    break;
                }
                default:
                    break;
            }
        }
    }
    
    /* invoking syscall */
    return liveshim_syscall_invoke(syscallProxy, syscall_num, sys_args, in_ports, in_ports_cnt, type, out_ports, out_ports_cnt);
}
