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

#ifndef RKS_H
#define RKS_H

#include <Recovery/include/recovery_ksurface.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RKS_EXPORT __attribute__((visibility("default")))
#define RKS_HIDDEN __attribute__((visibility("hidden")))

/* ----------------------------------------------------------------------
 *  global state
 * -------------------------------------------------------------------- */

typedef struct rks_state {
    char root[PATH_MAX];            /* ~/Library/TWRP, the vroot */
    char jbroot[PATH_MAX];          /* root/opt/procursus */
    char bundle[PATH_MAX];
    int (*sign)(const char *path);
    void (*log)(const char *message);
    mach_port_t port;               /* syscall server receive + send right */
    pid_t kernel_pid;               /* the bootloader, parent of everything the recovery spawns */
    rks_exit_handler_t exit_handler;
    void *exit_context;
} rks_state_t;

RKS_HIDDEN extern rks_state_t rks;

RKS_HIDDEN void rks_logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* ----------------------------------------------------------------------
 *  syscall server (wire format of LiveShim/LiveShimSyscall.c)
 * -------------------------------------------------------------------- */

typedef struct {
    mach_msg_header_t               header;
    mach_msg_body_t                 body;
    mach_msg_ool_ports_descriptor_t oolp;
    uint32_t                        syscall_num;
    int64_t                         args[6];
    mach_msg_max_trailer_t          trailer;    /* part of the client's message size, like in LiveShim */
} rks_request_t;

typedef struct {
    mach_msg_header_t               header;
    uint8_t                         body[sizeof(rks_request_t)];
    mach_msg_max_trailer_t          trailer;
} rks_recv_buffer_t;

typedef struct {
    mach_msg_header_t               header;
    mach_msg_body_t                 body;
    mach_msg_ool_ports_descriptor_t oolp;
    int64_t                         result;
    errno_t                         err;
} rks_reply_t;

#define RKS_MAX_OUT_PORTS 8

struct rks_proc;

typedef struct rks_call {
    struct rks_proc     *proc;          /* caller, retained for the call */
    task_t              task;           /* caller's task port (own reference) or MACH_PORT_NULL */
    int64_t             *args;
    mach_port_t         *in_ports;
    uint32_t            in_count;
    mach_msg_type_name_t in_disposition;
    mach_port_t         out_ports[RKS_MAX_OUT_PORTS];
    uint32_t            out_count;
    rks_recv_buffer_t   *buffer;        /* a handler that replies later takes it and sets this to NULL */
    errno_t             err;
} rks_call_t;

typedef int64_t (*rks_handler_t)(rks_call_t *call);

#define RKS_FAIL(call, e) do { (call)->err = (e); return -1; } while(0)

RKS_HIDDEN int rks_syscall_server_start(void);
RKS_HIDDEN void rks_send_reply(rks_recv_buffer_t *buffer, int64_t result, const mach_port_t *out_ports, uint32_t out_count, errno_t err);

/* guest memory */
RKS_HIDDEN bool rks_copy_in(task_t task, void *dst, uint64_t src, size_t size);
RKS_HIDDEN bool rks_copy_out(task_t task, uint64_t dst, const void *src, size_t size);
RKS_HIDDEN char *rks_copy_str_in(task_t task, uint64_t src, size_t max);

/* ----------------------------------------------------------------------
 *  processes
 * -------------------------------------------------------------------- */

typedef enum {
    RKS_PROC_RUNNING = 0,
    RKS_PROC_STOPPED,
    RKS_PROC_ZOMBIE,
} rks_proc_state_t;

typedef struct rks_proc {
    int                 refs;
    pid_t               pid;
    pid_t               ppid;
    pid_t               pgid;
    pid_t               sid;
    task_t              task;               /* handed off by the guest, MACH_PORT_NULL until then */
    bool                handoff_pending;
    rks_proc_state_t    state;
    int                 status;             /* wait(2) status of the pending state change */
    bool                status_pending;     /* stop/continue change not yet reported */
    bool                reaped;
    bool                has_reported_exit;  /* exit() status reported by librecoveryrtpatch */
    int                 reported_exit;
    int                 fatal_signal;       /* last terminating signal the kernel delivered */
    bool                exit_known;         /* exit status came from FrontBoard */
    int                 exit_status;
    uint64_t            dead_since;         /* mach_absolute_time() when death was observed */
    void                *extension;         /* NSExtension (retained), delivers signals */
    void                *process;           /* FBProcess (retained) when FrontBoard is available */
    void                *observer;          /* FBProcess observer (retained) */
    struct rks_proc     *next;
} rks_proc_t;

RKS_HIDDEN extern pthread_mutex_t rks_proc_lock;

RKS_HIDDEN void rks_proc_init(void);
RKS_HIDDEN rks_proc_t *rks_proc_lookup(pid_t pid);                 /* retained or NULL */
RKS_HIDDEN rks_proc_t *rks_proc_lookup_locked(pid_t pid);          /* not retained, lock held */
RKS_HIDDEN void rks_proc_retain(rks_proc_t *proc);
RKS_HIDDEN void rks_proc_release(rks_proc_t *proc);
/* retained; setsid makes it a session (and group) leader, pgroup >= 0 puts it in that group (0: its own) */
RKS_HIDDEN rks_proc_t *rks_proc_register(pid_t pid, pid_t ppid, bool setsid, pid_t pgroup);
RKS_HIDDEN bool rks_pgrp_exists_in_session(pid_t pgid, pid_t sid);
RKS_HIDDEN void rks_proc_set_task(rks_proc_t *proc, task_t task);
RKS_HIDDEN void rks_proc_exited(pid_t pid, bool have_status, int status);
RKS_HIDDEN int rks_proc_signal(rks_proc_t *proc, int sig);
RKS_HIDDEN int rks_pgrp_signal(pid_t pgid, int sig);
RKS_HIDDEN void rks_proc_monitor_start(void);

/* deferred replies */
RKS_HIDDEN int64_t rks_wait4_block(rks_call_t *call, pid_t selector, int options, uint64_t status_ptr);
RKS_HIDDEN int64_t rks_waittask_block(rks_call_t *call, pid_t target);

/* ----------------------------------------------------------------------
 *  TTY
 * -------------------------------------------------------------------- */

typedef struct rks_tty rks_tty_t;

RKS_HIDDEN rks_tty_t *rks_tty_create(int *master_fd, int *slave_fd);   /* fds are dup'able userspace ends, owned by the caller */
RKS_HIDDEN rks_tty_t *rks_tty_for_fd(int fd);                          /* retained or NULL */
RKS_HIDDEN rks_tty_t *rks_tty_for_port(mach_port_t fileport);          /* retained or NULL */
RKS_HIDDEN void rks_tty_retain(rks_tty_t *tty);
RKS_HIDDEN void rks_tty_release(rks_tty_t *tty);
RKS_HIDDEN void rks_tty_attach(rks_tty_t *tty, rks_proc_t *leader);
RKS_HIDDEN int rks_tty_set_size(rks_tty_t *tty, unsigned short rows, unsigned short cols);
RKS_HIDDEN int64_t rks_tty_ioctl(rks_call_t *call, rks_tty_t *tty, unsigned long request, uint64_t arg);

/* ----------------------------------------------------------------------
 *  task handoff, spawn
 * -------------------------------------------------------------------- */

RKS_HIDDEN kern_return_t rks_task_handoff_receive(mach_port_t exception_port, task_t *task);

RKS_HIDDEN int rks_spawn_server_start(void);
RKS_HIDDEN bool rks_extension_kill(void *extension, int sig);     /* -[NSExtension _kill:] */

/* syscall handlers */
#define RKS_DECLARE_HANDLER(name) RKS_HIDDEN int64_t rks_sys_##name(rks_call_t *call)
RKS_DECLARE_HANDLER(getppid);
RKS_DECLARE_HANDLER(getpgrp);
RKS_DECLARE_HANDLER(getpgid);
RKS_DECLARE_HANDLER(setpgid);
RKS_DECLARE_HANDLER(getsid);
RKS_DECLARE_HANDLER(setsid);
RKS_DECLARE_HANDLER(root_id);
RKS_DECLARE_HANDLER(accept);
RKS_DECLARE_HANDLER(kill);
RKS_DECLARE_HANDLER(wait4);
RKS_DECLARE_HANDLER(waittask);
RKS_DECLARE_HANDLER(handoffep);
RKS_DECLARE_HANDLER(task_for_pid);
RKS_DECLARE_HANDLER(ioctl);
RKS_DECLARE_HANDLER(openpty);
RKS_DECLARE_HANDLER(vroot);
RKS_DECLARE_HANDLER(sign);
RKS_DECLARE_HANDLER(sign2);
RKS_DECLARE_HANDLER(loginctl);
RKS_DECLARE_HANDLER(groupctl);
RKS_DECLARE_HANDLER(pectl);
RKS_DECLARE_HANDLER(exitstatus);
RKS_DECLARE_HANDLER(spawn);

#ifdef __cplusplus
}
#endif

#endif /* RKS_H */
