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
#include <CoreFoundation/CoreFoundation.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/event.h>
#include <fcntl.h>

pthread_mutex_t rks_proc_lock = PTHREAD_MUTEX_INITIALIZER;
static rks_proc_t *g_procs = NULL;

typedef struct rks_wait4_waiter {
    rks_recv_buffer_t *buffer;
    pid_t caller;
    pid_t caller_pgid;
    pid_t selector;
    int options;
    task_t task;
    uint64_t status_ptr;
    struct rks_wait4_waiter *next;
} rks_wait4_waiter_t;

typedef struct rks_task_waiter {
    rks_recv_buffer_t *buffer;
    pid_t target;
    struct rks_task_waiter *next;
} rks_task_waiter_t;

static rks_wait4_waiter_t *g_wait4_waiters = NULL;
static rks_task_waiter_t *g_task_waiters = NULL;

typedef struct rks_pending_reply {
    rks_recv_buffer_t *buffer;
    int64_t result;
    errno_t err;
    task_t task;
    uint64_t status_ptr;
    int status;
    bool copy_status;
    struct rks_pending_reply *next;
} rks_pending_reply_t;

typedef struct rks_exit_note {
    pid_t pid;
    int status;
    bool report;
    struct rks_exit_note *next;
} rks_exit_note_t;

void rks_proc_retain(rks_proc_t *proc)
{
    __atomic_add_fetch(&proc->refs, 1, __ATOMIC_ACQ_REL);
}

void rks_proc_release(rks_proc_t *proc)
{
    if(proc == NULL || __atomic_sub_fetch(&proc->refs, 1, __ATOMIC_ACQ_REL) != 0)
    {
        return;
    }
    if(proc->task != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), proc->task);
    }
    if(proc->extension != NULL) CFRelease(proc->extension);
    free(proc);
}

rks_proc_t *rks_proc_lookup_locked(pid_t pid)
{
    for(rks_proc_t *proc = g_procs; proc != NULL; proc = proc->next)
    {
        if(proc->pid == pid && !proc->reaped)
        {
            return proc;
        }
    }
    return NULL;
}

rks_proc_t *rks_proc_lookup(pid_t pid)
{
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *proc = rks_proc_lookup_locked(pid);
    if(proc != NULL)
    {
        rks_proc_retain(proc);
    }
    pthread_mutex_unlock(&rks_proc_lock);
    return proc;
}

/* lock held, drops the table's reference */
static void rks_proc_unlink_locked(rks_proc_t *target)
{
    for(rks_proc_t **cursor = &g_procs; *cursor != NULL; cursor = &(*cursor)->next)
    {
        if(*cursor == target)
        {
            *cursor = target->next;
            target->next = NULL;
            target->reaped = true;
            rks_proc_release(target);
            return;
        }
    }
}

void rks_proc_init(void)
{
    rks_proc_t *kernel = calloc(1, sizeof(rks_proc_t));
    kernel->refs = 1;
    kernel->pid = rks.kernel_pid;
    kernel->ppid = 1;
    kernel->pgid = rks.kernel_pid;
    kernel->sid = rks.kernel_pid;
    pthread_mutex_lock(&rks_proc_lock);
    kernel->next = g_procs;
    g_procs = kernel;
    pthread_mutex_unlock(&rks_proc_lock);
}

rks_proc_t *rks_proc_register(pid_t pid, pid_t ppid, bool setsid, pid_t pgroup)
{
    rks_proc_t *proc = calloc(1, sizeof(rks_proc_t));
    if(proc == NULL)
    {
        return NULL;
    }
    proc->refs = 2;
    proc->pid = pid;
    proc->ppid = ppid;
    proc->handoff_pending = true;
    
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *old = rks_proc_lookup_locked(pid);
    if(old != NULL)
    {
        rks_proc_unlink_locked(old);
    }
    rks_proc_t *parent = rks_proc_lookup_locked(ppid);
    proc->pgid = parent ? parent->pgid : pid;
    proc->sid = parent ? parent->sid : pid;
    if(setsid)
    {
        proc->sid = pid;
        proc->pgid = pid;
    }
    else if(pgroup >= 0)
    {
        proc->pgid = pgroup == 0 ? pid : pgroup;
    }
    proc->next = g_procs;
    g_procs = proc;
    pthread_mutex_unlock(&rks_proc_lock);
    return proc;
}

bool rks_pgrp_exists_in_session(pid_t pgid, pid_t sid)
{
    for(rks_proc_t *proc = g_procs; proc != NULL; proc = proc->next)
    {
        if(!proc->reaped && proc->state != RKS_PROC_ZOMBIE && proc->pgid == pgid && proc->sid == sid)
        {
            return true;
        }
    }
    return false;
}

static void rks_pending_push(rks_pending_reply_t **list, rks_recv_buffer_t *buffer, int64_t result, errno_t err,
                             task_t task, uint64_t status_ptr, bool copy_status, int status)
{
    rks_pending_reply_t *reply = calloc(1, sizeof(rks_pending_reply_t));
    if(reply == NULL)
    {
        mach_msg_destroy(&buffer->header);
        free(buffer);
        if(task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
        return;
    }
    reply->buffer = buffer;
    reply->result = result;
    reply->err = err;
    reply->task = task;
    reply->status_ptr = status_ptr;
    reply->copy_status = copy_status;
    reply->status = status;
    reply->next = *list;
    *list = reply;
}

static void rks_pending_flush(rks_pending_reply_t *list)
{
    while(list != NULL)
    {
        rks_pending_reply_t *next = list->next;
        if(list->copy_status && list->status_ptr != 0)
        {
            rks_copy_out(list->task, list->status_ptr, &list->status, sizeof(int));
        }
        rks_send_reply(list->buffer, list->result, NULL, 0, list->err);
        if(list->task != MACH_PORT_NULL)
        {
            mach_port_deallocate(mach_task_self(), list->task);
        }
        free(list);
        list = next;
    }
}

static bool rks_wait4_matches(pid_t selector, pid_t caller_pgid, rks_proc_t *child)
{
    if(selector > 0) return child->pid == selector;
    if(selector == -1) return true;
    if(selector == 0) return child->pgid == caller_pgid;
    return child->pgid == -selector;
}

static pid_t rks_wait4_claim_locked(pid_t parent, pid_t caller_pgid, pid_t selector, int options, int *status, bool *matched)
{
    *matched = false;
    for(rks_proc_t *child = g_procs; child != NULL; child = child->next)
    {
        if(child->reaped || child->ppid != parent || child->pid == rks.kernel_pid || !rks_wait4_matches(selector, caller_pgid, child))
        {
            continue;
        }
        *matched = true;
        
        if(child->status_pending && child->state != RKS_PROC_ZOMBIE)
        {
            bool stopped = WIFSTOPPED(child->status) && !WIFCONTINUED(child->status);
            if((stopped && (options & WUNTRACED)) || (WIFCONTINUED(child->status) && (options & WCONTINUED)))
            {
                child->status_pending = false;
                *status = child->status;
                return child->pid;
            }
        }
        
        if(child->state == RKS_PROC_ZOMBIE)
        {
            pid_t pid = child->pid;
            *status = child->status;
            rks_proc_unlink_locked(child);
            return pid;
        }
    }
    return 0;
}

static void rks_wait4_notify_locked(pid_t parent, rks_pending_reply_t **replies)
{
    rks_wait4_waiter_t **cursor = &g_wait4_waiters;
    while(*cursor != NULL)
    {
        rks_wait4_waiter_t *waiter = *cursor;
        if(waiter->caller != parent)
        {
            cursor = &waiter->next;
            continue;
        }

        int status = 0;
        bool matched = false;
        pid_t pid = rks_wait4_claim_locked(parent, waiter->caller_pgid, waiter->selector, waiter->options, &status, &matched);
        if(pid > 0)
        {
            rks_pending_push(replies, waiter->buffer, pid, 0, waiter->task, waiter->status_ptr, true, status);
        }
        else if(!matched)
        {
            rks_pending_push(replies, waiter->buffer, -1, ECHILD, waiter->task, 0, false, 0);
        }
        else
        {
            cursor = &waiter->next;
            continue;
        }
        *cursor = waiter->next;
        free(waiter);
    }
}

static void rks_waittask_notify_locked(pid_t target, rks_pending_reply_t **replies)
{
    rks_task_waiter_t **cursor = &g_task_waiters;
    while(*cursor != NULL)
    {
        rks_task_waiter_t *waiter = *cursor;
        if(waiter->target != target)
        {
            cursor = &waiter->next;
            continue;
        }
        rks_pending_push(replies, waiter->buffer, 0, 0, MACH_PORT_NULL, 0, false, 0);
        *cursor = waiter->next;
        free(waiter);
    }
}

static void rks_drop_waiters_of_locked(pid_t caller, rks_pending_reply_t **replies)
{
    rks_wait4_waiter_t **cursor = &g_wait4_waiters;
    while(*cursor != NULL)
    {
        rks_wait4_waiter_t *waiter = *cursor;
        if(waiter->caller == caller)
        {
            rks_pending_push(replies, waiter->buffer, -1, EINTR, waiter->task, 0, false, 0);
            *cursor = waiter->next;
            free(waiter);
        }
        else
        {
            cursor = &waiter->next;
        }
    }
}

int64_t rks_wait4_block(rks_call_t *call, pid_t selector, int options, uint64_t status_ptr)
{
    rks_wait4_waiter_t *waiter = calloc(1, sizeof(rks_wait4_waiter_t));
    if(waiter == NULL)
    {
        RKS_FAIL(call, ENOMEM);
    }
    if(call->task != MACH_PORT_NULL)
    {
        mach_port_mod_refs(mach_task_self(), call->task, MACH_PORT_RIGHT_SEND, 1);
    }
    waiter->buffer = call->buffer;
    waiter->caller = call->proc->pid;
    waiter->caller_pgid = call->proc->pgid;
    waiter->selector = selector;
    waiter->options = options;
    waiter->task = call->task;
    waiter->status_ptr = status_ptr;
    call->buffer = NULL;

    waiter->next = g_wait4_waiters;
    g_wait4_waiters = waiter;
    return 0;
}

int64_t rks_waittask_block(rks_call_t *call, pid_t target)
{
    rks_task_waiter_t *waiter = calloc(1, sizeof(rks_task_waiter_t));
    if(waiter == NULL)
    {
        RKS_FAIL(call, ENOMEM);
    }
    waiter->buffer = call->buffer;
    waiter->target = target;
    call->buffer = NULL;
    waiter->next = g_task_waiters;
    g_task_waiters = waiter;
    return 0;
}

void rks_proc_set_task(rks_proc_t *proc, task_t task)
{
    rks_pending_reply_t *replies = NULL;
    pthread_mutex_lock(&rks_proc_lock);
    if(proc->task != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), proc->task);
    }
    proc->task = task;
    proc->handoff_pending = false;
    rks_waittask_notify_locked(proc->pid, &replies);
    pthread_mutex_unlock(&rks_proc_lock);
    rks_pending_flush(replies);
}

static int rks_final_status(rks_proc_t *proc, bool have_status, int status)
{
    if(have_status) return status;
    if(proc->has_reported_exit) return W_EXITCODE(proc->reported_exit & 0xff, 0);
    if(proc->fatal_signal) return W_EXITCODE(0, proc->fatal_signal);
    return W_EXITCODE(0, SIGKILL);
}

void rks_proc_exited(pid_t pid, bool have_status, int status)
{
    rks_pending_reply_t *replies = NULL;
    rks_exit_note_t *notes = NULL;
    
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *proc = rks_proc_lookup_locked(pid);
    if(proc == NULL || proc->pid == rks.kernel_pid)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        return;
    }
    
    if(proc->state == RKS_PROC_ZOMBIE)
    {
        if(have_status)
        {
            proc->status = status;
        }
        pthread_mutex_unlock(&rks_proc_lock);
        return;
    }
    
    proc->state = RKS_PROC_ZOMBIE;
    proc->status = rks_final_status(proc, have_status, status);
    proc->status_pending = false;
    if(proc->task != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), proc->task);
        proc->task = MACH_PORT_NULL;
    }
    proc->handoff_pending = false;
    
    /* orphans go to the recovery, which reaps them */
    for(rks_proc_t *child = g_procs; child != NULL; )
    {
        rks_proc_t *next = child->next;
        if(!child->reaped && child->ppid == pid)
        {
            child->ppid = rks.kernel_pid;
            if(child->state == RKS_PROC_ZOMBIE)
            {
                rks_proc_unlink_locked(child);
            }
        }
        child = next;
    }
    
    rks_drop_waiters_of_locked(pid, &replies);
    rks_waittask_notify_locked(pid, &replies);
    
    pid_t parent = proc->ppid;
    /* the recovery's own children (the terminal's shell) go to the exit handler */
    rks_exit_note_t *note = parent == rks.kernel_pid ? calloc(1, sizeof(rks_exit_note_t)) : NULL;
    if(note != NULL)
    {
        note->pid = pid;
        note->status = proc->status;
        note->report = true;
        note->next = notes;
        notes = note;
    }
    if(parent == rks.kernel_pid)
    {
        rks_proc_unlink_locked(proc);
    }
    else
    {
        rks_wait4_notify_locked(parent, &replies);
    }
    pthread_mutex_unlock(&rks_proc_lock);
    
    rks_pending_flush(replies);
    
    /* like KSurface (proc_zombify): the parent learns about it with SIGCHLD */
    if(parent != rks.kernel_pid)
    {
        rks_proc_t *parent_proc = rks_proc_lookup(parent);
        if(parent_proc != NULL)
        {
            rks_proc_signal(parent_proc, SIGCHLD);
            rks_proc_release(parent_proc);
        }
    }
    
    while(notes != NULL)
    {
        rks_exit_note_t *next = notes->next;
        if(notes->report && rks.exit_handler != NULL)
        {
            rks.exit_handler(notes->pid, notes->status, rks.exit_context);
        }
        free(notes);
        notes = next;
    }
}

static bool rks_signal_is_fatal_by_default(int sig)
{
    switch(sig)
    {
        case SIGCHLD:
        case SIGCONT:
        case SIGURG:
        case SIGWINCH:
        case SIGINFO:
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
        case 0:
            return false;
        default:
            return true;
    }
}

int rks_proc_signal(rks_proc_t *proc, int sig)
{
    if(sig == SIGTTIN || sig == SIGTTOU)
    {
        return 0;
    }
    if(sig == SIGTSTP)
    {
        sig = SIGSTOP;
    }
    
    pthread_mutex_lock(&rks_proc_lock);
    if(proc->reaped || proc->state == RKS_PROC_ZOMBIE)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        return ESRCH;
    }
    if(proc->pid == rks.kernel_pid)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        return EPERM;
    }
    void *extension = proc->extension;
    if(extension != NULL)
    {
        CFRetain(extension);
    }
    int previous_fatal = proc->fatal_signal;
    if(rks_signal_is_fatal_by_default(sig))
    {
        proc->fatal_signal = sig;
    }
    pthread_mutex_unlock(&rks_proc_lock);
    
    if(sig == 0)
    {
        if(extension != NULL) CFRelease(extension);
        return 0;
    }
    
    bool delivered = extension != NULL && rks_extension_kill(extension, sig);
    if(extension != NULL)
    {
        CFRelease(extension);
    }
    if(!delivered && kill(proc->pid, sig) != 0)
    {
        int err = errno;
        pthread_mutex_lock(&rks_proc_lock);
        if(!proc->reaped && proc->state != RKS_PROC_ZOMBIE)
        {
            proc->fatal_signal = previous_fatal;
        }
        pthread_mutex_unlock(&rks_proc_lock);
        return err;
    }
    
    rks_pending_reply_t *replies = NULL;
    pid_t state_changed_parent = 0;
    pthread_mutex_lock(&rks_proc_lock);
    if(!proc->reaped && proc->state != RKS_PROC_ZOMBIE)
    {
        if(sig == SIGSTOP)
        {
            proc->state = RKS_PROC_STOPPED;
            proc->status = W_STOPCODE(SIGSTOP);
            proc->status_pending = true;
            rks_wait4_notify_locked(proc->ppid, &replies);
            state_changed_parent = proc->ppid;
        }
        else if(sig == SIGCONT && proc->state == RKS_PROC_STOPPED)
        {
            proc->state = RKS_PROC_RUNNING;
            proc->status = W_STOPCODE(SIGCONT);    /* WIFCONTINUED on Darwin */
            proc->status_pending = true;
            rks_wait4_notify_locked(proc->ppid, &replies);
            state_changed_parent = proc->ppid;
        }
    }
    pthread_mutex_unlock(&rks_proc_lock);
    rks_pending_flush(replies);
    
    /* like KSurface (proc_state_change): stop/continue reach the parent as SIGCHLD */
    if(state_changed_parent > 0 && state_changed_parent != rks.kernel_pid)
    {
        rks_proc_t *parent = rks_proc_lookup(state_changed_parent);
        if(parent != NULL)
        {
            rks_proc_signal(parent, SIGCHLD);
            rks_proc_release(parent);
        }
    }
    return 0;
}

int rks_pgrp_signal(pid_t pgid, int sig)
{
    pid_t pids[256];
    size_t count = 0;
    pthread_mutex_lock(&rks_proc_lock);
    for(rks_proc_t *proc = g_procs; proc != NULL && count < 256; proc = proc->next)
    {
        if(!proc->reaped && proc->state != RKS_PROC_ZOMBIE && proc->pgid == pgid && proc->pid != rks.kernel_pid)
        {
            pids[count++] = proc->pid;
        }
    }
    pthread_mutex_unlock(&rks_proc_lock);
    
    bool any = false;
    for(size_t i = 0; i < count; i++)
    {
        rks_proc_t *proc = rks_proc_lookup(pids[i]);
        if(proc != NULL)
        {
            if(rks_proc_signal(proc, sig) == 0)
            {
                any = true;
            }
            rks_proc_release(proc);
        }
    }
    return any ? 0 : ESRCH;
}

static int g_exit_kq = -1;

static void *rks_exit_watcher(void *ctx)
{
    (void)ctx;
    pthread_setname_np("librecoveryksurface.exitwatch");
    for(;;)
    {
        struct kevent event;
        int count = kevent(g_exit_kq, NULL, 0, &event, 1, NULL);
        if(count < 0)
        {
            if(errno == EINTR) continue;
            rks_logf("exit watch: kevent failed (%s), stopping", strerror(errno));
            return NULL;
        }
        if(count == 1 && event.filter == EVFILT_PROC && !(event.flags & EV_ERROR) && (event.fflags & NOTE_EXIT))
        {
            rks_proc_exited((pid_t)event.ident, false, 0);
        }
    }
}

void rks_proc_exit_watch(pid_t pid)
{
    static int logged_err = 0;
    
    if(g_exit_kq < 0 || pid <= 0)
    {
        return;
    }
    struct kevent change, receipt;
    EV_SET(&change, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT | EV_RECEIPT, NOTE_EXIT, 0, NULL);
    int count;
    do { count = kevent(g_exit_kq, &change, 1, &receipt, 1, NULL); } while(count < 0 && errno == EINTR);
    
    int err;
    if(count < 0) err = errno;
    else if(count != 1 || !(receipt.flags & EV_ERROR)) err = EPROTO;
    else err = (int)receipt.data;
    
    if(err == 0)
    {
        pthread_mutex_lock(&rks_proc_lock);
        rks_proc_t *proc = rks_proc_lookup_locked(pid);
        if(proc != NULL)
        {
            proc->exit_watched = true;
        }
        pthread_mutex_unlock(&rks_proc_lock);
    }
    else if(err == ESRCH)
    {
        /* died before we could register */
        rks_proc_exited(pid, false, 0);
    }
    else if(__atomic_exchange_n(&logged_err, err, __ATOMIC_RELAXED) != err)
    {
        rks_logf("exit watch: NOTE_EXIT refused for pid %d (%s), polling instead", pid, strerror(err));
    }
}

static void *rks_monitor(void *ctx)
{
    (void)ctx;
    pthread_setname_np("librecoveryksurface.monitor");
    for(;;)
    {
        usleep(50 * 1000);
        
        pid_t finalize[64];
        size_t count = 0;
        
        pthread_mutex_lock(&rks_proc_lock);
        for(rks_proc_t *proc = g_procs; proc != NULL && count < 64; proc = proc->next)
        {
            if(proc->reaped || proc->state == RKS_PROC_ZOMBIE || proc->pid == rks.kernel_pid || proc->exit_watched)
            {
                continue;
            }
            
            bool dead = false;
            if(proc->task != MACH_PORT_NULL)
            {
                mach_port_type_t type = 0;
                dead = mach_port_type(mach_task_self(), proc->task, &type) != KERN_SUCCESS || (type & MACH_PORT_TYPE_DEAD_NAME);
            }
            else
            {
                dead = kill(proc->pid, 0) != 0 && errno == ESRCH;
            }
            if(dead)
            {
                finalize[count++] = proc->pid;
            }
        }
        pthread_mutex_unlock(&rks_proc_lock);
        
        for(size_t i = 0; i < count; i++)
        {
            rks_proc_exited(finalize[i], false, 0);
        }
    }
    return NULL;
}

void rks_proc_monitor_start(void)
{
    pthread_t thread;
    
    g_exit_kq = kqueue();
    if(g_exit_kq >= 0)
    {
        fcntl(g_exit_kq, F_SETFD, FD_CLOEXEC);
        if(pthread_create(&thread, NULL, rks_exit_watcher, NULL) == 0)
        {
            pthread_detach(thread);
        }
        else
        {
            close(g_exit_kq);
            g_exit_kq = -1;
        }
    }
    if(g_exit_kq < 0)
    {
        rks_logf("exit watch: no kqueue, polling every process");
    }
    
    if(pthread_create(&thread, NULL, rks_monitor, NULL) == 0)
    {
        pthread_detach(thread);
    }
}

int64_t rks_sys_getppid(rks_call_t *call)
{
    pthread_mutex_lock(&rks_proc_lock);
    pid_t ppid = call->proc->ppid;
    pthread_mutex_unlock(&rks_proc_lock);
    return ppid;
}

int64_t rks_sys_getpgrp(rks_call_t *call)
{
    pthread_mutex_lock(&rks_proc_lock);
    pid_t pgid = call->proc->pgid;
    pthread_mutex_unlock(&rks_proc_lock);
    return pgid;
}

int64_t rks_sys_getpgid(rks_call_t *call)
{
    pid_t pid = (pid_t)call->args[0];
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *target = pid == 0 ? call->proc : rks_proc_lookup_locked(pid);
    pid_t pgid = target ? target->pgid : -1;
    pthread_mutex_unlock(&rks_proc_lock);
    if(pgid < 0)
    {
        RKS_FAIL(call, ESRCH);
    }
    return pgid;
}

int64_t rks_sys_getsid(rks_call_t *call)
{
    pid_t pid = (pid_t)call->args[0];
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *target = pid == 0 ? call->proc : rks_proc_lookup_locked(pid);
    pid_t sid = target ? target->sid : -1;
    pthread_mutex_unlock(&rks_proc_lock);
    if(sid < 0)
    {
        RKS_FAIL(call, ESRCH);
    }
    return sid;
}

int64_t rks_sys_setsid(rks_call_t *call)
{
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *self = call->proc;
    /* a process group leader cannot start a session */
    for(rks_proc_t *proc = g_procs; proc != NULL; proc = proc->next)
    {
        if(proc != self && !proc->reaped && proc->state != RKS_PROC_ZOMBIE && proc->pgid == self->pid)
        {
            pthread_mutex_unlock(&rks_proc_lock);
            RKS_FAIL(call, EPERM);
        }
    }
    self->sid = self->pid;
    self->pgid = self->pid;
    pid_t sid = self->sid;
    pthread_mutex_unlock(&rks_proc_lock);
    return sid;
}

int64_t rks_sys_setpgid(rks_call_t *call)
{
    pid_t pid = (pid_t)call->args[0];
    pid_t pgid = (pid_t)call->args[1];
    if(pgid < 0)
    {
        RKS_FAIL(call, EINVAL);
    }

    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *self = call->proc;
    rks_proc_t *target = (pid == 0 || pid == self->pid) ? self : rks_proc_lookup_locked(pid);
    errno_t err = 0;
    if(target == NULL || (target != self && target->ppid != self->pid))
    {
        err = ESRCH;
    }
    else if(target->sid != self->sid || target->sid == target->pid)
    {
        err = EPERM;
    }
    else
    {
        if(pgid == 0)
        {
            pgid = target->pid;
        }
        if(pgid != target->pid && !rks_pgrp_exists_in_session(pgid, self->sid))
        {
            err = EPERM;
        }
        else
        {
            target->pgid = pgid;
        }
    }
    pthread_mutex_unlock(&rks_proc_lock);
    if(err != 0)
    {
        RKS_FAIL(call, err);
    }
    return 0;
}

int64_t rks_sys_kill(rks_call_t *call)
{
    pid_t pid = (pid_t)call->args[0];
    int sig = (int)call->args[1];
    if(sig < 0 || sig >= NSIG)
    {
        RKS_FAIL(call, EINVAL);
    }

    if(pid > 0)
    {
        rks_proc_t *target = rks_proc_lookup(pid);
        if(target == NULL)
        {
            RKS_FAIL(call, ESRCH);
        }
        int err = rks_proc_signal(target, sig);
        rks_proc_release(target);
        if(err != 0)
        {
            RKS_FAIL(call, err);
        }
        return 0;
    }

    if(pid == 0 || pid < -1)
    {
        pthread_mutex_lock(&rks_proc_lock);
        pid_t pgid = pid == 0 ? call->proc->pgid : -pid;
        pthread_mutex_unlock(&rks_proc_lock);
        int err = rks_pgrp_signal(pgid, sig);
        if(err != 0)
        {
            RKS_FAIL(call, err);
        }
        return 0;
    }

    /* -1: everything but the recovery and the caller */
    pid_t pids[256];
    size_t count = 0;
    pthread_mutex_lock(&rks_proc_lock);
    for(rks_proc_t *proc = g_procs; proc != NULL && count < 256; proc = proc->next)
    {
        if(!proc->reaped && proc->state != RKS_PROC_ZOMBIE && proc->pid != rks.kernel_pid && proc->pid != call->proc->pid)
        {
            pids[count++] = proc->pid;
        }
    }
    pthread_mutex_unlock(&rks_proc_lock);
    for(size_t i = 0; i < count; i++)
    {
        rks_proc_t *target = rks_proc_lookup(pids[i]);
        if(target != NULL)
        {
            rks_proc_signal(target, sig);
            rks_proc_release(target);
        }
    }
    if(count == 0)
    {
        RKS_FAIL(call, ESRCH);
    }
    return 0;
}

int64_t rks_sys_wait4(rks_call_t *call)
{
    pid_t selector = (pid_t)call->args[0];
    uint64_t status_ptr = (uint64_t)call->args[1];
    int options = (int)call->args[2];

    pthread_mutex_lock(&rks_proc_lock);
    pid_t caller = call->proc->pid;
    pid_t caller_pgid = call->proc->pgid;
    int status = 0;
    bool matched = false;
    pid_t pid = rks_wait4_claim_locked(caller, caller_pgid, selector, options, &status, &matched);
    if(pid > 0)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        if(status_ptr != 0)
        {
            rks_copy_out(call->task, status_ptr, &status, sizeof(status));
        }
        return pid;
    }
    if(!matched)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        RKS_FAIL(call, ECHILD);
    }
    if(options & WNOHANG)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        return 0;
    }
    /* registered under the lock: no state change can slip in between the scan and the wait */
    int64_t result = rks_wait4_block(call, selector, options, status_ptr);
    pthread_mutex_unlock(&rks_proc_lock);
    return result;
}

int64_t rks_sys_waittask(rks_call_t *call)
{
    pid_t target = (pid_t)call->args[0];
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *proc = rks_proc_lookup_locked(target);
    if(proc == NULL)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        RKS_FAIL(call, ECHILD);
    }
    if(proc->task != MACH_PORT_NULL || proc->state == RKS_PROC_ZOMBIE)
    {
        pthread_mutex_unlock(&rks_proc_lock);
        return 0;
    }
    int64_t result = rks_waittask_block(call, target);
    pthread_mutex_unlock(&rks_proc_lock);
    return result;
}

/* recovery drops entitlements: any process may have any task port */
int64_t rks_sys_task_for_pid(rks_call_t *call)
{
    pid_t pid = (pid_t)call->args[0];
    pthread_mutex_lock(&rks_proc_lock);
    rks_proc_t *target = rks_proc_lookup_locked(pid);
    task_t task = MACH_PORT_NULL;
    if(target != NULL && target->task != MACH_PORT_NULL &&
       mach_port_mod_refs(mach_task_self(), target->task, MACH_PORT_RIGHT_SEND, 1) == KERN_SUCCESS)
    {
        task = target->task;
    }
    pthread_mutex_unlock(&rks_proc_lock);
    if(task == MACH_PORT_NULL)
    {
        RKS_FAIL(call, ESRCH);
    }
    call->out_ports[call->out_count++] = task;
    return 0;
}

int64_t rks_sys_exitstatus(rks_call_t *call)
{
    pthread_mutex_lock(&rks_proc_lock);
    call->proc->has_reported_exit = true;
    call->proc->reported_exit = (int)call->args[0];
    pthread_mutex_unlock(&rks_proc_lock);
    return 0;
}
