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

#include <LindChain/ProcEnvironment/Surface/sys/proc/wait4.h>
#include <LindChain/ProcEnvironment/Surface/proc/proc.h>
#include <LindChain/ProcEnvironment/Surface/proc/list.h>
#include <errno.h>

typedef struct wait4_payload {
    userspace_pointer_t status_ptr;
    userspace_pointer_t rusage_ptr;
    int options;
    task_t task;
    recv_buffer_t *buffer;
    pid_t waitonpid;
    pid_t caller_pgid;
} wait4_payload_t;

static bool wait4_matches_selector(pid_t selector,
                                   pid_t caller_pgid,
                                   ksurface_proc_t *child)
{
    pid_t child_pid = proc_getpid(child);
    pid_t child_pgid = proc_getpgid(child);
    
    if(selector > 0)
    {
        return selector == child_pid;
    }
    if(selector == -1)
    {
        return true;
    }
    if(selector == 0)
    {
        return child_pgid == caller_pgid;
    }
    
    return child_pgid == (pid_t)(-(int64_t)selector);
}

void *proc_reap_thread(void *ctx)
{
    proc_reap((ksurface_proc_t*)ctx);
    kvo_release(ctx);
    return NULL;
}

bool wait4_proc_event_handler(uint32_t type,
                              uint64_t val,
                              kvobject_event_t *event)
{
    ksurface_proc_t *parent = (ksurface_proc_t*)(event->owner);
    wait4_payload_t *payload = (wait4_payload_t*)(event->ctx);
    ksurface_proc_t *child = (ksurface_proc_t*)(uintptr_t)val;
    if(type == kvObjEventUnregister)
    {
        mach_port_deallocate(mach_task_self(), payload->task);
        free(payload);
        return true;
    }
    
    if(child == NULL)
    {
        return true;
    }
    
    pthread_mutex_lock(&(parent->children.mutex));
    kvo_wrlock(child);
    if(!wait4_matches_selector(payload->waitonpid, payload->caller_pgid, child))
    {
        kvo_unlock(child);
        pthread_mutex_unlock(&(parent->children.mutex));
        return false;
    }
    
    switch(type)
    {
        case kProcEventTypeWait4:
            if((((payload->options & WSTOPPED) == WSTOPPED) && WIFSTOPPED(child->nyx.p_status)) ||
               (((payload->options & WCONTINUED) == WCONTINUED) && WIFCONTINUED(child->nyx.p_status)))
            {
                goto out_trigger_unregister;
            }
            else if(child->bsd.kp_proc.p_stat == SZOMB)
            {
                if(!kvo_retain(child))
                {
                    kpanic("failed to retain exited child process");
                }
                
                pthread_t thread;
                if(pthread_create(&thread, NULL, proc_reap_thread, child) != 0)
                {
                    kpanic("failed to create reap thread for exited child process");
                }
                else
                {
                    pthread_detach(thread);
                }
                
                if(!WIFEXITED(child->nyx.p_status))
                {
                    child->nyx.p_status = W_EXITCODE(0, SIGKILL);
                }
                
                goto out_trigger_unregister;
            }
            break;
        default:
            break;
    }
    
    kvo_unlock(child);
    pthread_mutex_unlock(&(parent->children.mutex));
    return false;

out_trigger_unregister:
    syscall_copy_out(payload->task, sizeof(int), &(child->nyx.p_status), payload->status_ptr);
    child->nyx.p_status = 0;
    syscall_send_reply(&(payload->buffer->header), proc_getpid(child), NULL, 0, true, 0);
    kvo_unlock(child);
    pthread_mutex_unlock(&(parent->children.mutex));
    return true;
}

static void wait4_replay_children(ksurface_proc_t *parent,
                                  pid_t selector,
                                  pid_t caller_pgid)
{
    ksurface_proc_t *children[CHILD_PROC_MAX];
    uint64_t count = 0;
    
    pthread_mutex_lock(&(parent->children.mutex));
    for(uint64_t i = 0; i < parent->children.children_cnt && count < CHILD_PROC_MAX; i++)
    {
        ksurface_proc_t *child = parent->children.children[i];
        if(!kvo_retain(child))
        {
            continue;
        }
        
        kvo_rdlock(child);
        bool matches = wait4_matches_selector(selector, caller_pgid, child);
        kvo_unlock(child);
        
        if(!matches)
        {
            kvo_release(child);
            continue;
        }
        
        children[count++] = child;
    }
    pthread_mutex_unlock(&(parent->children.mutex));
    
    for(uint64_t i = 0; i < count; i++)
    {
        kvo_event_trigger(parent, kProcEventTypeWait4, (uintptr_t)children[i]);
        kvo_release(children[i]);
    }
}

DEFINE_SYSCALL_HANDLER(wait4)
{
    pid_t u_pid = (pid_t)args[0];
    int u_options = (int)args[2];
    pid_t caller_pgid = proc_getpgid(sys_proc_snapshot_);
    bool matched_child = false;
    
    pthread_mutex_lock(&(sys_proc_->children.mutex));
    for(uint64_t i = 0; i < sys_proc_->children.children_cnt; i++)
    {
        ksurface_proc_t *proc = sys_proc_->children.children[i];
        if(!wait4_matches_selector(u_pid, caller_pgid, proc))
        {
            continue;
        }
        
        matched_child = true;
        kvo_rdlock(proc);
        
        if(!kvo_retain(proc))
        {
            kvo_unlock(proc);
            continue;
        }
        
        if((((u_options & WSTOPPED) == WSTOPPED) && WIFSTOPPED(proc->nyx.p_status)) || (((u_options & WCONTINUED) == WCONTINUED) && WIFCONTINUED(proc->nyx.p_status)))
        {
            goto out_report;
        }
        else if(proc->bsd.kp_proc.p_stat == SZOMB)
        {
            pthread_mutex_unlock(&(sys_proc_->children.mutex));
            proc_reap(proc);
            pthread_mutex_lock(&(sys_proc_->children.mutex));
            
            if(!WIFEXITED(proc->nyx.p_status))
            {
                proc->nyx.p_status = W_EXITCODE(0, SIGKILL);
            }
            
        out_report:
            syscall_copy_out(sys_task_, sizeof(int), &(proc->nyx.p_status), (userspace_pointer_t)args[1]);
            proc->nyx.p_status = 0;
            
            pid_t reported_pid = proc_getpid(proc);
            kvo_unlock(proc);
            kvo_release(proc);
            pthread_mutex_unlock(&(sys_proc_->children.mutex));
            return reported_pid;
        }
        
        kvo_unlock(proc);
        kvo_release(proc);
    }
    
    pthread_mutex_unlock(&(sys_proc_->children.mutex));
    
    if(!matched_child)
    {
        sys_return_failure_with_errno(ECHILD);
    }
    
    if((u_options & WNOHANG) == WNOHANG)
    {
        sys_return;
    }
    
    wait4_payload_t *payload = malloc(sizeof(wait4_payload_t));
    if(payload == NULL)
    {
        sys_return_failure_with_errno(ENOMEM);
    }
    
    kern_return_t kr = mach_port_mod_refs(mach_task_self(), sys_task_, MACH_PORT_RIGHT_SEND, 1);
    if(kr != KERN_SUCCESS)
    {
        free(payload);
        sys_return_failure_with_errno(EAGAIN);
    }
    
    payload->task = sys_task_;
    payload->status_ptr = (userspace_pointer_t)args[1];
    payload->rusage_ptr = (userspace_pointer_t)args[3];
    payload->options = u_options;
    payload->buffer = *recv_buffer;
    payload->waitonpid = u_pid;
    payload->caller_pgid = caller_pgid;
    
    kr = kvo_event_register(sys_proc_, kProcEventTypeWait4, wait4_proc_event_handler, payload, NULL);
    if(kr != KERN_SUCCESS)
    {
        mach_port_deallocate(mach_task_self(), sys_task_);
        free(payload);
        sys_return_failure_with_errno(EAGAIN);
    }
    
    *recv_buffer = NULL;
    
    wait4_replay_children(sys_proc_, u_pid, caller_pgid);
    sys_return;
}
