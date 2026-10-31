/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab
 Copyright (C) 2026 zipgod24

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

#import <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/trust/entitlement.h>
#import <LindChain/ProcEnvironment/Surface/proc/spawn.h>
#import <LindChain/ProcEnvironment/Surface/proc/remove.h>
#import <LindChain/ProcEnvironment/Surface/proc/insert.h>
#import <LindChain/ProcEnvironment/Surface/proc/def.h>
#import <LindChain/ProcEnvironment/PEProcessManager.h>
#import <LindChain/ProcEnvironment/PEUserspaceManager.h>
#include <ksurface_config.h>

LIBKERN_DEFINE_PATCHABLE(kern_return_t, proc_spawn, (ksurface_proc_t *parent,
                                                     ksurface_proc_t **child,
                                                     pid_t child_pid,
                                                     int child_pidv,
                                                     ksurface_trust_identity_t *identity))
{
    assert(parent != NULL && child != NULL && identity != NULL);
    
    ksurface_proc_t *child_new = kvo_copy(parent);
    if(child_new == NULL)
    {
        return KERN_FAILURE;
    }

    proc_setppid(child_new, proc_getpid(child_new));    /* as the child is the copy of the parent the current pid is the ppid */
    proc_setpid(child_new, child_pid);      /* function passed pid of child */
    proc_setpidv(child_new, child_pidv);
    
    child_new->nyx.identity = identity;
    
    child_new->nyx.entitlements = trust_identity_entitlement_flags_from_entitlements(identity->entitlements);
    child_new->nyx.maxEntitlements = child_new->nyx.entitlements;
    
    if(parent == kernel_proc_)
    {
        /* process needs fresh credentials */
        proc_setmobilecred(child_new);
        proc_setsid(child_new, proc_getpid(child_new));
        proc_setpgid(child_new, proc_getpid(child_new));
    }
    
    if(CFDictionaryGetValue(identity->entitlements, kNXT2EntitlementPlatform) == kCFBooleanTrue)
    {
        /* only platform processes can use those */
        
        if(CFDictionaryGetValue(identity->entitlements, kNXT2EntitlementPlatformRoot) == kCFBooleanTrue)
        {
            /*
             * child process exeuctable is platform binary and has
             * the special platform root entitlement which overweighs
             * the platform user and group entitlement.
             */
            proc_setrootcred(child_new);
        }
        else
        {
            /* special user and group entitlement handling */
            CFNumberRef entitlementUserIdentifier = CFDictionaryGetValue(identity->entitlements, kNXT2EntitlementPlatformUser);
            CFNumberRef entitlementGroupIdentifier = CFDictionaryGetValue(identity->entitlements, kNXT2EntitlementPlatformGroup);
            int32_t identifier;
            if(entitlementUserIdentifier != NULL && CFNumberGetValue(entitlementUserIdentifier, kCFNumberSInt32Type, &identifier))
            {
                proc_setruid(child_new, identifier);
                proc_seteuid(child_new, identifier);
                proc_setsvuid(child_new, identifier);
            }
            if(entitlementGroupIdentifier != NULL && CFNumberGetValue(entitlementGroupIdentifier, kCFNumberSInt32Type, &identifier))
            {
                proc_setrgid(child_new, identifier);
                proc_setegid(child_new, identifier);
                proc_setsvgid(child_new, identifier);
            }
        }
    }
        
    /* FIXME: argv[0] shall be used for p_comm and not the last path component */
    const char *name = strrchr(identity->path, '/');
    name = name ? name + 1 : identity->path;
    strlcpy(child_new->bsd.kp_proc.p_comm, name, MAXCOMLEN + 1);
    
    /* insert will retain the child process */
    if(proc_insert(child_new) != KERN_SUCCESS)
    {
        klog_log("ksurface:proc:spawn", "failed to insert process %p into process table", child);
        
        /* releasing child process because of failed insert */
        kvo_release(child_new);
        return KERN_FAILURE;
    }
    
    /*
     * referencing parent first, to
     * first of all prevent a reference leak
     * and second of all dont waste cpu cycles
     * this is basically the part where we
     * tell the parent who their child is
     * and the child who their parent is
     * and create a reference contract.
     */
    if(!kvo_retain(parent))
    {
        goto out_parent_contract_retain_failed;
    }
    
    pthread_mutex_lock(&(parent->children.mutex));
    
    /*
     * checking if it would exceed maximum amount
     * of child processes per process.
     */
    if(parent->children.children_cnt >= CHILD_PROC_MAX ||
       !kvo_retain(child_new))
    {
        pthread_mutex_unlock(&(parent->children.mutex));
        kvo_release(child_new);
        
    out_parent_contract_retain_failed:
        proc_remove_by_pid(proc_getpid(child_new));
        return KERN_FAILURE;
    }
    
    pthread_mutex_lock(&(child_new->children.mutex));
    
    /* performing contract */
    child_new->children.parent = parent;
    child_new->children.parent_cld_idx = parent->children.children_cnt++;
    parent->children.children[child_new->children.parent_cld_idx] = child_new;
    
    pthread_mutex_unlock(&(child_new->children.mutex));
    pthread_mutex_unlock(&(parent->children.mutex));
    
    *child = child_new;
    
    /* child stays retained for the caller */
    return KERN_SUCCESS;
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, proc_kill, (ksurface_proc_t *child,
                                                    int sig))
{
    if(child == NULL)
    {
        return KERN_INVALID_ADDRESS;
    }
    
    /* only valid signals shall be played with lol */
    if(sig <= 0 || sig >= NSIG)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    /* getting the processes high level structure */
    kvo_rdlock(child);  /* locking so we can safely read the pid field */
#if KSURFACE_EMIT_LAUNCHD
    if(proc_getpid(child) == 1)
    {
        kvo_unlock(child);
        if(sig == SIGKILL ||
           sig == SIGTERM)
        {
            @autoreleasepool {
                [[PEUserspaceManager shared] rebootUserspace];
            }
        }
        return KERN_SUCCESS;
    }
#endif /* KSURFACE_EMIT_LAUNCHD */
    PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:proc_getpid(child)];
    kvo_unlock(child);
    if(!process)
    {
        /*
         * returns the same value as normal failure to prevent deterministic exploitation,
         * of process reference counting.
         */
        return KERN_NOT_FOUND;
    }
    
    [process sendSignal:sig];
    return KERN_SUCCESS;
}

static inline kern_return_t proc_reap_nolock(ksurface_proc_t *proc)
{
    assert(proc != NULL && proc != kernel_proc_);
    
    /* retain process that wants to exit */
    if(!kvo_retain(proc))
    {
        return KERN_FAILURE;
    }
    
    /* lock mutex */
    pthread_mutex_lock(&(proc->children.mutex));
    
    /* killing all children of the exiting process */
    while(proc->children.children_cnt > 0)
    {
        /* get index of last child */
        uint64_t idx = proc->children.children_cnt - 1;
        ksurface_proc_t *child = proc->children.children[idx];
        
        /* retaining child */
        if(!kvo_retain(child))
        {
            /* in case we cannot retain the child, we skip the child */
            continue;
        }
        
        /* unlocking our mutex */
        pthread_mutex_unlock(&(proc->children.mutex));
        
        /* calling exit on the child */
        proc_reap_nolock(child);
        
        /* releasing reference previously retained */
        kvo_release(child);
        
        /* relocking */
        pthread_mutex_lock(&(proc->children.mutex));
    }
    
    /* unlock */
    pthread_mutex_unlock(&(proc->children.mutex));
    
    /* remove from parent */
    ksurface_proc_t *parent = proc->children.parent;
    if(parent != NULL)
    {
        /* retaining the parent */
        if(!kvo_retain(parent))
        {
            /* releasing child */
            kvo_release(proc);
            return KERN_FAILURE;
        }
        
        /* lock order: parent → child */
        pthread_mutex_lock(&(parent->children.mutex));
        pthread_mutex_lock(&(proc->children.mutex));
        
        uint64_t my_idx = proc->children.parent_cld_idx;
        uint64_t last_idx = parent->children.children_cnt - 1;
        
        /* swap with last if needed */
        if(my_idx != last_idx)
        {
            ksurface_proc_t *last_proc = parent->children.children[last_idx];
            
            pthread_mutex_lock(&(last_proc->children.mutex));
            parent->children.children[my_idx] = last_proc;
            last_proc->children.parent_cld_idx = my_idx;
            pthread_mutex_unlock(&(last_proc->children.mutex));
        }
        
        /* clear slot and decrement */
        parent->children.children[last_idx] = NULL;
        parent->children.children_cnt--;
        
        /* clear our parent reference */
        proc->children.parent = NULL;
        proc->children.parent_cld_idx = 0;
        
        pthread_mutex_unlock(&(proc->children.mutex));
        pthread_mutex_unlock(&(parent->children.mutex));
        
        /* release relationship references */
        kvo_release(proc);
        kvo_release(parent);
        
        /* release working ref */
        kvo_release(parent);
    }
    
    pid_t pid = proc_getpid(proc);
    
    /* TODO: Completely move to tree-based system, which is possible now */
    proc_remove_by_pid__nolock(pid);  /* remove from global table */
    
    /* release our working reference */
    kvo_release(proc);
    
    /* terminate process */
    PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:pid];
    if(process != NULL)
    {
        [process forceTerminate];
    }
    
    return KERN_SUCCESS;
}

kern_return_t proc_reap(ksurface_proc_t *proc)
{
    assert(proc != NULL && proc != kernel_proc_);
    proc_table_wrlock();
    kern_return_t kr = proc_reap_nolock(proc);
    proc_table_unlock();
    return kr;
}

kern_return_t proc_zombify(ksurface_proc_t *proc)
{
    assert(proc != NULL && proc != kernel_proc_);
    
    /* retain process that wants to be zombified */
    if(!kvo_retain(proc))
    {
        return KERN_FAILURE;
    }
    
    pthread_mutex_lock(&(proc->children.mutex));
    
    /* killing all children of the exiting process */
    while(proc->children.children_cnt > 0)
    {
        /* get index of last child */
        uint64_t idx = proc->children.children_cnt - 1;
        ksurface_proc_t *child = proc->children.children[idx];
        
        /* retaining child */
        if(!kvo_retain(child))
        {
            /* in case we cannot retain the child, we skip the child */
            continue;
        }
        
        /*
         * have to unlock it so proc_exit can claim the lock
         * on the recurse. as its needed to zombify all processes
         * underneath.
         */
        pthread_mutex_unlock(&(proc->children.mutex));
        proc_reap(child);
        kvo_release(child);
        pthread_mutex_lock(&(proc->children.mutex));
    }
    
    /* when parent is the kernel dont zombify, reap immediately */
    if(proc->children.parent == kernel_proc_)
    {
        pthread_mutex_unlock(&(proc->children.mutex));
        kvo_release(proc);
        proc_reap(proc);
        return KERN_SUCCESS;
    }
    
    pthread_mutex_unlock(&(proc->children.mutex));
    
    /* mark as zombified */
    kvo_wrlock(proc);
    proc->bsd.kp_proc.p_stat = SZOMB;
    kvo_unlock(proc);
    
    ksurface_proc_t *parent = NULL;
    kern_return_t kr = proc_parent_for_proc(proc, &parent);
    if(kr == KERN_SUCCESS)
    {
        kvo_event_trigger(parent, kProcEventTypeWait4, (uintptr_t)proc);
        
        PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:proc_getpid(parent)];
        if(process != nil)
        {
            [process sendSignal:SIGCHLD];
        }
        
        kvo_release(parent);
    }
    
    kvo_release(proc);
    
    return KERN_SUCCESS;
}

kern_return_t proc_state_change(ksurface_proc_t *proc,
                                int64_t status)
{
    ksurface_proc_t *parent = NULL;
    kern_return_t kr = proc_parent_for_proc(proc, &parent);
    if(kr != KERN_SUCCESS)
    {
        return kr;
    }
    
    pthread_mutex_lock(&(parent->children.mutex));
    proc->nyx.p_status = status;
    pthread_mutex_unlock(&(parent->children.mutex));
    
    kvo_event_trigger(parent, kProcEventTypeWait4, (uintptr_t)proc);
    
    PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:proc_getpid(parent)];
    kvo_release(parent);
    if(process == nil)
    {
        return KERN_NO_ACCESS;
    }
    
    [process sendSignal:SIGCHLD];
    
    return KERN_SUCCESS;
}
