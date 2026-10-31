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

#include <LindChain/ProcEnvironment/Surface/sys/proc/proc_info.h>
#include <LindChain/ProcEnvironment/Surface/proc/lookup.h>
#include <LindChain/ProcEnvironment/Surface/proc/spawn.h>
#include <LindChain/ProcEnvironment/Surface/proc/permit.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <os/lock.h>
#include <ksurface_config.h>

static os_unfair_lock g_kernmsgbuf_lock = OS_UNFAIR_LOCK_INIT;

DEFINE_SYSCALL_HANDLER(proc_info_listpids)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_pidinfo)
{
    uint32_t u_flavour = (uint32_t)args[2];
    
    switch(u_flavour)
    {
        case PROC_PIDLISTFDS:
        case PROC_PIDTASKALLINFO:
            sys_return_failure_with_errno(ENOSYS);
        case PROC_PIDTBSDINFO:
        {
            /* prepare arguments */
            pid_t u_pid = (pid_t)args[1];
            userspace_pointer_t u_buffer_ptr = (userspace_pointer_t)args[4];
            int32_t u_size = (int32_t)args[5];
            
            if(u_size < sizeof(struct proc_bsdinfo))
            {
                sys_set_errno(ENOMEM);
                return (int)sizeof(struct proc_bsdinfo);
            }
            
            if(u_size > sizeof(struct proc_bsdinfo))
            {
                sys_set_errno(EOVERFLOW);
                return (int)sizeof(struct proc_bsdinfo);
            }
            
            /* getting target process */
            ksurface_proc_t *target;
            kern_return_t ret = proc_for_pid(u_pid, &target);
            if(ret != KERN_SUCCESS)
            {
                sys_return_failure_with_errno(ESRCH);
            }
            
            /* checking if caller can see target process */
            proc_visibility_t vis = proc_get_proc_visibility(sys_proc_snapshot_);
            if(!proc_can_see_proc(sys_proc_snapshot_, target, vis))
            {
                kvo_release(target);
                sys_return_failure_with_errno(ESRCH);
            }
            
            kvo_rdlock(target);
            struct proc_bsdinfo bsd_pcb;    /* BSD process control block likely idk */
            bzero(&bsd_pcb, sizeof(struct proc_bsdinfo));
            bsd_pcb.pbi_flags = target->bsd.kp_proc.p_flag;     /* idk */
            bsd_pcb.pbi_status = target->bsd.kp_proc.p_stat;    /* idk */
            bsd_pcb.pbi_xstatus = target->bsd.kp_proc.p_stat;   /* idk */
            bsd_pcb.pbi_pid = proc_getpid(target);
            bsd_pcb.pbi_ppid = proc_getppid(target);
            bsd_pcb.pbi_uid = proc_geteuid(target);
            bsd_pcb.pbi_gid = proc_getegid(target);
            bsd_pcb.pbi_ruid = proc_getruid(target);
            bsd_pcb.pbi_rgid = proc_getrgid(target);
            bsd_pcb.pbi_svuid = proc_getsvuid(target);
            bsd_pcb.pbi_svgid = proc_getsvgid(target);
            strlcpy(bsd_pcb.pbi_comm, target->bsd.kp_proc.p_comm, MAXCOMLEN);
            strlcpy(bsd_pcb.pbi_name, target->bsd.kp_proc.p_comm, MAXCOMLEN);
            bsd_pcb.pbi_nfiles = 0;
            bsd_pcb.pbi_pgid = proc_getpgid(target);
            bsd_pcb.pbi_pjobc = 0;  /* no job control yet */
            bsd_pcb.e_tdev = 0;     /* controlling tty dev */
            bsd_pcb.e_tpgid = 0;    /* tty process group id */
            bsd_pcb.pbi_nice = 0;
            bsd_pcb.pbi_start_tvsec = target->bsd.kp_proc.p_un.__p_starttime.tv_sec;
            bsd_pcb.pbi_start_tvusec = target->bsd.kp_proc.p_un.__p_starttime.tv_usec;
            kvo_unlock(target);
            kvo_release(target);
            
            if(!syscall_copy_out(sys_task_, sizeof(struct proc_bsdinfo), &bsd_pcb, u_buffer_ptr))
            {
                sys_return_failure_with_errno(EFAULT);
            }
            
            sys_return;
        }
        case PROC_PIDTASKINFO:
        case PROC_PIDTHREADINFO:
        case PROC_PIDLISTTHREADS:
        case PROC_PIDREGIONINFO:
        case PROC_PIDREGIONPATHINFO:
        case PROC_PIDVNODEPATHINFO:
        case PROC_PIDTHREADPATHINFO:
            sys_return_failure_with_errno(ENOSYS);
        case PROC_PIDPATHINFO:
        {
            /* prepare arguments */
            pid_t u_pid = (pid_t)args[1];
            userspace_pointer_t u_buffer_ptr = (userspace_pointer_t)args[4];
            int32_t u_size = (int32_t)args[5];
            
            if(u_size < PROC_PIDPATHINFO_SIZE)
            {
                /* XNU semantic */
                sys_return_failure_with_errno(ENOMEM);
            }
            
            if(u_size > PROC_PIDPATHINFO_MAXSIZE)
            {
                /* XNU semantic */
                sys_return_failure_with_errno(EOVERFLOW);
            }
            
            /* getting target process */
            ksurface_proc_t *target;
            kern_return_t ret = proc_for_pid(u_pid, &target);
            if(ret != KERN_SUCCESS)
            {
                sys_return_failure_with_errno(ESRCH);
            }
            
#if KSURFACE_EMIT_KERNEL_TASK
            /* check if it is kernel task */
            kvo_rdlock(target);
            if(target->bsd.kp_proc.p_flag & P_SYSTEM)
            {
                kvo_unlock(target);
                kvo_release(target);
                sys_return_failure_with_errno(ESRCH);
            }
            kvo_unlock(target);
#endif /* KSURFACE_EMIT_KERNEL_TASK */
            
            /* checking if caller can see target process */
            proc_visibility_t vis = proc_get_proc_visibility(sys_proc_snapshot_);
            if(!proc_can_see_proc(sys_proc_snapshot_, target, vis))
            {
                kvo_release(target);
                sys_return_failure_with_errno(ESRCH);
            }
            
            /* getting buffer of target (we shouldn't hold it for long) */
            char path[sizeof(target->nyx.identity->path)];
            kvo_rdlock(target);
            size_t size = strlcpy(path, target->nyx.identity->path, sizeof(target->nyx.identity->path)) + 1;
            kvo_unlock(target);
            kvo_release(target);
            
            /* final copy out */
            if(!syscall_copy_out(sys_task_, size, path, u_buffer_ptr))
            {
                sys_return_failure_with_errno(EFAULT);
            }
            sys_return;
        }
        case PROC_PIDWORKQUEUEINFO:
        case PROC_PIDT_SHORTBSDINFO:
        case PROC_PIDLISTFILEPORTS:
        case PROC_PIDTHREADID64INFO:
        case PROC_PIDUNIQIDENTIFIERINFO:
        case PROC_PIDT_BSDINFOWITHUNIQID:
        case PROC_PIDARCHINFO:
        case PROC_PIDCOALITIONINFO:
        case PROC_PIDNOTEEXIT:
        case PROC_PIDREGIONPATHINFO2:
        case PROC_PIDREGIONPATHINFO3:
        case PROC_PIDEXITREASONINFO:
        case PROC_PIDEXITREASONBASICINFO:
        case PROC_PIDLISTUPTRS:
        case PROC_PIDLISTDYNKQUEUES:
        case PROC_PIDLISTTHREADIDS:
        case PROC_PIDVMRTFAULTINFO:
        case PROC_PIDPLATFORMINFO:
        case PROC_PIDREGIONPATH:
        case PROC_PIDIPCTABLEINFO:
        default:
            sys_return_failure_with_errno(ENOSYS);
    }
    sys_return_failure_with_errno(EINVAL);
}

DEFINE_SYSCALL_HANDLER(proc_info_pidfdinfo)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_kernmsgbuf)
{
    /* parsing arguments */
    userspace_pointer_t u_buffer = (userspace_pointer_t)args[4];
    int32_t u_buffersize = (int32_t)args[5];
    
    if(u_buffersize < 0)
    {
        sys_return_failure_with_errno(EINVAL);
    }
    
    /* first permission checks */
    if(proc_geteuid(sys_proc_snapshot_) != 0 &&
       !entitlement_got_entitlement(proc_getmaxentitlements(sys_proc_snapshot_), kPEEntitlementFlagPlatform) &&
       trust_enforcement_should_deny(proc_getpid(sys_proc_snapshot_), kPEEntitlementFlagPlatform, "kernmsgbuf read"))
    {
        sys_return_failure_with_errno(EPERM);
    }
    
    /* getting size */
    extern int kfd; /* file descriptor to kernel log */
    struct stat kfdstat;
    if(fstat(kfd, &kfdstat) != 0)
    {
        return 0;
    }
    off_t currentSize = kfdstat.st_size;
    off_t copySize = (u_buffersize < currentSize) ? u_buffersize : currentSize;
    
    /* is it asking for the size? */
    if(u_buffersize == 0 && u_buffer == NULL)
    {
        return (int)currentSize;
    }
    
    /* copy! (locked so it doesn't become a memory starvation vector) */
    os_unfair_lock_lock(&g_kernmsgbuf_lock);
    void *klog_mem = mmap(NULL, currentSize, PROT_READ, MAP_SHARED, kfd, 0);
    if(klog_mem == MAP_FAILED)
    {
        os_unfair_lock_unlock(&g_kernmsgbuf_lock);
        sys_return_failure_with_errno(ENOMEM);  /* "if you run out of memory, you run out of memory" - speedyfriendy67 (such a retarded quote bruh ^^) */
    }
    bool success = syscall_copy_out(sys_task_, copySize, klog_mem, u_buffer);
    munmap(klog_mem, currentSize);
    os_unfair_lock_unlock(&g_kernmsgbuf_lock);
    if(!success)
    {
        sys_return_failure_with_errno(EFAULT);
    }
    
    return (int)copySize;
}

DEFINE_SYSCALL_HANDLER(proc_info_setcontrol)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_pidfileportinfo)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_terminate)
{
    /* parsing arguments */
    pid_t u_pid = (pid_t)args[1];
    
    /* we need the process */
    ksurface_proc_t *target;
    kern_return_t kr = proc_for_pid(u_pid, &target);
    if(kr != KERN_SUCCESS)
    {
        sys_return_failure_with_errno(ESRCH);
    }
    
    if(!proc_snapshot_primitive_over_proc_allowed(sys_proc_snapshot_, target, kPEEntitlementFlagProcessKill, kPEEntitlementFlagNone, err))
    {
        kvo_release(target);
        sys_return_failure();
    }
    
    /* making sure it is not ksurface it self */
    kvo_rdlock(target);
    if(target->bsd.kp_proc.p_flag & P_SYSTEM)
    {
        kvo_unlock(target);
        kvo_release(target);
        sys_return_failure_with_errno(EPERM);
    }
    kvo_unlock(target);
    
    /* now terminating it lol */
    proc_kill(target, SIGKILL);
    kvo_release(target);
    sys_return;
}

DEFINE_SYSCALL_HANDLER(proc_info_dirtycontrol)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_pidrusage)
{
    /* parse arguments */
    pid_t u_pid = (pid_t)args[1];
    uint32_t u_flavour = (uint32_t)args[2];
    userspace_pointer_t u_buffer_ptr = (userspace_pointer_t)args[4];
    
    if(u_flavour > RUSAGE_INFO_V6)
    {
        sys_return_failure_with_errno(ENOSYS);
    }
    
    /* getting target process */
    ksurface_proc_t *target;
    kern_return_t ret = proc_for_pid(u_pid, &target);
    if(ret != KERN_SUCCESS)
    {
        sys_return_failure_with_errno(ESRCH);
    }
    
    /* checking if caller can see target process */
    proc_visibility_t vis = proc_get_proc_visibility(sys_proc_snapshot_);
    if(!proc_can_see_proc(sys_proc_snapshot_, target, vis))
    {
        kvo_release(target);
        sys_return_failure_with_errno(ESRCH);
    }
    
    task_t target_task;
    task_special_port_t flavour = TASK_NAME_PORT;
    kern_return_t kr = proc_task_for_proc(target, &flavour, &target_task);
    if(kr != KERN_SUCCESS)
    {
        kvo_release(target);
        sys_return_failure_with_errno(ESRCH);
    }
    
    struct rusage_info_v6 rv6 = {};
    kvo_rdlock(target);
    switch(u_flavour)
    {
        case RUSAGE_INFO_V6:
        {
            /*
             * UNIMPLEMENTED
             *
             * uint64_t ri_user_ptime;
             * uint64_t ri_system_ptime;
             * uint64_t ri_pinstructions;
             * uint64_t ri_pcycles;
             * uint64_t ri_energy_nj;
             * uint64_t ri_penergy_nj;
             * uint64_t ri_secure_time_in_system;
             * uint64_t ri_secure_ptime_in_system;
             * uint64_t ri_neural_footprint;
             * uint64_t ri_lifetime_max_neural_footprint;
             * uint64_t ri_interval_max_neural_footprint;
             * uint64_t ri_conclave_footprint;
             * uint64_t ri_page_wait_time_mach;
             * uint64_t ri_page_cache_hits;
             * uint64_t ri_reserved[6];
             */
            [[fallthrough]];
        }
        case RUSAGE_INFO_V5:
        {
            struct rusage_info_v5 *rv5 __attribute__((unused)) = (struct rusage_info_v5*)&rv6;
            /*
             * UNIMPLEMENTED
             *
             * uint64_t ri_flags;
             */
            [[fallthrough]];
        }
        case RUSAGE_INFO_V4:
        {
            struct rusage_info_v4 *rv4 __attribute__((unused)) = (struct rusage_info_v4*)&rv6;
            /*
             * UNIMPLEMENTED
             *
             * uint64_t ri_logical_writes;
             * uint64_t ri_lifetime_max_phys_footprint;
             * uint64_t ri_instructions;
             * uint64_t ri_cycles;
             * uint64_t ri_billed_energy;
             * uint64_t ri_serviced_energy;
             * uint64_t ri_interval_max_phys_footprint;
             * uint64_t ri_runnable_time;
             */
            [[fallthrough]];
        }
        case RUSAGE_INFO_V3:
        {
            struct rusage_info_v3 *rv3 __attribute__((unused)) = (struct rusage_info_v3*)&rv6;
            /*
             * UNIMPLEMENTED
             *
             * uint64_t ri_cpu_time_qos_default;
             * uint64_t ri_cpu_time_qos_maintenance;
             * uint64_t ri_cpu_time_qos_background;
             * uint64_t ri_cpu_time_qos_utility;
             * uint64_t ri_cpu_time_qos_legacy;
             * uint64_t ri_cpu_time_qos_user_initiated;
             * uint64_t ri_cpu_time_qos_user_interactive;
             * uint64_t ri_billed_system_time;
             * uint64_t ri_serviced_system_time;
             */
            [[fallthrough]];
        }
        case RUSAGE_INFO_V2:
        {
            struct rusage_info_v2 *rv2 __attribute__((unused)) = (struct rusage_info_v2*)&rv6;
            /*
             * UNIMPLEMENTED
             *
             * uint64_t ri_diskio_bytesread;        // not possible for now, only XNU knows
             * uint64_t ri_diskio_byteswritten;     // not possible for now, only XNU knows
             */
            [[fallthrough]];
        }
        case RUSAGE_INFO_V1:
        {
            struct rusage_info_v1 *rv1 __attribute__((unused)) = (struct rusage_info_v1*)&rv6;
            /*
             * UNIMPLEMENTED
             *
             * uint64_t ri_child_user_time;         // technicaly possible, recurse needed?
             * uint64_t ri_child_system_time;       // technicaly possible, recurse needed?
             * uint64_t ri_child_pkg_idle_wkups;    // technicaly possible, recurse needed?
             * uint64_t ri_child_interrupt_wkups;   // technicaly possible, recurse needed?
             * uint64_t ri_child_pageins;           // technicaly possible, recurse needed?
             * uint64_t ri_child_elapsed_abstime;   // technicaly possible, recurse needed?
             */
            [[fallthrough]];
        }
        case RUSAGE_INFO_V0:
        {
            struct rusage_info_v0 *rv0 = (struct rusage_info_v0*)&rv6;
            //rv0->ri_uuid = (unimplemented)
            {
                task_power_info_data_t pi;
                mach_msg_type_number_t count = TASK_POWER_INFO_COUNT;
                if(task_info(target_task, TASK_POWER_INFO, (task_info_t)&pi, &count) == KERN_SUCCESS)
                {
                    rv0->ri_user_time = pi.total_user;
                    rv0->ri_system_time = pi.total_system;
                    rv0->ri_interrupt_wkups = pi.task_interrupt_wakeups;
                    rv0->ri_pkg_idle_wkups = pi.task_platform_idle_wakeups;
                }
            }
            {
                task_events_info_data_t ev;
                mach_msg_type_number_t count = TASK_EVENTS_INFO_COUNT;
                if(task_info(target_task, TASK_EVENTS_INFO, (task_info_t)&ev, &count) == KERN_SUCCESS)
                {
                    rv0->ri_pageins = (uint64_t)(uint32_t)ev.pageins;
                }
            }
            //rv0->ri_wired_size = (unimplemented, cause only XNU can know this)
            {
                task_vm_info_data_t vmi;
                mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
                if(task_info(target_task, TASK_VM_INFO, (task_info_t)&vmi, &count) == KERN_SUCCESS)
                {
                    rv0->ri_resident_size = vmi.resident_size;
                    if(count >= TASK_VM_INFO_REV1_COUNT)
                    {
                        rv0->ri_phys_footprint = (uint64_t)vmi.phys_footprint;
                    }
                }
            }
            rv0->ri_proc_start_abstime = target->nyx.start_abstime;
            rv0->ri_proc_exit_abstime = target->nyx.exit_abstime;
            [[fallthrough]];
        }
        default:
            break;
    }
    mach_port_deallocate(mach_task_self(), target_task);
    kvo_unlock(target);
    kvo_release(target);
    
    static size_t russize[RUSAGE_INFO_V6 + 1] = {
        sizeof(struct rusage_info_v0),
        sizeof(struct rusage_info_v1),
        sizeof(struct rusage_info_v2),
        sizeof(struct rusage_info_v3),
        sizeof(struct rusage_info_v4),
        sizeof(struct rusage_info_v5),
        sizeof(struct rusage_info_v6),
    };
    
    if(!syscall_copy_out(sys_task_, russize[u_flavour], &rv6, u_buffer_ptr))
    {
        sys_return_failure_with_errno(EFAULT);
    }
    
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_pidoriginatorinfo)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_listcoalitions)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_canusefghw)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_piddynkqueueinfo)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info_udata_info)
{
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(proc_info)
{
    /* parse arguments */
    int32_t u_callnum = (int32_t)args[0];
    /*
     * pid_t u_pid = (pid_t)args[1];
     * uint32_t u_flavour = (uint32_t)args[2];
     * uint64_t u_arg = (uint64_t)args[3];
     * userspace_pointer_t u_buffer = (userspace_pointer_t)args[4];
     * int32_t u_buffersize = (int32_t)args[5];
     */
    
    switch(u_callnum)
    {
        case PROC_INFO_CALL_LISTPIDS:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_listpids);
        case PROC_INFO_CALL_PIDINFO:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_pidinfo);
        case PROC_INFO_CALL_PIDFDINFO:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_pidfdinfo);
        case PROC_INFO_CALL_KERNMSGBUF:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_kernmsgbuf);
        case PROC_INFO_CALL_SETCONTROL:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_setcontrol);
        case PROC_INFO_CALL_PIDFILEPORTINFO:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_pidfileportinfo);
        case PROC_INFO_CALL_TERMINATE:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_terminate);
        case PROC_INFO_CALL_DIRTYCONTROL:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_dirtycontrol);
        case PROC_INFO_CALL_PIDRUSAGE:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_pidrusage);
        case PROC_INFO_CALL_PIDORIGINATORINFO:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_pidoriginatorinfo);
        case PROC_INFO_CALL_LISTCOALITIONS:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_listcoalitions);
        case PROC_INFO_CALL_CANUSEFGHW:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_canusefghw);
        case PROC_INFO_CALL_PIDDYNKQUEUEINFO:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_piddynkqueueinfo);
        case PROC_INFO_CALL_UDATA_INFO:
            return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(proc_info_udata_info);
        default:
            break;
    }
    sys_return_failure_with_errno(ENOSYS);
}
