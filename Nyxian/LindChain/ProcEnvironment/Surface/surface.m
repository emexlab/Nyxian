/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

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

#import <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/Surface/surface.h>
#import <LindChain/ProcEnvironment/Surface/proc/proc.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/sys/syscall.h>
#import <LindChain/ProcEnvironment/LiveContainer/utils.h>
#import <LindChain/ProcEnvironment/Surface/sys/host/sysctl.h>
#import <LindChain/ProcEnvironment/Surface/fs/fs.h>
#import <LindChain/ProcEnvironment/Surface/trust/keychain.h>
#import <ksurface_config.h>
#import <ksurface_abi.h>

syscall_list_item_t sys_list[] = {
    /* necessary for basic function */
    { .name = "SYS_handoffep",      .sysnum = SYS_handoffep,    .hndl = GET_SYSCALL_HANDLER(handoffep)      },
    { .name = "SYS_pectl",          .sysnum = SYS_pectl,        .hndl = GET_SYSCALL_HANDLER(pectl)          },
    { .name = "sys_getppid",        .sysnum = SYS_getppid,      .hndl = GET_SYSCALL_HANDLER(getppid)        },
    { .name = "SYS_openpty",        .sysnum = SYS_openpty,      .hndl = GET_SYSCALL_HANDLER(openpty)        },
    { .name = "SYS_vroot",          .sysnum = SYS_vroot,        .hndl = GET_SYSCALL_HANDLER(vroot)          },
    
#if KSURFACE_SYS_IOCTL_ENABLED
    { .name = "SYS_ioctl",          .sysnum = SYS_ioctl,        .hndl = GET_SYSCALL_HANDLER(ioctl)          },
#endif /* KSURFACE_SYS_IOCTL_ENABLED */
    
#if KSURFACE_SYS_SYSCTL_ENABLED
    { .name = "SYS_sysctl",         .sysnum = SYS_sysctl,       .hndl = GET_SYSCALL_HANDLER(sysctl)         },
    { .name = "SYS_sysctlbyname",   .sysnum = SYS_sysctlbyname, .hndl = GET_SYSCALL_HANDLER(sysctlbyname)   },
#endif /* KSURFACE_SYS_SYSCTL_ENABLED */
    
#if KSURFACE_SYS_TASK_ENABLED
    { .name = "SYS_task_for_pid",   .sysnum = SYS_task_for_pid, .hndl = GET_SYSCALL_HANDLER(task_for_pid)   },
#endif /* KSURFACE_SYS_UCRED_ENABLED */
    
#if KSURFACE_SYS_UCRED_ENABLED
    { .name = "SYS_setuid",         .sysnum = SYS_setuid,       .hndl = GET_SYSCALL_HANDLER(setuid)         },
    { .name = "SYS_seteuid",        .sysnum = SYS_seteuid,      .hndl = GET_SYSCALL_HANDLER(seteuid)        },
    { .name = "SYS_setgid",         .sysnum = SYS_setgid,       .hndl = GET_SYSCALL_HANDLER(setgid)         },
    { .name = "SYS_setegid",        .sysnum = SYS_setegid,      .hndl = GET_SYSCALL_HANDLER(setegid)        },
    { .name = "SYS_setreuid",       .sysnum = SYS_setreuid,     .hndl = GET_SYSCALL_HANDLER(setreuid)       },
    { .name = "SYS_setregid",       .sysnum = SYS_setregid,     .hndl = GET_SYSCALL_HANDLER(setregid)       },
    { .name = "SYS_getuid",         .sysnum = SYS_getuid,       .hndl = GET_SYSCALL_HANDLER(getuid)         },
    { .name = "SYS_geteuid",        .sysnum = SYS_geteuid,      .hndl = GET_SYSCALL_HANDLER(geteuid)        },
    { .name = "SYS_getgid",         .sysnum = SYS_getgid,       .hndl = GET_SYSCALL_HANDLER(getgid)         },
    { .name = "SYS_getegid",        .sysnum = SYS_getegid,      .hndl = GET_SYSCALL_HANDLER(getegid)        },
    { .name = "SYS_getpgrp",        .sysnum = SYS_getpgrp,      .hndl = GET_SYSCALL_HANDLER(getpgrp)        },
    { .name = "SYS_setpgid",        .sysnum = SYS_setpgid,      .hndl = GET_SYSCALL_HANDLER(setpgid)        },
    { .name = "SYS_getsid",         .sysnum = SYS_getsid,       .hndl = GET_SYSCALL_HANDLER(getsid)         },
    { .name = "SYS_setsid",         .sysnum = SYS_setsid,       .hndl = GET_SYSCALL_HANDLER(setsid)         },
    { .name = "SYS_getpgid",        .sysnum = SYS_getpgid,      .hndl = GET_SYSCALL_HANDLER(getpgid)        },
    { .name = "SYS_loginctl",       .sysnum = SYS_loginctl,     .hndl = GET_SYSCALL_HANDLER(loginctl)       },
    { .name = "SYS_groupctl",       .sysnum = SYS_groupctl,     .hndl = GET_SYSCALL_HANDLER(groupctl)       },
#endif /* KSURFACE_SYS_UCRED_ENABLED */
    
#if KSURFACE_SYS_PROC_ENABLED
    { .name = "SYS_kill",           .sysnum = SYS_kill,         .hndl = GET_SYSCALL_HANDLER(kill)           },
    { .name = "SYS_wait4",          .sysnum = SYS_wait4,        .hndl = GET_SYSCALL_HANDLER(wait4)          },
    { .name = "SYS_waittask",       .sysnum = SYS_waittask,     .hndl = GET_SYSCALL_HANDLER(waittask)       },
    { .name = "SYS_sign",           .sysnum = SYS_sign,         .hndl = GET_SYSCALL_HANDLER(sign)           },
    { .name = "SYS_proc_info",      .sysnum = SYS_proc_info,    .hndl = GET_SYSCALL_HANDLER(proc_info)      },
#endif /* KSURFACE_SYS_PROC_ENABLED */
};

ksurface_mapping_t *ksurface = NULL;

int ksurface_sethostname(NSString *hostname)
{
    if(hostname == nil)
    {
        return -1;
    }
    
    /*
     * validates hostname in lenght
     * and formatting making sure it
     * meets networking standards.
     */
    if(!is_valid_hostname_regex([hostname UTF8String]))
    {
        return -1;
    }
    
    host_wrlock();
    klog_log("surface", "setting hostname to \"%s\"", [hostname UTF8String]);
    strlcpy(ksurface->host_info.hostname, [hostname UTF8String], MAXHOSTNAMELEN);
    [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithCString:ksurface->host_info.hostname encoding:NSUTF8StringEncoding] forKey:@"LDEHostname"];
    host_unlock();
    
    return 0;
}

void ksurface_kinit_get_keys(void)
{
    if(ksurface->pub_key != NULL)
    {
        free(ksurface->pub_key);
    }
    
    /*
     * this is the install time generated CS blob
     * key used to sign executables with nyxians
     * own virtualised entitlements, which are only
     * valid within the environment.
     */
    if(!get_static_kernel_key(NULL, NULL, &(ksurface->pub_key), &(ksurface->pub_key_len)))
    {
        /* shall never happen */
        kpanic("failed to get code signature key pair");
    }
    klog_log("ksurface:kinit:kalloc", "got code signature key pair");
}

static inline void ksurface_kinit_kalloc(void)
{
    assert(ksurface == NULL);
    
    ksurface = malloc(sizeof(ksurface_mapping_t));
    if(ksurface == NULL)
    {
        /* shall never happen */
        kpanic("allocating ksurface failed got NULL pointer from malloc");
    }
    klog_log("ksurface:kinit:kalloc", "allocated ksurface @ %p", ksurface);
    
    /* prepare key fields that are not nullified */
    ksurface->pub_key = NULL;
    
    /* get code signature key pair */
    ksurface_kinit_get_keys();
    
    /*
     * do you have to make a comment on this one -.-
     * isint it obvious~~
     * well this is for the softies which can only take
     * one at a time.
     */
    klog_log("ksurface:kinit:kalloc", "initializing global locks");
    pthread_rwlock_t *wls[] = { &(ksurface->proc_info.struct_lock),  &(ksurface->host_info.struct_lock), &(ksurface->tty_info.struct_lock), &(ksurface->kext_info.struct_lock) };
    for(unsigned char i = 0; i < sizeof(wls) / sizeof(pthread_rwlock_t*); i++)
    {
        klog_log("ksurface:kinit:kalloc", "initializing global lock @ %p", wls[i]);
        if(pthread_rwlock_init(wls[i], NULL) != 0)
        {
            kpanic("failed to initialize global lock @ %p", wls[i]);
        }
    }
    
    /*
     * setting up process radix trees, a radix tree
     * is a very efficient data struc..., bruh
     * just use google.. im not your CS teacher.
     */
    klog_log("ksurface:kinit:kalloc", "initializing radix trees");
    ksurface->proc_info.tree.root = NULL;
    ksurface->proc_info.proc_count = 0;
    ksurface->tty_info.tty.root = NULL;
    ksurface->kext_info.kexts.root = NULL;
}

static inline void ksurface_kinit_kinfo(void)
{
    /* restoring hostname */
    NSString *hostname = [[NSUserDefaults standardUserDefaults] stringForKey:@"LDEHostname"] ?: @"localhost";
    klog_log("ksurface:kinit:kinfo", "setting up hostname with \"%s\"", [hostname UTF8String]);
    strlcpy(ksurface->host_info.hostname, hostname.UTF8String, MAXHOSTNAMELEN);
}

static inline void ksurface_kinit_kserver(void)
{
    /*
     * allocating syscall server, which is used
     * to process syscalls for our "userspace"
     * for example if the guest wants to have a
     * list of all proceses it needs to invoke
     * SYS_sysctl, on normal iOS this gets blocked
     * because of sandbox, here in this case
     * we handle the syscall and write into the
     * userspace passed buffer pointer a buffer
     * with kinfo_proc data structures.
     */
    ksurface->sys_server = syscall_server_create();
    if(ksurface->sys_server == NULL)
    {
        /* shall never happen */
        kpanic("got NULL syscall server");
    }
    klog_log("ksurface:kinit:kserver", "allocated syscall server @ %p", ksurface->sys_server);
    
    /*
     * registers all virtualized syscalls with
     * their appropriate handlers.
     */
    for(uint32_t sys_i = 0; sys_i < sizeof(sys_list) / sizeof(sys_list[0]); sys_i++)
    {
        syscall_list_item_t *item = &(sys_list[sys_i]);
        assert(item);
        syscall_server_register(ksurface->sys_server, item->sysnum, item->hndl);
        klog_log("ksurface:kinit:kserver", "registered syscall %d (%s)", item->sysnum, item->name);
    }
    
    /* kickstarting server~~ */
    syscall_server_start(ksurface->sys_server);
    klog_log("ksurface:kinit:kserver", "started syscall server");
}

static inline void ksurface_kinit_kproc(void)
{
    /*
     * creating brand new kernel process
     * which is there so proc_fork works
     * which needs a parent process data
     * object passed and we also do it
     * so processes can know that Nyxian
     * exists and can aquire for example
     * a task name right to Nyxian.
     */
    ksurface_proc_t *kproc = kvo_alloc_fastpath(proc);
    if(kproc == NULL)
    {
        /* shall never happen */
        kpanic("got NULL kernel process");
    }
    klog_log("ksurface:kinit:kproc", "allocated kernel process @ %p", kproc);
    
    kproc->nyx.identity = trust_identity_get_kernel();
    if(kproc->nyx.identity == NULL)
    {
        /* shall never happen */
        kpanic("got NULL kernel trust identity");
    }
    
    kern_return_t kr;
#if KSURFACE_EMIT_KERNEL_TASK
    /* setting up properties */
    proc_setpid(kproc, 0);
    proc_setppid(kproc, 0);
    proc_setsid(kproc, 0);
    proc_setpgid(kproc, 0);
    strlcpy(kproc->bsd.kp_proc.p_comm, "kernel_task", MAXCOMLEN);
#else
    /* setting up properties */
    proc_setpid(kproc, getpid());
    proc_setppid(kproc, getppid());
    proc_setsid(kproc, getsid(getpid()));
    proc_setpgid(kproc, getpgrp());
    const char *name = strrchr(kproc->nyx.identity->path, '/');
    name = name ? name + 1 : kproc->nyx.identity->path;
    strlcpy(kproc->bsd.kp_proc.p_comm, name, MAXCOMLEN);
    
    /* kernel shall only expose its task name */
    task_t task;
    kr = task_get_special_port(mach_task_self(), TASK_NAME_PORT, &task);
    if(kr != KERN_SUCCESS)
    {
        /* shall never happen */
        kpanic("failed to aquire task name of kernel it self");
    }
    kproc->task = task;
#endif /* KSURFACE_EMIT_KERNEL_TASK */
    
    kproc->bsd.kp_proc.p_flag = P_SYSTEM | P_LP64;
    
    /* storing kernel proc */
    klog_log("ksurface:kinit:kproc", "inserting kernel process");
    kr = proc_insert(kproc);
    if(kr != KERN_SUCCESS)
    {
        /* shall never happen */
        kpanic("failed to insert kernel process");
    }
    
    ksurface->proc_info.kern_proc = kproc;
    
    /* releaing our reference to kernel proc, because we return now and kproc is now held by the radix tree */
    kvo_release(kproc);
}

void ksurface_kinit(void)
{
    /* starting huh :3 (shall only run once) */
    klog_log("ksurface:kinit", "I love XNU >~<");
    klog_log("ksurface:kinit", "");
    klog_log("ksurface:kinit", "   |\\__/,|   (`\\");
    klog_log("ksurface:kinit", " _.|o o  |_   ) )");
    klog_log("ksurface:kinit", "-(((---(((--------");
    klog_log("ksurface:kinit", "");
    
    /*
     * allocates the surface where everything nyxian kernel
     * related exists, structures that are made to store
     * sensitive information.
     */
    ksurface_kinit_kalloc();
    ksurface_kinit_kinfo();
    ksurface_kinit_kserver();
    ksurface_kinit_kproc();
    
    /* initialize other subsytems */
    if(ksurface_fs_init() != KERN_SUCCESS)
    {
        kpanic("fs didn't initialize");
    }
    
    if(ksurface_keychain_update() != KERN_SUCCESS)
    {
        kpanic("keychain didn't initialize");
    }
    
    /* put log devices where they actually belong to */
    NSString *kfd_path = [NSString stringWithFormat:@"%@/Documents/mntfs/devfs/kmsg", NSHomeDirectory()];
    NSString *kfd_path_old = [NSString stringWithFormat:@"%@/Documents/mntfs/devfs/kmsg_old", NSHomeDirectory()];
    NSString *entry_path = [NSString stringWithFormat:@"%@/Documents/kmsg.txt", NSHomeDirectory()];
    NSString *entry_old_path = [NSString stringWithFormat:@"%@/Documents/kmsg_old.txt", NSHomeDirectory()];
    
    /* now mapping klog to its dev device position */
    unlink([kfd_path UTF8String]);
    unlink([kfd_path_old UTF8String]);
    rename([entry_path UTF8String], [kfd_path UTF8String]);
    rename([entry_old_path UTF8String], [kfd_path_old UTF8String]);
}
