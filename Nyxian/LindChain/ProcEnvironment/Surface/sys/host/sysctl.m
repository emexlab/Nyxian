/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab
 Copyright (C) 2026 semvis123

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

#import <Foundation/Foundation.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <regex.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/sys/host/sysctl.h>
#import <LindChain/ProcEnvironment/Surface/proc/list.h>
#import <ksurface_config.h>

/* sysctl defs */
typedef struct {
    int name[6];
    u_int namelen;
    userspace_pointer_t oldp;
    userspace_pointer_t oldlenp;
    userspace_pointer_t newp;
    size_t newlen;
    errno_t err;
    task_t task;
    ksurface_proc_snapshot_t *proc_snapshot;
} sysctl_req_t;

typedef int (*sysctl_fn_t)(sysctl_req_t *req);

typedef struct {
    const int mib[20];
    size_t mib_len;
    sysctl_fn_t fn;
} sysctl_map_entry_t;

typedef struct {
    const char *name;
    const sysctl_map_entry_t *entry;
} sysctl_name_map_entry_t;

/* sysctl apis */

int sysctl_kernmaxproc(sysctl_req_t *req)
{
    size_t user_outlen = 0;
    size_t needed = sizeof(int);
    int maxproc = PROC_MAX;
    
    /* if user provided oldlenp, copy it in */
    if(req->oldlenp != NULL &&
       !syscall_copy_in(req->task, sizeof(size_t), &user_outlen, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    /* if oldp is set user wants the value */
    if(req->oldp)
    {
        /* sanitizing buffer lenght */
        if(user_outlen < needed)
        {
            req->err = ENOMEM;
            return -1;
        }
        
        if(!syscall_copy_out(req->task, sizeof(int), &maxproc, req->oldp))
        {
            req->err = EFAULT;
            return -1;
        }
    }
    
    /* always copy out size */
    if(req->oldlenp != NULL &&
       !syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    return 0;
}

int sysctl_kernproc(sysctl_req_t *req)
{
    /* prepare arguments */
    proc_flavour_t flavour;
    size_t user_outlen = 0;
    size_t needed = 0;
    
    /* finding out flavour */
    switch(req->name[2])
    {
        case KERN_PROC_ALL:
            flavour = PROC_FLV_ALL;
            break;
        case KERN_PROC_UID:
            flavour = PROC_FLV_UID;
            goto validate;
        case KERN_PROC_RUID:
            flavour = PROC_FLV_RUID;
            goto validate;
        case KERN_PROC_SESSION:
            flavour = PROC_FLV_SID;
            goto validate;
        case KERN_PROC_PGRP:
            flavour = PROC_FLV_PGID;
            goto validate;
        case KERN_PROC_PID:
            flavour = PROC_FLV_PID;
            
            /* some flavours require 4 */
        validate:
            if(!req->oldlenp || req->namelen != 4)
            {
                req->err = EINVAL;
                return -1;
            }
            
            break;
        default:
            req->err = EINVAL;
            return -1;
    }
    
    /* if user provided oldlenp, copy it in */
    if(req->oldlenp != NULL &&
       !syscall_copy_in(req->task, sizeof(size_t), &user_outlen, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    /* copying current process table */
    kinfo_proc_t *kpbuf = NULL;
    kern_return_t kr = proc_list(req->proc_snapshot, &kpbuf, &needed, flavour, req->name[3]);
    
    /* checking if succeeded  */
    if(kr != KERN_SUCCESS)
    {
        req->err = ENOMEM;
        goto out_free_kpbuf_and_ret_excp;
    }
    
    /* getting how many processes we currently have */
    if(needed == 0)
    {
        req->err = ENOMEM;
        goto out_free_kpbuf_and_ret_excp;
    }
    
    /* size only query */
    if(req->oldp == NULL)
    {
        if(!syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
        {
            req->err = EFAULT;
            goto out_free_kpbuf_and_ret_excp;
        }
        goto out_free_kpbuf;
    }
    
    /* copy request fails (buffer too small) */
    if(user_outlen < needed)
    {
        if(!syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
        {
            req->err = EFAULT;
            goto out_free_kpbuf_and_ret_excp;
        }
        req->err = ENOMEM;
        goto out_free_kpbuf_and_ret_excp;
    }
    else
    {
        if(!syscall_copy_out(req->task, needed, kpbuf, req->oldp))
        {
            req->err = EFAULT;
            goto out_free_kpbuf_and_ret_excp;
        }
    }
    
    /* copy out buffer lenght */
    if(!syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
    {
        req->err = EFAULT;
        goto out_free_kpbuf_and_ret_excp;
    }
    
out_free_kpbuf:
    free(kpbuf);
    return 0;
    
out_free_kpbuf_and_ret_excp:
    free(kpbuf);
    return -1;
}

bool is_valid_hostname_regex(const char *hostname)
{
    /* checking string lenght */
    if(strnlen(hostname, MAXHOSTNAMELEN) >= MAXHOSTNAMELEN)
    {
        return false;
    }
    
    /* compiling regex pattern once */
    static regex_t *regex;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        /* allocating this, dont make me regret this */
        regex = malloc(sizeof(regex_t));
        
        /* null terminator check */
        if(regex == NULL)
        {
            return;
        }
        
        /* compiling regex pattern */
        if(regcomp(regex, "^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", REG_EXTENDED) != 0)
        {
            /* if it fails then freeing regex and setting it to null */
            free(regex);
            regex = NULL;
        }
    });
    
    /* null pointer checking */
    if(regex == NULL)
    {
        return false;
    }
    
    /* the pattern must be valid */
    return (regexec(regex, hostname, 0, NULL, 0) == 0);
}

int sysctl_kernhostname(sysctl_req_t *req)
{
    if(req->oldp && req->oldlenp)
    {
        host_rdlock();
        size_t hlen = strlen(ksurface->host_info.hostname) + 1;
        
        size_t oldlenp = 0;
        if(!syscall_copy_in(req->task, sizeof(size_t), &oldlenp, req->oldlenp))
        {
            host_unlock();
            req->err = EFAULT;
            return -1;
        }
        
        if(oldlenp < hlen)
        {
            host_unlock();
            req->err = ENOMEM;
            return -1;
        }
        
        if(!syscall_copy_out(req->task, hlen, ksurface->host_info.hostname, req->oldp) ||
           !syscall_copy_out(req->task, sizeof(size_t), &hlen, req->oldlenp))
        {
            host_unlock();
            req->err = EFAULT;
            return -1;
        }
        host_unlock();
    }
    
    if(req->newp && req->newlen)
    {
        if(!entitlement_got_entitlement(proc_getentitlements(req->proc_snapshot), kPEEntitlementFlagHostManager))
        {
            req->err = EPERM;
            return -1;
        }
        
        if(req->newlen >= MAXHOSTNAMELEN)
        {
            req->err = EINVAL;
            return -1;
        }
        
        /* copy buffer in */
        char *newname = syscall_copy_str_in(req->task, req->newp, req->newlen);
        if(!newname)
        {
            req->err = EFAULT;
            return -1;
        }
        
        /* checking regex */
        if(!is_valid_hostname_regex(newname))
        {
            req->err = EINVAL;
            free(newname);
            return -1;
        }
        
        host_wrlock();
        strlcpy(ksurface->host_info.hostname, newname, sizeof(ksurface->host_info.hostname));
        [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithCString:ksurface->host_info.hostname encoding:NSUTF8StringEncoding] forKey:@"LDEHostname"];
        host_unlock();
        
        free(newname);
    }
    
    return 0;
}

int sysctl_kernprocargs2(sysctl_req_t *req)
{
    if(req->namelen < 3)
    {
        req->err = EINVAL;
        return -1;
    }
    
    pid_t pid = (pid_t)req->name[2];
#if KSURFACE_EMIT_KERNEL_TASK
    if(pid == 0)
    {
        req->err = EINVAL;
        return -1;
    }
#endif /* KSURFACE_EMIT_KERNEL_TASK */
    
    size_t user_outlen = 0;
    if(req->oldlenp != NULL && !syscall_copy_in(req->task, sizeof(size_t), &user_outlen, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    kinfo_proc_t *kpbuf = NULL;
    size_t needed = 0;
    kern_return_t kr = proc_list(req->proc_snapshot, &kpbuf, &needed, PROC_FLV_PID, pid); /* TODO: efficency using proc lookup api on PROC_FLV_PID, as its one pid and radix lookup gives you proc structure for one pid */
    if(kr != KERN_SUCCESS || needed == 0 || kpbuf == NULL)
    {
        req->err = ESRCH;
        free(kpbuf);
        return -1;
    }
    
    /*
     * for now we do it with p_comm, i don't think
     * I HAVE TO REPEAT THAT PCOMM IS NOT LAST
     * PATH COMPONENT FIXME: (frida fix this)
     */
    char comm[MAXCOMLEN + 1];
    strlcpy(comm, kpbuf[0].kp_proc.p_comm, sizeof(comm));
    free(kpbuf);
    
    /* building minimal fake proc arg buffer */
    int argc = 1;
    size_t comm_len = strlen(comm) + 1;
    size_t bufsize  = sizeof(int) + comm_len + comm_len;
    
    uint8_t *buf = calloc(1, bufsize);
    if(buf == NULL)
    {
        req->err = ENOMEM;
        return -1;
    }
    
    uint8_t *p = buf;
    memcpy(p, &argc, sizeof(int));
    p += sizeof(int);
    memcpy(p, comm, comm_len);
    p += comm_len;
    memcpy(p, comm, comm_len);
    
    /* size-only query */
    if(req->oldp == NULL)
    {
        if(req->oldlenp != NULL && !syscall_copy_out(req->task, sizeof(size_t), &bufsize, req->oldlenp))
        {
            req->err = EFAULT;
            free(buf);
            return -1;
        }
        free(buf);
        return 0;
    }
    
    if(user_outlen < bufsize)
    {
        if(req->oldlenp != NULL)
        {
            syscall_copy_out(req->task, sizeof(size_t), &bufsize, req->oldlenp);
        }
        req->err = ENOMEM;
        free(buf);
        return -1;
    }
    
    if(!syscall_copy_out(req->task, bufsize, buf, req->oldp))
    {
        req->err = EFAULT;
        free(buf);
        return -1;
    }
    
    if(req->oldlenp != NULL && !syscall_copy_out(req->task, sizeof(size_t), &bufsize, req->oldlenp))
    {
        req->err = EFAULT;
        free(buf);
        return -1;
    }
    
    free(buf);
    return 0;
}

int sysctl_kernargmax(sysctl_req_t *req)
{
    size_t user_outlen = 0;
    size_t needed = sizeof(int);
    int argmax = ARG_MAX;
    
    if(req->oldlenp != NULL && !syscall_copy_in(req->task, sizeof(size_t), &user_outlen, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    if(req->oldp)
    {
        if(user_outlen < needed)
        {
            req->err = ENOMEM;
            return -1;
        }
        
        if(!syscall_copy_out(req->task, sizeof(int), &argmax, req->oldp))
        {
            req->err = EFAULT;
            return -1;
        }
    }
    
    if(req->oldlenp != NULL && !syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    return 0;
}

int sysctl_kernboottime(sysctl_req_t *req)
{
    size_t user_outlen = 0;
    size_t needed = sizeof(struct timeval);
    struct timeval kval = {
        .tv_sec = g_process_start_time_sysctl.tv_sec,
        .tv_usec = (__darwin_suseconds_t)(g_process_start_time_sysctl.tv_nsec / 1000),
    };
    
    if(req->oldlenp != NULL && !syscall_copy_in(req->task, sizeof(size_t), &user_outlen, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    if(req->oldp)
    {
        if(user_outlen < needed)
        {
            req->err = ENOMEM;
            return -1;
        }
        
        if(!syscall_copy_out(req->task, sizeof(struct timeval), &kval, req->oldp))
        {
            req->err = EFAULT;
            return -1;
        }
    }
    
    if(req->oldlenp != NULL && !syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    return 0;
}

extern int kfd;
int sysctl_kernmsgbuf(sysctl_req_t *req)
{
    size_t needed = sizeof(int);
    size_t user_outlen = 0;
    if(req->newp != NULL || req->newlen != 0)
    {
        req->err = EPERM;
        return -1;
    }
    
    struct stat st;
    if(fstat(kfd, &st) != 0)
    {
        req->err = errno;
        return -1;
    }
    
    if(st.st_size > INT_MAX)
    {
        req->err = EOVERFLOW;
        return -1;
    }
    
    int msgbufsize = (int)st.st_size;
    
    if(req->oldlenp != NULL)
    {
        if(!syscall_copy_in(req->task, sizeof(size_t), &user_outlen, req->oldlenp))
        {
            req->err = EFAULT;
            return -1;
        }
    }
    
    if(req->oldp != NULL)
    {
        if(req->oldlenp == NULL)
        {
            req->err = EFAULT;
            return -1;
        }
        
        if(user_outlen < needed)
        {
            syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp);
            req->err = ENOMEM;
            return -1;
        }
        
        if(!syscall_copy_out(req->task, sizeof(msgbufsize), &msgbufsize, req->oldp))
        {
            req->err = EFAULT;
            return -1;
        }
    }
    
    if(req->oldlenp != NULL && !syscall_copy_out(req->task, sizeof(size_t), &needed, req->oldlenp))
    {
        req->err = EFAULT;
        return -1;
    }
    
    return 0;
}

/* sysctl map entries */
static const sysctl_map_entry_t sysctl_map[] = {
    { { CTL_KERN, KERN_HOSTNAME                 }, 2, sysctl_kernhostname },
    { { CTL_KERN, KERN_BOOTTIME                 }, 2, sysctl_kernboottime },
    { { CTL_KERN, 9999                          }, 2, sysctl_kernmsgbuf },      /* got no solid identifier in XNU's BSD */
    { { CTL_KERN, KERN_MAXPROC                  }, 2, sysctl_kernmaxproc },
    { { CTL_KERN, KERN_PROC, KERN_PROC_ALL      }, 3, sysctl_kernproc },
    { { CTL_KERN, KERN_ARGMAX                   }, 2, sysctl_kernargmax },
    { { CTL_KERN, KERN_PROC, KERN_PROC_SESSION  }, 3, sysctl_kernproc },
    { { CTL_KERN, KERN_PROC, KERN_PROC_PID      }, 3, sysctl_kernproc },
    { { CTL_KERN, KERN_PROC, KERN_PROC_UID      }, 3, sysctl_kernproc },
    { { CTL_KERN, KERN_PROC, KERN_PROC_RUID     }, 3, sysctl_kernproc },
    { { CTL_KERN, KERN_PROCARGS2                }, 2, sysctl_kernprocargs2 }
};

static const sysctl_name_map_entry_t sysctl_name_map[] = {
    { "kern.hostname",          &sysctl_map[0] },
    { "kern.boottime",          &sysctl_map[1] },
    { "kern.msgbuf",            &sysctl_map[2] },
    { "kern.maxproc",           &sysctl_map[3] },
    { "kern.proc.all",          &sysctl_map[4] },
    { "kern.argmax",            &sysctl_map[5] },
};

/* lookup symbol */
static sysctl_fn_t sysctl_lookup(sysctl_req_t *req)
{
    for (size_t i = 0; i < sizeof(sysctl_map)/sizeof(sysctl_map[0]); i++)
    {
        const sysctl_map_entry_t *e = &sysctl_map[i];
        
        if (req->namelen < e->mib_len)
        {
            continue;
        }
        
        bool match = true;
        for(size_t j = 0; j < e->mib_len; j++)
        {
            if(req->name[j] != e->mib[j])
            {
                match = false;
                break;
            }
        }
        
        if(match)
        {
            return e->fn;
        }
    }
    
    return NULL;
}

DEFINE_SYSCALL_HANDLER(sysctl)
{
    /* prepare request */
    sysctl_req_t req = {
        .name           = {},
        .namelen        = (u_int)args[1],
        .oldp           = (userspace_pointer_t)args[2],
        .oldlenp        = (userspace_pointer_t)args[3],
        .newp           = (userspace_pointer_t)args[4],
        .newlen         = (size_t)args[5],
        .err            = 0,
        .task           = sys_task_,
        .proc_snapshot  = sys_proc_snapshot_,
    };
    
    size_t count = req.namelen;
    if(count > 6)
    {
        sys_return_failure_with_errno(ENOSYS);
    }
    
    /* copy name array from userspace */
    if(!syscall_copy_in(sys_task_, count * sizeof(int), &(req.name), (userspace_pointer_t)args[0]))
    {
        sys_return_failure_with_errno(EFAULT);
    }
    
    /* looking up sysctl map */
    sysctl_fn_t fn = sysctl_lookup(&req);
    if(fn != NULL)
    {
        int ret = fn(&req);
        errno = req.err;
        return ret;
    }
    
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(sysctlbyname)
{    
    char *name_buf = syscall_copy_str_in(sys_task_, (userspace_pointer_t)args[0], 128);
    
    if(name_buf == NULL)
    {
        sys_return_failure_with_errno(EINVAL);
    }
    
    const sysctl_name_map_entry_t *found = NULL;
    for(size_t i = 0; i < sizeof(sysctl_name_map)/sizeof(sysctl_name_map[0]); i++)
    {
        if(strcmp(name_buf, sysctl_name_map[i].name) == 0)
        {
            found = &sysctl_name_map[i];
            break;
        }
    }
    
    free(name_buf);
    
    if(found == NULL)
    {
        sys_return_failure_with_errno(ENOSYS);
    }
    
    sysctl_req_t req = {
        .name           = {},
        .namelen        = (u_int)found->entry->mib_len,
        .oldp           = (userspace_pointer_t)args[1],
        .oldlenp        = (userspace_pointer_t)args[2],
        .newp           = (userspace_pointer_t)args[3],
        .newlen         = (size_t)args[4],
        .err            = 0,
        .task           = sys_task_,
        .proc_snapshot  = sys_proc_snapshot_,
    };
    
    memcpy(req.name, found->entry->mib, found->entry->mib_len * sizeof(int));
    
    int ret = found->entry->fn(&req);
    errno = req.err;
    return ret;
}
