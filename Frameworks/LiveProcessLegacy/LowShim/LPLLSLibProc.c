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

#include <LiveProcessLegacy/LPLShim.h>
#include <Nyxian/LindChain/ProcEnvironment/Surface/libkern/bsd/proc_info.h>
#include <Broadpatch/Broadpatch.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <execinfo.h>
#include <string.h>

extern int __proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg, user_addr_t buffer, int32_t buffersize);

LIBKERN_PATCH(int, __proc_info, (int32_t callnum,
                                 int32_t pid,
                                 uint32_t flavor,
                                 uint64_t arg,
                                 user_addr_t buffer,
                                 int32_t buffersize),
{
    errno = 0;
    int ret = (int)liveshim_syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize);
    if(errno == ENOSYS)
    {
        errno = 0;  /* must be reset so it is no errno */
        ret = LIBKERN_ORIG(__proc_info)(callnum, pid, flavor, arg, buffer, buffersize);
    }
    return ret;
});

LIBKERN_PATCH(int, proc_pidinfo, (pid_t pid,
                                  int flavor,
                                  uint64_t arg,
                                  void * buffer,
                                  int buffersize),{
    return __proc_info(PROC_INFO_CALL_PIDINFO, pid, flavor, 0, (user_addr_t)buffer, buffersize);
});

LIBKERN_PATCH(int, proc_name, (pid_t pid,
                               void *buffer,
                               uint32_t buffersize),
{
    struct proc_bsdinfo pbsd;
    if(buffersize < sizeof(pbsd.pbi_name))
    {
        errno = ENOMEM;
        return 0;
    }
    
    int retval = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &pbsd, sizeof(pbsd));
    if(retval != 0)
    {
        if(pbsd.pbi_name[0])
        {
            bcopy(&pbsd.pbi_name, buffer, sizeof(pbsd.pbi_name));
        }
        else
        {
            bcopy(&pbsd.pbi_comm, buffer, sizeof(pbsd.pbi_comm));
        }
        return (int)strlen(buffer);
    }
    return 0;
});

LIBKERN_PATCH(int, proc_pidpath, (pid_t pid,
                                  void *buffer,
                                  uint32_t buffersize),
{
    /* sanity check */
    if(buffersize == 0 || buffer == NULL)
    {
        return 0;
    }
    
    /* syscall with SYS_PROCPATH */
    int retval = proc_pidinfo(pid, PROC_PIDPATHINFO, 0, buffer, buffersize);
    if(retval != 0)
    {
        return 0;
    }
    
    /* final return of lenght */
    return (int)strlen((char*)buffer);
});

LIBKERN_PATCH(int, proc_listallpids, (void *buffer,
                                      int buffersize),
{
    if(buffersize < 0)
    {
        errno = EINVAL;
        return -1;
    }
    
    if(buffersize < 0)
    {
        errno = EINVAL;
        return -1;
    }
    
    struct kinfo_proc kp[500];
    size_t len = sizeof(kp);
    
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    sysctl(mib, 3, &kp, &len, NULL, 0); /* goes through broadpatch */
    
    size_t count = (uint32_t)(len / sizeof(struct kinfo_proc));
    
    size_t n = 0;
    size_t needed_bytes = 0;
    
    needed_bytes = (size_t)count * sizeof(pid_t);
    
    if(buffer != NULL && buffersize > 0)
    {
        size_t capacity = (size_t)buffersize / sizeof(pid_t);
        n = count < capacity ? count : capacity;
        
        pid_t *pids = (pid_t *)buffer;
        
        for(size_t i = 0; i < n; i++)
        {
            pids[i] = kp[i].kp_proc.p_pid;
        }
    }
    
    if(buffer == NULL || buffersize == 0)
    {
        return (int)needed_bytes;
    }
    
    return (int)(n * sizeof(pid_t));
});

LIBKERN_PATCH(int, proc_pid_rusage, (int pid,
                                     int flavor,
                                     rusage_info_t *buffer),
{
    return __proc_info(PROC_INFO_CALL_PIDRUSAGE, pid, (uint32_t)flavor, (uint64_t)0, (user_addr_t)buffer, 0);
});

LIBKERN_PATCH(int, proc_kmsgbuf, (void *buffer,
                                  uint32_t buffersize),{
    return __proc_info(PROC_INFO_CALL_KERNMSGBUF, 0, 0, (uint64_t)0, (user_addr_t)buffer, buffersize);
});

static bool liveshim_signal_self_locally(int sig)
{
    if(sig <= 0 || sig >= NSIG || sig == SIGKILL || sig == SIGSTOP || sig == SIGCONT)
    {
        return false;
    }
    
    sigset_t blocked;
    if(pthread_sigmask(SIG_BLOCK, NULL, &blocked) != 0 || sigismember(&blocked, sig))
    {
        return false;
    }
    
    return pthread_kill(pthread_self(), sig) == 0;
}

LIBKERN_PATCH(int, kill, (pid_t pid,
                          int sig),
{
    if(pid == getpid() && liveshim_signal_self_locally(sig))
    {
        return 0;
    }
    return (int)liveshim_syscall(SYS_kill, pid, sig);
});

LIBKERN_PATCH(int, raise, (int sig),{
    if(liveshim_signal_self_locally(sig))
    {
        return 0;
    }
    return kill(getpid(), sig);
});

static void liveshim_abort_reporter(int sig)
{
    static const char header[] = "\n[LiveShim] SIGABRT, backtrace:\n";
    write(STDERR_FILENO, header, sizeof(header) - 1);
    void *frames[64];
    int count = backtrace(frames, 64);
    backtrace_symbols_fd(frames, count, STDERR_FILENO);
    raise(sig);
}

static void liveshim_install_abort_reporter(void)
{
    struct sigaction current;
    if(sigaction(SIGABRT, NULL, &current) != 0 || current.sa_handler != SIG_DFL)
    {
        return;
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = liveshim_abort_reporter;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, NULL);
}

__attribute__((constructor))
static void InstallPatches(void)
{
    liveshim_install_abort_reporter();
    
    LIBKERN_INSTALL_PATCH(__proc_info);
    LIBKERN_INSTALL_PATCH(proc_pidinfo);
    LIBKERN_INSTALL_PATCH(proc_name);
    LIBKERN_INSTALL_PATCH(proc_pidpath);
    LIBKERN_INSTALL_PATCH(proc_listallpids);
    LIBKERN_INSTALL_PATCH(proc_pid_rusage);
    LIBKERN_INSTALL_PATCH(proc_kmsgbuf);
    LIBKERN_INSTALL_PATCH(kill);
    LIBKERN_INSTALL_PATCH(raise);
}
