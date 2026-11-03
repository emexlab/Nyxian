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
#include <Broadpatch/Broadpatch.h>
#include <ksurface_abi.h>
#include <sys/param.h>
#include <grp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>

#ifndef PE_SUPPLEMENTARY_GROUPS_MAX
#define PE_SUPPLEMENTARY_GROUPS_MAX 32
#endif

static pthread_mutex_t g_login_name_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_login_name[MAXLOGNAME];

static int nyxian_login_name_fetch(char *dst,
                                   size_t dstlen)
{
    if(dst == NULL || dstlen == 0)
    {
        return EINVAL;
    }
    
    int64_t len64 = liveshim_syscall(SYS_loginctl, kPELoginCTLGetLength);
    if(len64 < 0)
    {
        return errno ? errno : EIO;
    }
    
    size_t len = (size_t)len64;
    if(len == 0)
    {
        const char *fallback = getenv("LOGNAME");
        if(fallback == NULL || fallback[0] == '\0')
        {
            fallback = getenv("USER");
        }
        if(fallback == NULL || fallback[0] == '\0')
        {
            return ENOENT;
        }
        if(strlcpy(dst, fallback, dstlen) >= dstlen)
        {
            return ERANGE;
        }
        return 0;
    }
    
    if(len + 1 > dstlen)
    {
        return ERANGE;
    }
    
    memset(dst, 0, dstlen);
    size_t words = (len + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    for(size_t i = 0; i < words; i++)
    {
        int64_t ret = liveshim_syscall(SYS_loginctl, kPELoginCTLGetWord, i);
        if(ret < 0)
        {
            return errno ? errno : EIO;
        }
        uint64_t word = (uint64_t)ret;
        size_t offset = i * sizeof(word);
        size_t count = len - offset;
        if(count > sizeof(word))
        {
            count = sizeof(word);
        }
        memcpy(dst + offset, &word, count);
    }
    dst[len] = '\0';
    return 0;
}

LIBKERN_PATCH(int, setlogin, (const char *name),
{
    if(name == NULL)
    {
        errno = EFAULT;
        return -1;
    }
    size_t len = strnlen(name, MAXLOGNAME);
    if(len >= MAXLOGNAME)
    {
        errno = EINVAL;
        return -1;
    }
    
    size_t words = (len + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    for(size_t i = 0; i < words; i++)
    {
        uint64_t word = 0;
        size_t offset = i * sizeof(word);
        size_t count = len - offset;
        if(count > sizeof(word))
        {
            count = sizeof(word);
        }
        memcpy(&word, name + offset, count);
        if(liveshim_syscall(SYS_loginctl, kPELoginCTLSetWord, i, word, 0, 0, 0) < 0)
        {
            return -1;
        }
    }
    
    if(liveshim_syscall(SYS_loginctl, kPELoginCTLCommit, len, 0, 0, 0, 0) < 0)
    {
        return -1;
    }
    
    pthread_mutex_lock(&g_login_name_lock);
    strlcpy(g_login_name, name, sizeof(g_login_name));
    pthread_mutex_unlock(&g_login_name_lock);
    return 0;
});

LIBKERN_PATCH(char *, getlogin, (void),
{
    pthread_mutex_lock(&g_login_name_lock);
    int rc = nyxian_login_name_fetch(g_login_name, sizeof(g_login_name));
    pthread_mutex_unlock(&g_login_name_lock);
    if(rc != 0)
    {
        errno = rc;
        return NULL;
    }
    return g_login_name;
});

LIBKERN_PATCH(int, getlogin_r, (char *name,
                                size_t namelen),
{
    if(name == NULL || namelen == 0)
    {
        return EINVAL;
    }
    pthread_mutex_lock(&g_login_name_lock);
    int rc = nyxian_login_name_fetch(name, namelen);
    pthread_mutex_unlock(&g_login_name_lock);
    return rc;
});

LIBKERN_PATCH(int, getgroups, (int gidsetsize,
                               gid_t grouplist[]),
{
    if(gidsetsize < 0)
    {
        errno = EINVAL;
        return -1;
    }
    int64_t count64 = liveshim_syscall(SYS_groupctl, kPEGroupCTLGetCount);
    if(count64 < 0)
    {
        return -1;
    }
    int count = (int)count64;
    if(gidsetsize == 0)
    {
        return count;
    }
    if(grouplist == NULL || gidsetsize < count)
    {
        errno = EINVAL;
        return -1;
    }
    
    for(int i = 0; i < count; i++)
    {
        int64_t gid = liveshim_syscall(SYS_groupctl, kPEGroupCTLGetAt, i);
        if(gid < 0)
        {
            return -1;
        }
        grouplist[i] = (gid_t)gid;
    }
    return count;
});

LIBKERN_PATCH(int, setgroups, (int ngroups,
                               const gid_t *grouplist),
{
    if(ngroups < 0 || ngroups > PE_SUPPLEMENTARY_GROUPS_MAX || (ngroups > 0 && grouplist == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    for(int i = 0; i < ngroups; i++)
    {
        if(liveshim_syscall(SYS_groupctl, kPEGroupCTLSetAt, i, grouplist[i]) < 0)
        {
            return -1;
        }
    }
    if(liveshim_syscall(SYS_groupctl, kPEGroupCTLCommit, ngroups) < 0)
    {
        return -1;
    }
    return 0;
});

LIBKERN_PATCH(int, initgroups, (const char *username,
                                int basegid),
{
    if(username == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    int groups[PE_SUPPLEMENTARY_GROUPS_MAX];
    int count = PE_SUPPLEMENTARY_GROUPS_MAX;
    if(getgrouplist(username, basegid, groups, &count) < 0)
    {
        groups[0] = basegid;
        count = 1;
    }
    gid_t gids[PE_SUPPLEMENTARY_GROUPS_MAX];
    for(int i = 0; i < count; i++)
    {
        gids[i] = (gid_t)groups[i];
    }
    return setgroups(count, gids);
});

LIBKERN_PATCH(uid_t, getuid, (void),
{
    return (uid_t)liveshim_syscall(SYS_getuid);
});

LIBKERN_PATCH(gid_t, getgid, (void),
{
    return (gid_t)liveshim_syscall(SYS_getgid);
});

LIBKERN_PATCH(uid_t, geteuid, (void),
{
    return (uid_t)liveshim_syscall(SYS_geteuid);
});

LIBKERN_PATCH(gid_t, getegid, (void),
{
    return (gid_t)liveshim_syscall(SYS_getegid);
});

LIBKERN_PATCH(int, chown, (const char *path,
                           uid_t owner,
                           gid_t group),
{
    return LIBKERN_ORIG(chown)(path, 501, 501);
});

LIBKERN_PATCH(int, lchown, (const char *path,
                            uid_t owner,
                            gid_t group),
{
    return LIBKERN_ORIG(lchown)(path, 501, 501);
});

LIBKERN_PATCH(int, fchown, (int fd,
                            uid_t owner,
                            gid_t group),
{
    return LIBKERN_ORIG(fchown)(fd, 501, 501);
});

LIBKERN_PATCH(int, fchownat, (int fd,
                              const char *path,
                              uid_t owner,
                              gid_t group,
                              int flags),
{
    return LIBKERN_ORIG(fchownat)(fd, path, 501, 501, flags);
});

static inline bool liveshim_is_root(void)
{
    return (uid_t)liveshim_syscall(SYS_geteuid) == 0;
}

static inline mode_t liveshim_root_mode(mode_t mode,
                                        mode_t type)
{
    return mode | (S_ISDIR(type) ? S_IRWXU : (S_IRUSR | S_IWUSR));
}

LIBKERN_PATCH(int, chmod, (const char *path,
                           mode_t mode),
{
    struct stat st;
    if(liveshim_is_root() && stat(path, &st) == 0)
    {
        mode = liveshim_root_mode(mode, st.st_mode);
    }
    return LIBKERN_ORIG(chmod)(path, mode);
});

LIBKERN_PATCH(int, fchmod, (int fd,
                            mode_t mode),
{
    struct stat st;
    if(liveshim_is_root() && fstat(fd, &st) == 0)
    {
        mode = liveshim_root_mode(mode, st.st_mode);
    }
    return LIBKERN_ORIG(fchmod)(fd, mode);
});

LIBKERN_PATCH(int, mkdir, (const char *path,
                           mode_t mode),
{
    if(liveshim_is_root())
    {
        mode |= S_IRWXU;
    }
    return LIBKERN_ORIG(mkdir)(path, mode);
});

LIBKERN_PATCH(int, mkdirat, (int fd,
                             const char *path,
                             mode_t mode),
{
    if(liveshim_is_root())
    {
        mode |= S_IRWXU;
    }
    return LIBKERN_ORIG(mkdirat)(fd, path, mode);
});

LIBKERN_PATCH(pid_t, getppid, (void),
{
    return (pid_t)liveshim_syscall(SYS_getppid);
});

LIBKERN_PATCH(int, setuid, (uid_t uid),
{
    return (int)liveshim_syscall(SYS_setuid, uid);
});

LIBKERN_PATCH(int, seteuid, (uid_t euid),
{
    return (int)liveshim_syscall(SYS_seteuid, euid);
});

LIBKERN_PATCH(int, setruid, (uid_t uid),
{
    return (int)liveshim_syscall(SYS_setreuid, uid, -1);
});

LIBKERN_PATCH(int, setreuid, (uid_t ruid,
                              uid_t euid),
{
    return (int)liveshim_syscall(SYS_setreuid, ruid, euid);
});

LIBKERN_PATCH(int, setgid, (gid_t gid),
{
    return (int)liveshim_syscall(SYS_setgid, gid);
});

LIBKERN_PATCH(int, setegid, (gid_t gid),
{
    return (int)liveshim_syscall(SYS_setegid, gid);
});

LIBKERN_PATCH(int, setrgid, (gid_t gid),
{
    return (int)liveshim_syscall(SYS_setregid, gid, -1);
});

LIBKERN_PATCH(int, setregid, (gid_t egid,
                              gid_t rgid),
{
    return (int)liveshim_syscall(SYS_setregid, egid, rgid);
});

LIBKERN_PATCH(pid_t, getpgrp, (void),
{
    return (pid_t)liveshim_syscall(SYS_getpgrp);
});

LIBKERN_PATCH(pid_t, getpgid, (pid_t pid),
{
    return (pid_t)liveshim_syscall(SYS_getpgid, pid);
});

LIBKERN_PATCH(int, setpgid, (pid_t pid,
                             pid_t pgid),
{
    return (int)liveshim_syscall(SYS_setpgid, pid, pgid);
});

LIBKERN_PATCH(pid_t, getsid, (pid_t sid),
{
    return (pid_t)liveshim_syscall(SYS_getsid, sid);
});

LIBKERN_PATCH(int, setsid, (void),
{
    return (int)liveshim_syscall(SYS_setsid);
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(getuid);
    LIBKERN_INSTALL_PATCH(getgid);
    LIBKERN_INSTALL_PATCH(geteuid);
    LIBKERN_INSTALL_PATCH(getegid);
    LIBKERN_INSTALL_PATCH(getlogin);
    LIBKERN_INSTALL_PATCH(getlogin_r);
    LIBKERN_INSTALL_PATCH(setlogin);
    LIBKERN_INSTALL_PATCH(getgroups);
    LIBKERN_INSTALL_PATCH(setgroups);
    LIBKERN_INSTALL_PATCH(initgroups);
    LIBKERN_INSTALL_PATCH(chown);
    LIBKERN_INSTALL_PATCH(lchown);
    LIBKERN_INSTALL_PATCH(fchown);
    LIBKERN_INSTALL_PATCH(fchownat);
    LIBKERN_INSTALL_PATCH(chmod);
    LIBKERN_INSTALL_PATCH(fchmod);
    LIBKERN_INSTALL_PATCH(mkdir);
    LIBKERN_INSTALL_PATCH(mkdirat);
    LIBKERN_INSTALL_PATCH(getppid);
    LIBKERN_INSTALL_PATCH(setuid);
    LIBKERN_INSTALL_PATCH(seteuid);
    LIBKERN_INSTALL_PATCH(setruid);
    LIBKERN_INSTALL_PATCH(setreuid);
    LIBKERN_INSTALL_PATCH(setgid);
    LIBKERN_INSTALL_PATCH(setegid);
    LIBKERN_INSTALL_PATCH(setrgid);
    LIBKERN_INSTALL_PATCH(setregid);
    LIBKERN_INSTALL_PATCH(getpgrp);
    LIBKERN_INSTALL_PATCH(getpgid);
    LIBKERN_INSTALL_PATCH(setpgid);
    LIBKERN_INSTALL_PATCH(getsid);
    LIBKERN_INSTALL_PATCH(setsid);
    LIBKERN_INSTALL_PATCH(setgroups);
}
