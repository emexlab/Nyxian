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
#include <LindChain/Private/mach/fileport.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static pthread_mutex_t g_sign_lock = PTHREAD_MUTEX_INITIALIZER;

static bool rks_path_inside(const char *path, const char *dir)
{
    size_t length = strlen(dir);
    return length > 0 && strncmp(path, dir, length) == 0 && (path[length] == '/' || path[length] == '\0');
}

static int rks_sign_path(const char *path)
{
    char resolved[PATH_MAX];
    if(realpath(path, resolved) == NULL)
    {
        return errno ? errno : ENOENT;
    }

    const char *home = getenv("HOME");
    char home_real[PATH_MAX];
    if(home == NULL || realpath(home, home_real) == NULL || !rks_path_inside(resolved, home_real))
    {
        rks_logf("sign: refusing %s (outside the bootloader container)", resolved);
        return EPERM;
    }
    if(rks.sign == NULL)
    {
        return ENOTSUP;
    }

    /* one at a time: two guests loading the same library must not rewrite it concurrently */
    pthread_mutex_lock(&g_sign_lock);
    int err = rks.sign(resolved);
    pthread_mutex_unlock(&g_sign_lock);
    if(err != 0)
    {
        rks_logf("sign: %s failed (%d)", resolved, err);
    }
    return err;
}

int64_t rks_sys_sign(rks_call_t *call)
{
    if(call->in_count < 1 || call->in_ports == NULL || !MACH_PORT_VALID(call->in_ports[0]))
    {
        RKS_FAIL(call, EINVAL);
    }
    int fd = fileport_makefd(call->in_ports[0]);
    if(fd < 0)
    {
        RKS_FAIL(call, EBADF);
    }
    int flags = fcntl(fd, F_GETFL);
    char path[PATH_MAX];
    bool ok = flags != -1 && (flags & O_ACCMODE) == O_RDWR && fcntl(fd, F_GETPATH, path) == 0;
    close(fd);
    if(!ok)
    {
        RKS_FAIL(call, EBADF);
    }
    int err = rks_sign_path(path);
    if(err != 0)
    {
        RKS_FAIL(call, err == EPERM ? EPERM : ENOEXEC);
    }
    return 0;
}

int64_t rks_sys_sign2(rks_call_t *call)
{
    char *path = rks_copy_str_in(call->task, (uint64_t)call->args[0], PATH_MAX);
    if(path == NULL)
    {
        RKS_FAIL(call, EFAULT);
    }
    int err = rks_sign_path(path);
    free(path);
    if(err != 0)
    {
        RKS_FAIL(call, err == EPERM ? EPERM : ENOEXEC);
    }
    return 0;
}
