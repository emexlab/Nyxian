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

LIBKERN_PATCH(int, sysctl, (int *name,
                            u_int namelen,
                            void *__sized_by(*oldlenp) oldp,
                            size_t *oldlenp,
                            void *__sized_by(newlen) newp,
                            size_t newlen),
{
    int ret = (int)liveshim_syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
    return (ret == -1 && errno == ENOSYS) ? LIBKERN_ORIG(sysctl)(name, namelen, oldp, oldlenp, newp, newlen) : ret;
});

LIBKERN_PATCH(int, sysctlbyname, (const char *name,
                                  void *__sized_by(*oldlenp) oldp,
                                  size_t *oldlenp,
                                  void *__sized_by(newlen) newp,
                                  size_t newlen),
{
    int ret = (int)liveshim_syscall(SYS_sysctlbyname, name, oldp, oldlenp, newp, newlen);
    return (ret == -1 && errno == ENOSYS) ? LIBKERN_ORIG(sysctlbyname)(name, oldp, oldlenp, newp, newlen) : ret;
});

LIBKERN_PATCH(int, gethostname, (char *name,
                                 size_t len),
{
    int mib[2] = { CTL_KERN, KERN_HOSTNAME };
    int retval = sysctl(mib, 2, name, &len, NULL, 0);
    name[len] = '\0';
    return retval;
});

LIBKERN_PATCH(int, sethostname, (char *name,
                                 size_t len),
{
    int mib[2] = { CTL_KERN, KERN_HOSTNAME };
    return sysctl(mib, 2, NULL, NULL, name, len);
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(sysctl);
    LIBKERN_INSTALL_PATCH(sysctlbyname);
    LIBKERN_INSTALL_PATCH(gethostname);
    LIBKERN_INSTALL_PATCH(sethostname);
}
