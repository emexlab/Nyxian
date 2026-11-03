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
#include <sys/ioccom.h>
#include <sys/stat.h>

LIBKERN_PATCH(int, access, (const char *path,
                            int mode),
{
    if(mode & X_OK)
    {
        struct stat sb;
        if(stat(path, &sb) == 0)
        {
            if(sb.st_mode & S_IXUSR)
            {
                if(mode == X_OK)
                {
                    return 0;
                }
                return LIBKERN_ORIG(access)(path, mode & ~X_OK);
            }
        }
    }
    return LIBKERN_ORIG(access)(path, mode);
});


LIBKERN_PATCH(int, faccessat, (int dirfd,
                               const char *path,
                               int mode,
                               int flags),
{
    if(mode & X_OK)
    {
        struct stat sb;
        int stat_flags = (flags & AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;
        if(fstatat(dirfd, path, &sb, stat_flags) == 0)
        {
            if(sb.st_mode & S_IXUSR)
            {
                if(mode == X_OK)
                {
                    return 0;
                }
                return LIBKERN_ORIG(faccessat)(dirfd, path, mode & ~X_OK, flags);
            }
        }
    }
    return LIBKERN_ORIG(faccessat)(dirfd, path, mode, flags);
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(access);
    LIBKERN_INSTALL_PATCH(faccessat);
}
