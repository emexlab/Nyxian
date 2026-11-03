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

#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <LiveProcessLegacy/LPLShim.h>
#include <LiveProcessLegacy/LPLVRoot.h>
#include <Broadpatch/Broadpatch.h>

static void fill_fake(struct statfs *f)
{
    memset(f, 0, sizeof(*f));
    f->f_bsize = 4096;
    f->f_iosize = 4096;
    f->f_blocks = 1000000;
    f->f_bfree = 500000;
    f->f_bavail = 500000;
    f->f_files = 100000;
    f->f_ffree = 90000;
    f->f_fsid.val[0] = 0x1337;
    f->f_fsid.val[1] = 0xbeef;
    f->f_owner = 0;
    f->f_flags = MNT_LOCAL | MNT_ROOTFS;
    strlcpy(f->f_fstypename, "apfs", sizeof(f->f_fstypename));
    const char *vroot = liveshim_vroot();
    strlcpy(f->f_mntonname, vroot ? vroot : "/", sizeof(f->f_mntonname));
    strlcpy(f->f_mntfromname, "nyxian", sizeof(f->f_mntfromname));
}

LIBKERN_PATCH(int, getmntinfo, (struct statfs **mntbufp,
                                int flags),
{
    struct statfs *buf;
    int n = LIBKERN_ORIG(getmntinfo)(&buf, flags);
    if(n <= 0)
    {
        *mntbufp = buf;
        return n;
    }
    
    fill_fake(&buf[n]);
    *mntbufp = buf;
    return n + 1;
});

LIBKERN_PATCH(int, getmntinfo_r_np, (struct statfs **mntbufp,
                                     int flags),
{
    struct statfs *buf;
    int n = LIBKERN_ORIG(getmntinfo_r_np)(&buf, flags);
    if(n <= 0)
    {
        *mntbufp = buf;
        return n;
    }
    
    fill_fake(&buf[n]);
    *mntbufp = buf;
    return n + 1;
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(getmntinfo);
    LIBKERN_INSTALL_PATCH(getmntinfo_r_np);
}
