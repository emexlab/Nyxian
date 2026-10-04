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

#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <LiveShim/shim.h>
#include <LiveShim/vroot.h>
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
    strlcpy(f->f_mntonname, liveshim_vroot(), sizeof(f->f_mntonname));
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
