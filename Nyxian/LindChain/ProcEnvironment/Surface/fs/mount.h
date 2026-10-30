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

#ifndef FS_MOUNT_H
#define FS_MOUNT_H

#include <CoreFoundation/CoreFoundation.h>
#include <mach/kern_return.h>
#include <LindChain/ProcEnvironment/Surface/fs/preserver.h>
#include <LindChain/ProcEnvironment/Surface/fs/sandbox.h>

typedef CF_OPTIONS(UInt64, FSMountAttr) {
    kFSMountAttrNone                    = 0,
    kFSMountAttrRead                    = 1ull << 0,    /* grants read access in file system sandbox */
    kFSMountAttrWrite                   = 1ull << 1,    /* grants write access in file system sandbox MARK: kFSMountAttrRead is required for this, otherwise will error with KERN_INVALID_ARGUMENT */
    kFSMountAttrClear                   = 1ull << 2,    /* clears the mount_dir or bind_dir if passed */
    kFSMountAttrReadPlatform            = 1ull << 3,    /* grants read access in file system sandbox if it is a platform process */
    kFSMountAttrWritePlatform           = 1ull << 4,    /* grants write access in file system sandbox if it is a platform process */
    kFSMountAttrReadEntitlement         = 1ull << 5,    /* grants read access in file system sandbox if a specific entitlement is met   TODO: not supported yet */
    kFSMountAttrWriteEntitlement        = 1ull << 6,    /* grants write access in file system sandbox if a specific entitlement is met  TODO: not supported yet */
};

extern const char FS_MOUNT_SANDBOX[PATH_MAX];
extern const char FS_MOUNT_NOUNLINK[PATH_MAX];

/* TODO: not supported yet */
typedef struct {
    CFStringRef readEntitlement;
    CFStringRef writeEntitlement;
} FSMountAttrEntitlementDefinition;

kern_return_t ksurface_fs_mount(FSMountAttr attributes, const char *mount_dir, const char *bind_dir, ...) __attribute__((deprecated("Use ksurface_fs_mount2(3) instead")));
kern_return_t ksurface_fs_mount2(FSMountAttr attributes, const char *device_dir, const char *mount_dir, ...);

kern_return_t ksurface_fs_umount(const char *mount_dir);

kern_return_t ksurface_fs_mount3_var_add(const char *var, const char *path);
kern_return_t ksurface_fs_mount3_var_del(const char *var);
kern_return_t ksurface_fs_mount3(FSMountAttr attributes, const char *device_dir, const char *mount_dir, ...);

#endif /* FS_MOUNT_H */
