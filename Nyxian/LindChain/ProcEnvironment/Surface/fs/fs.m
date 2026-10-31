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

#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#include <LindChain/ProcEnvironment/Surface/fs/fs.h>
#include <LindChain/ProcEnvironment/Surface/fs/mount.h>
#include <LindChain/ProcEnvironment/Surface/fs/preserver.h>
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>
#include <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#include <LindChain/ProcEnvironment/Surface/libkern/kxld/kxopen.h>
#import <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/KextLoader/PEKext.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

NSString *kextFSRoot = nil;

static void ksurface_fs_init_mount3(FSMountAttr attributes,
                                    const char *device_dir,
                                    const char *mount_dir,
                                    ...)
{
    if(ksurface_fs_mount3(attributes, device_dir, mount_dir) != KERN_SUCCESS)
    {
        kpanic("failed to create %s userspace mount", mount_dir);
    }
}

kern_return_t ksurface_fs_init(void)
{
    const char *home = getenv("HOME");
    if(!home)
    {
        klog_log("ksurface:fs", "HOME unset");
        return KERN_FAILURE;
    }
    
    klog_log("ksurface:fs", "initializing mntfs");
    klog_log("ksurface:fs", "preparing userspace mounts");
    
    kextFSRoot = [NSString stringWithFormat:@"%s/Documents/mntfs/kextfs", home];
    
    kern_return_t kr = ksurface_fs_sandbox_init();
    if(kr != KERN_SUCCESS)
    {
        kpanic("failed to initialize fs sandbox");
    }
    
    if(ksurface_fs_mount3_var_add("croot", home) != KERN_SUCCESS ||
       ksurface_fs_mount3_var_add("bootloader", NSBundle.mainBundle.bundlePath.UTF8String) != KERN_SUCCESS ||
       ksurface_fs_mount3_var_add("vroot", "$croot/Documents/rootfs") != KERN_SUCCESS ||
       ksurface_fs_mount3_var_add("mnt", "$croot/Documents/mntfs") != KERN_SUCCESS)
    {
        kpanic("failed to initialize fs variable table");
    }
    
    /* TODO: fstab reader */
    /* main */
    ksurface_fs_init_mount3(kFSMountAttrNone, FS_MOUNT_NOUNLINK, "$mnt");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot");
    
    /* mntfs */
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrClear, FS_MOUNT_NOUNLINK, "$mnt/devfs");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrClear, FS_MOUNT_NOUNLINK, "$mnt/bootfs");
    ksurface_fs_init_mount3(kFSMountAttrRead, FS_MOUNT_NOUNLINK, "$mnt/kextfs");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite | kFSMountAttrWritePlatform, FS_MOUNT_NOUNLINK, "$mnt/lsfs");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$mnt/etcfs");
    
    /* bootfs */
    ksurface_fs_init_mount3(kFSMountAttrRead, "$bootloader/Frameworks/bootstrapd.dylib", "$mnt/bootfs/libexec/bootstrapd");
    ksurface_fs_init_mount3(kFSMountAttrRead, "$bootloader/Frameworks/MobileDevelopmentService.dylib", "$mnt/bootfs/libexec/MobileDevelopmentService");
    ksurface_fs_init_mount3(kFSMountAttrRead, "$bootloader", "$mnt/bootfs/bootloader");
    ksurface_fs_init_mount3(kFSMountAttrRead, "$bootloader/Shared/kernel", "$mnt/bootfs/headers");
    ksurface_fs_init_mount3(kFSMountAttrRead, "$mnt/bootfs", "$vroot/boot");
    
    /* kextfs */
    ksurface_fs_init_mount3(kFSMountAttrRead, "$mnt/kextfs", "$mnt/bootfs/kexts");
    
    /* devfs */
    ksurface_fs_init_mount3(kFSMountAttrRead, "$mnt/devfs", "$vroot/dev");
    
    /* lsfs */
    ksurface_fs_init_mount3(kFSMountAttrRead, "$bootloader/Shared/LaunchServices/org.emexlabs.bootstrapd.plist", "$mnt/lsfs/org.emexlabs.bootstrapd.plist");
    ksurface_fs_init_mount3(kFSMountAttrRead, "$bootloader/Shared/LaunchServices/org.emexlabs.compilerd.plist", "$mnt/lsfs/org.emexlabs.compilerd.plist");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite | kFSMountAttrWritePlatform, "$mnt/lsfs", "$vroot/System/Library/LaunchDaemons");
    
    /* etcfs */
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, "$mnt/etcfs", "$vroot/etc");
    
    /* rootfs */
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite | kFSMountAttrClear, FS_MOUNT_NOUNLINK, "$vroot/tmp");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/var/containers");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/var/mobile/Containers");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/var/mobile/tmp");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/var/root");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/usr/bin");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/usr/sbin");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/usr/lib");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/usr/include");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/bin");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/sbin");
    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot/lib");
    
    klog_log("ksurface:fs", "starting mount preserver");
    kr = ksurface_fs_preserver_kickstart();
    if(kr != KERN_SUCCESS)
    {
        kpanic("failed to start mount preserver");
        return kr;
    }
    
    return KERN_SUCCESS;
}

kern_return_t ksurface_fs_install_kext_at_path(const char *path)
{
    if(path == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    NSString *nsPath = [NSString stringWithCString:path encoding:NSUTF8StringEncoding];
    if(nsPath == nil)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    /* gather bundle and executable */
    NSBundle *bundle = [NSBundle bundleWithPath:nsPath];
    if(bundle == nil)
    {
        return KERN_DENIED;
    }
    
    NSString *executable = bundle.executablePath;
    if(executable == nil)
    {
        return KERN_DENIED;
    }
    
    /* validate apple signature */
    LCMachO *machO = LCMapMachO(executable.UTF8String, true);
    if(machO == NULL)
    {
        return KERN_DENIED;
    }
    
    bool isAppleSigned = LCCheckCodeSignature(machO);
    LCUnmapMachO(machO);
    if(!isAppleSigned)
    {
        return KERN_DENIED;
    }
    
    /* validate kext's nxt2 blob */
    ksurface_nxt2_t result = {};
    kern_return_t kr = trust_nxt2_read(executable.UTF8String, &result);
    if(kr != KERN_SUCCESS ||
       !result.isValid ||
       !result.isSigned ||
       !result.isCdHashValid)
    {
        if(result.entitlements != nil)
        {
            CFRelease(result.entitlements);
        }
        return KERN_DENIED;
    }
    
    /* check entitlements */
    bool hasEntitlement = CFDictionaryGetValue(result.entitlements, kNXT2EntitlementKsurfaceKEXTLoading) == kCFBooleanTrue;
    CFRelease(result.entitlements);
    if(!hasEntitlement)
    {
        return KERN_DENIED;
    }
    
    /* ready to go, we trust that thing */
    NSString *kextPath = [kextFSRoot stringByAppendingFormat:@"/%@.kext", bundle.bundleIdentifier];
    [[NSFileManager defaultManager] removeItemAtPath:kextPath error:nil];
    if(![[NSFileManager defaultManager] copyItemAtPath:nsPath toPath:kextPath error:nil])
    {
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}
