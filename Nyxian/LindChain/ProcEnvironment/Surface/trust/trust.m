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

/* ----------------------------------------------------------------------
 *  System Headers
 * -------------------------------------------------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

/* ----------------------------------------------------------------------
 *  Project Headers
 * -------------------------------------------------------------------- */
#import <LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/Surface/trust/trust.h>
#import <LindChain/ProcEnvironment/Surface/surface.h>
#import <LindChain/ProcEnvironment/Surface/fs/sandbox.h>
#import <LindChain/ProcEnvironment/Utils/vnode.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <LindChain/Utils/CFTools.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <ksurface_config.h>

/* ----------------------------------------------------------------------
 *  Types
 * -------------------------------------------------------------------- */
typedef struct {
    const char *path;
    CFDictionaryRef entitlementPreset;
} trustDaemonEntry;

/* ----------------------------------------------------------------------
 *  Functions
 * -------------------------------------------------------------------- */
static _Atomic int g_enforcement_mode = -1;

bool trust_enforcement_set_mode(PEEnforcementMode mode)
{
    if(mode != kPEEnforcementModePermissive && mode != kPEEnforcementModeDisabled)
    {
        mode = kPEEnforcementModeEnforcing;
    }
    
    int expected = -1;
    return atomic_compare_exchange_strong(&g_enforcement_mode, &expected, (int)mode);
}

PEEnforcementMode trust_enforcement_mode(void)
{
    int expected = -1;
    atomic_compare_exchange_strong(&g_enforcement_mode, &expected, (int)kPEEnforcementModeEnforcing);
    return (PEEnforcementMode)atomic_load(&g_enforcement_mode);
}

bool trust_enforcement_should_deny(pid_t pid,
                                   PEEntitlementFlags missing,
                                   const char *operation)
{
    switch(trust_enforcement_mode())
    {
        case kPEEnforcementModeDisabled:
            return false;
        case kPEEnforcementModePermissive:
            klog_log("trust", "permissive: pid %d lacks 0x%llx for %s, allowed", pid, (unsigned long long)missing, operation ?: "?");
            return false;
        case kPEEnforcementModeEnforcing:
        default:
            klog_log("trust", "denied: pid %d lacks 0x%llx for %s", pid, (unsigned long long)missing, operation ?: "?");
            return true;
    }
}

bool trust_enforcement_overrides(pid_t pid,
                                 PEEntitlementFlags missing,
                                 const char *operation)
{
    switch(trust_enforcement_mode())
    {
        case kPEEnforcementModeDisabled:
            return true;
        case kPEEnforcementModePermissive:
            klog_log("trust", "permissive: pid %d lacks 0x%llx for %s, widened", pid, (unsigned long long)missing, operation ?: "?");
            return true;
        case kPEEnforcementModeEnforcing:
        default:
            return false;
    }
}

static bool array_is_all_strings(CFArrayRef arr)
{
    CFIndex n = CFArrayGetCount(arr);
    for(CFIndex i = 0; i < n; i++)
    {
        CFTypeRef e = CFArrayGetValueAtIndex(arr, i);
        if(!e || CFGetTypeID(e) != CFStringGetTypeID())
        {
            return false;
        }
    }
    return true;
}

typedef struct {
    CFStringRef key;
    CFTypeID expected_type;
} entitlement_schema_entry;

LIBKERN_DEFINE_PATCHABLE(CFDictionaryRef, trust_identity_validate_entitlements, (CFStringRef executablePath,
                                                                                 CFDictionaryRef entitlements))
{
    if(entitlements == NULL)
    {
        return NULL;
    }
    
    /* allowance schema */
    const entitlement_schema_entry schema[] = {
        /* foundational */
        { kNXT2EntitlementPlatform,                     CFBooleanGetTypeID() },
        { kNXT2EntitlementPlatformRoot,                 CFBooleanGetTypeID() },
        { kNXT2EntitlementPlatformUser,                 CFNumberGetTypeID()  },
        { kNXT2EntitlementPlatformGroup,                CFNumberGetTypeID()  },
        { kNXT2EntitlementGetTaskAllow,                 CFBooleanGetTypeID() },
        { kNXT2EntitlementTaskForPid,                   CFBooleanGetTypeID() },
        { kNXT2EntitlementSUGID,                        CFBooleanGetTypeID() },
        { kNXT2EntitlementSystemTaskPorts,              CFBooleanGetTypeID() },
        
        /* process */
        { kNXT2EntitlementProcessEnumeration,           CFBooleanGetTypeID() },
        { kNXT2EntitlementProcessKill,                  CFBooleanGetTypeID() },
        { kNXT2EntitlementProcessSpawn,                 CFBooleanGetTypeID() },
        { kNXT2EntitlementProcessSpawnSignedOnly,       CFBooleanGetTypeID() },
        { kNXT2EntitlementProcessSpawnInheriteEntitlements, CFBooleanGetTypeID() },
        
        /* management */
        { kNXT2EntitlementManagementHost,               CFBooleanGetTypeID() },
        
        /* launch services */
        { kNXT2EntitlementLaunchServicesStart,          CFBooleanGetTypeID() },
        { kNXT2EntitlementLaunchServicesStop,           CFBooleanGetTypeID() },
        { kNXT2EntitlementLaunchServicesToggle,         CFBooleanGetTypeID() },
        { kNXT2EntitlementLaunchServicesGetEndpoint,    CFBooleanGetTypeID() },
        { kNXT2EntitlementLaunchServicesSetEndpoint,    CFBooleanGetTypeID() },
        { kNXT2EntitlementLaunchServicesGetEndpointAllowList,   CFArrayGetTypeID() },
        { kNXT2EntitlementLaunchServicesSetEndpointAllowList,   CFArrayGetTypeID() },
        
        /* sandbox */
        { kNXT2EntitlementSandboxFileRead,              CFArrayGetTypeID()   },
        { kNXT2EntitlementSandboxFileReadWrite,         CFArrayGetTypeID()   },
        { kNXT2EntitlementSandboxNoContainer,           CFBooleanGetTypeID() },
        { kNXT2EntitlementSandboxHost,                  CFBooleanGetTypeID() },
        
        /* ksurface */
        { kNXT2EntitlementKsurfaceKEXTLoading,          CFBooleanGetTypeID() },
    };
    const size_t schema_count = sizeof(schema) / sizeof(schema[0]);
    
    CFMutableDictionaryRef clean = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(!clean)
    {
        return NULL;
    }
    
    for(size_t i = 0; i < schema_count; i++)
    {
        CFTypeRef val = CFDictionaryGetValue(entitlements, schema[i].key);
        if(val == NULL)
        {
            continue;
        }
        if(CFGetTypeID(val) != schema[i].expected_type)
        {
            continue;
        }
        if(schema[i].expected_type == CFArrayGetTypeID())
        {
            if(!array_is_all_strings((CFArrayRef)val))
            {
                continue;
            }
        }
        CFDictionarySetValue(clean, schema[i].key, val);
    }
    
    CFMutableArrayRef rwPaths;
    CFArrayRef existing = CFDictionaryGetValue(clean, kNXT2EntitlementSandboxFileReadWrite);
    if(existing)
    {
        rwPaths = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, existing);
    }
    else
    {
        rwPaths = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    }
    
    CFMutableArrayRef roPaths;
    CFArrayRef roExisting = CFDictionaryGetValue(clean, kNXT2EntitlementSandboxFileRead);
    if(roExisting)
    {
        roPaths = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, roExisting);
    }
    else
    {
        roPaths = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    }
    
    if(rwPaths && roPaths)
    {
        /* dyld needs to see the executable */
        CFArrayAppendValue(roPaths, CFSTR("$(EXECUTABLE)"));
        CFArrayAppendValue(roPaths, CFSTR("$(BUNDLE)"));    /* if it is a bundle and bootstrapd has the same opinion about it */
        
        /* some random entitlement */
        if(CFDictionaryGetValue(clean, kNXT2EntitlementSandboxNoContainer) != kCFBooleanTrue)
        {
            /* grant container access */
            CFArrayAppendValue(roPaths, CFSTR("$(CONTAINER)"));
            CFArrayAppendValue(rwPaths, CFSTR("$(CONTAINER)/*"));
        }
        
        CFDictionarySetValue(clean, kNXT2EntitlementSandboxFileRead, roPaths);
        CFDictionarySetValue(clean, kNXT2EntitlementSandboxFileReadWrite, rwPaths);
        CFRelease(rwPaths);
        CFRelease(roPaths);
    }
    
    return clean;
}

static NSArray<NSString *> *PEResolveEntitlementPaths(NSString *pathTemplate,
                                                      NSDictionary<NSString *, NSString *> *vars)
{
    NSMutableString *resolved = [pathTemplate mutableCopy];
    for(NSString *key in vars)
    {
        NSString *token = [NSString stringWithFormat:@"$(%@)", key];
        [resolved replaceOccurrencesOfString:token withString:vars[key] options:0 range:NSMakeRange(0, resolved.length)];
    }
    
    if(![resolved hasSuffix:@"/*"])
    {
        return @[[resolved copy]];
    }
    
    NSString *dir = [resolved substringToIndex:resolved.length - 2];
    while(dir.length > 1 && [dir hasSuffix:@"/"])
    {
        dir = [dir substringToIndex:dir.length - 1];
    }
    
    NSError *err = nil;
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:&err];
    if(!entries)
    {
        return @[];
    }
    
    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithCapacity:entries.count];
    for(NSString *name in entries)
    {
        [paths addObject:[dir stringByAppendingPathComponent:name]];
    }
    [paths sortUsingSelector:@selector(compare:)];
    return [paths copy];
}

static NSString *PECanonicalizePath(NSString *path)
{
    char resolved[PATH_MAX];
    if(realpath(path.fileSystemRepresentation, resolved) == NULL)
    {
        return nil;
    }
    return [NSString stringWithUTF8String:resolved];
}

static void trust_identity_append_file_permissions(NSMutableArray<NSData*> *filePermissions,
                                                   NSString *rawPath,
                                                   NSDictionary *pathVariables,
                                                   FSMountPermissionFlags permission,
                                                   BOOL over_sbfs_layer,
                                                   CFDictionaryRef entitlements)
{
    NSArray<NSString*> *paths = PEResolveEntitlementPaths(rawPath, pathVariables);
    for(NSString *path in paths)
    {
        NSString *actualPath = PECanonicalizePath(path);
        if(actualPath)
        {
            if(over_sbfs_layer)
            {
                NSArray<NSData*> *extensions = (__bridge_transfer NSArray<NSData*>*)ksurface_fs_sandbox_copy_sandbox_extensions_for_entitlements(actualPath.UTF8String, permission, entitlements);
                if(extensions != nil)
                {
                    [filePermissions addObjectsFromArray:extensions];
                }
            }
            else
            {
                /* that means no mount permission layer! */
                NSData *extension = (__bridge_transfer NSData*)ksurface_fs_sandbox_copy_sandbox_extension_for_arbitary_path(actualPath.UTF8String, permission);
                if(extension != nil)
                {
                    [filePermissions addObject:extension];
                }
            }
        }
    }
}

static void trust_identity_append_file_permissions_for_paths(NSMutableArray<NSData*> *filePermissions,
                                                             NSArray<NSString*> *rawPaths,
                                                             NSDictionary *pathVariables,
                                                             FSMountPermissionFlags permission,
                                                             BOOL over_sbfs_layer,
                                                             CFDictionaryRef entitlements)
{
    for(NSString *rawPath in rawPaths)
    {
        trust_identity_append_file_permissions(filePermissions, rawPath, pathVariables, permission, over_sbfs_layer, entitlements);
    }
}

LIBKERN_DEFINE_PATCHABLE(CFArrayRef, trust_identity_give_file_permissions, (CFStringRef executableString,
                                                                            CFDictionaryRef entitlements))
{
    @autoreleasepool
    {
        NSMutableArray<NSData*> *filePermissions = [[NSMutableArray alloc] init];
        
        /* prepare variables */
        NSMutableDictionary *vars = [@{
            @"ROOTFS": NXBootstrap.shared.rootfsURL.path,   /* actually deprecated because it will be replaced by NXROOT like the env variable */
            @"NXROOT": NXBootstrap.shared.rootfsURL.path,
            @"EXECUTABLE": (__bridge NSString*)executableString,
        } mutableCopy];
        
        if(![[NSUserDefaults standardUserDefaults] boolForKey:@"nyxian.boot.sandbox.filesystems"])
        {
            trust_identity_append_file_permissions_for_paths(filePermissions, @[
                @"$(NXROOT)",
            ], vars, kFSMountPermissionReadWrite, true, entitlements);
            return (__bridge_retained CFArrayRef)filePermissions;
        }
        
        /* append applicable variables */
        LDEApplicationObject *applicationObject = [[LDEApplicationWorkspace shared] applicationObjectForExecutablePath:(__bridge NSString*)executableString];
        if(applicationObject != nil && applicationObject.bundlePath != nil && applicationObject.containerPath != nil)
        {
            /* is a application bundle */
            vars[@"CONTAINER"] = applicationObject.containerPath;
            vars[@"BUNDLE"] = applicationObject.bundlePath;
        }
        
        NSDictionary *nsEntitlements = (__bridge NSDictionary*)entitlements;
        
        /* append file permissions from entitlements */
        trust_identity_append_file_permissions_for_paths(filePermissions, nsEntitlements[(__bridge NSString*)kNXT2EntitlementSandboxFileRead], vars, kFSMountPermissionRead, true, entitlements);
        trust_identity_append_file_permissions_for_paths(filePermissions, nsEntitlements[(__bridge NSString*)kNXT2EntitlementSandboxFileReadWrite], vars, kFSMountPermissionReadWrite, true, entitlements);
        
        /* append extra file permissions that are on by default */
        trust_identity_append_file_permissions_for_paths(filePermissions, @[
            @"$(NXROOT)/boot/rtpatch",
            @"$(NXROOT)/boot/patchfinder.bin"
        ], vars, kFSMountPermissionRead, true, entitlements);
        
        /* handling the most powerful entitlement known to ksurface */
        if(CFDictionaryGetValue(entitlements, kNXT2EntitlementSandboxHost) == kCFBooleanTrue)
        {
            trust_identity_append_file_permissions(filePermissions, @"$(NXROOT)/../../*", vars, kFSMountPermissionRead, false, NULL);   /* making host data container sub paths readable */
            trust_identity_append_file_permissions_for_paths(filePermissions, @[
                @"$(NXROOT)/../*",          /* full documents path rw in container of host */
                @"$(NXROOT)/../Library/*",  /* full library path rw in container of host */
                @"$(NXROOT)/../tmp",        /* full tmp RW */
            ], vars, kFSMountPermissionReadWrite, false, NULL);
        }
        return (__bridge_retained CFArrayRef)filePermissions;
    }
}

PEEntitlementFlags trust_identity_entitlement_flags_from_entitlements(CFDictionaryRef entitlements)
{
    PEEntitlementFlags legacyEntitlements = kPEEntitlementFlagNone;
    if(entitlements == NULL)
    {
        return legacyEntitlements;
    }
    
    #define ENT_IS_TRUE(dict, key) \
        ({ CFTypeRef _v = CFDictionaryGetValue((dict), (key)); \
        (_v != NULL && CFGetTypeID(_v) == CFBooleanGetTypeID() \
        && CFBooleanGetValue((CFBooleanRef)_v)); })
    
    /* foundational */
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementPlatform)) legacyEntitlements |= kPEEntitlementFlagPlatform;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementPlatformRoot)) legacyEntitlements |= kPEEntitlementFlagPlatformRoot;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementGetTaskAllow)) legacyEntitlements |= kPEEntitlementFlagGetTaskAllowed;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementTaskForPid)) legacyEntitlements |= kPEEntitlementFlagTaskForPid;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementSystemTaskPorts)) legacyEntitlements |= kPEEntitlementFlagSystemTaskPorts;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementSUGID)) legacyEntitlements |= kPEEntitlementFlagProcessElevate;
    
    /* process */
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementProcessEnumeration)) legacyEntitlements |= kPEEntitlementFlagProcessEnumeration;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementProcessKill)) legacyEntitlements |= kPEEntitlementFlagProcessKill;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementProcessSpawn)) legacyEntitlements |= kPEEntitlementFlagProcessSpawn;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementProcessSpawnSignedOnly)) legacyEntitlements |= kPEEntitlementFlagProcessSpawnSignedOnly;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementProcessSpawnInheriteEntitlements)) legacyEntitlements |= kPEEntitlementFlagProcessSpawnInheriteEntitlements;
    
    /* management */
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementManagementHost)) legacyEntitlements |= kPEEntitlementFlagHostManager;
    
    /* launch services */
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementLaunchServicesStart)) legacyEntitlements |= kPEEntitlementFlagLaunchServicesStart;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementLaunchServicesStop)) legacyEntitlements |= kPEEntitlementFlagLaunchServicesStop;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementLaunchServicesToggle)) legacyEntitlements |= kPEEntitlementFlagLaunchServicesToggle;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementLaunchServicesGetEndpoint)) legacyEntitlements |= kPEEntitlementFlagLaunchServicesGetEndpoint;
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementLaunchServicesSetEndpoint)) legacyEntitlements |= kPEEntitlementFlagLaunchServicesSetEndpoint;
    
    /* ksurface */
    if(ENT_IS_TRUE(entitlements, kNXT2EntitlementKsurfaceKEXTLoading)) legacyEntitlements |= kPEEntitlementFlagLoadKEXT;
    
    #undef ENT_IS_TRUE
    return legacyEntitlements;
}

ksurface_trust_identity_t *trust_identity_get_kernel(void)
{
    static ksurface_trust_identity_t *identity = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        identity = calloc(1, sizeof(ksurface_trust_identity_t));
        identity->trustLevel = kPETrustLevelTrusted;
        identity->entitlements = CFDictionaryCreateCopy(kCFAllocatorDefault, kPEEntitlementsNXT2PresetsKernel);
        
        uint32_t bufsize = PATH_MAX;
        if(_NSGetExecutablePath(identity->path, &bufsize) > 0)
        {
            /* shall never happen */
            kpanic("failed to aquire executable path from dyld");
        }
    });
    return identity;
}

static bool trust_resign_with_fd(int *fd,
                                 ksurface_nxt2_t *result_nxt2)
{
    char path[MAXPATHLEN];
    if(fcntl(*fd, F_GETPATH, path) != 0)
    {
        return false;
    }
    
    if(result_nxt2->isValid &&
       result_nxt2->isCdHashValid &&
       result_nxt2->needsResign)
    {
        static os_unfair_lock resign_lock = OS_UNFAIR_LOCK_INIT;
        os_unfair_lock_lock(&resign_lock);
        
        if(![LCUtils signMachOAtURL:[NSURL fileURLWithPath:[NSString stringWithCString:path encoding:NSUTF8StringEncoding]]])
        {
            os_unfair_lock_unlock(&resign_lock);
            return false;
        }
        
        if(vnode_inaccessible_reopen(fd) != 0)
        {
            os_unfair_lock_unlock(&resign_lock);
            return false;
        }
        
        if(trust_nxt2_sign_fd(*fd, result_nxt2->entitlements, true, NULL) != KERN_SUCCESS)
        {
            os_unfair_lock_unlock(&resign_lock);
            return false;
        }
        
        ksurface_nxt2_t new_result_nxt2;
        if(trust_nxt2_read_fd(*fd, &new_result_nxt2) != KERN_SUCCESS)
        {
            os_unfair_lock_unlock(&resign_lock);
            return false;
        }
        
        if(new_result_nxt2.entitlements == NULL)
        {
            os_unfair_lock_unlock(&resign_lock);
            return false;
        }
        
        CFRelease(result_nxt2->entitlements);
        memcpy(result_nxt2, &new_result_nxt2, sizeof(*result_nxt2));
        
        os_unfair_lock_unlock(&resign_lock);
    }
    
    return true;
}

LIBKERN_DEFINE_PATCHABLE(ksurface_trust_identity_t *, trust_identity_create_from_path, (const char *path))
{
    if(path == NULL)
    {
        errno = EINVAL;
        return NULL;
    }
    
    /* daemon trustpath validation */
    trustDaemonEntry trustDaemonPath[] = {  /* those paths are immutable */
        {
            .path = [NXBootstrap.shared.rootfsURL URLByAppendingPathComponent:@"boot/libexec/bootstrapd"].path.UTF8String,
            .entitlementPreset = kPEEntitlementsNXT2PresetsDaemonBootstrap,
        },
        {
            .path = [NXBootstrap.shared.rootfsURL URLByAppendingPathComponent:@"boot/libexec/MobileDevelopmentService"].path.UTF8String,
            .entitlementPreset = kPEEntitlementsNXT2PresetsDaemonCompiler,
        }
    };
    
    CFStringRef executableString = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);
    if(executableString == NULL)
    {
        return NULL;
    }
    
    for(int index = 0; index < sizeof(trustDaemonPath) / sizeof(trustDaemonEntry); index++)
    {
        if(strncmp(path, trustDaemonPath[index].path, MAXPATHLEN - 1) == 0)
        {
            LCMachO *machO = LCMapMachO(path, true);
            if(machO == NULL)
            {
                return NULL;
            }
            
            bool isAppleSigned = LCCheckCodeSignature(machO);
            LCUnmapMachO(machO);
            if(!isAppleSigned)
            {
                return NULL;
            }
            
            ksurface_trust_identity_t *identity = calloc(1, sizeof(ksurface_trust_identity_t));
            if(identity == NULL)
            {
                /*
                 * returning cause this could become useful in a attack chain.
                 *
                 * 1. exhausting Nyxian's memory.
                 * 2. crash a daemon.
                 * 3. now it runs with fallback entitlements.
                 */
                errno = ENOMEM;
                CFRelease(executableString);
                return NULL;
            }
            strlcpy(identity->path, path, MAXPATHLEN);
            identity->trustLevel = kPETrustLevelTrusted;
            identity->entitlements = CFDictionaryCreateCopy(kCFAllocatorDefault, trustDaemonPath[index].entitlementPreset);
            if(identity->entitlements == NULL)
            {
                errno = ENOMEM;
                CFRelease(executableString);
                return NULL;
            }
            identity->filePermissions = trust_identity_give_file_permissions(executableString, identity->entitlements);
            return identity;
        }
    }
    
    /* check if path is readable and apple signed (required for trust levels lower than kPETrustLevelTrusted, because paths are attacker controlled) */
    if(access(path, R_OK) != 0)
    {
        errno = EACCES;
        CFRelease(executableString);
        return NULL;
    }
    
    /* signature validation */
#if KSURFACE_CS_ALLOW_NXT2
    {
        bool refresh = false;
        int fd = vnode_inaccessible_open(path, O_RDWR);
        if(fd < 0)
        {
            CFRelease(executableString);
            return NULL;
        }
        
        ksurface_nxt2_t result_nxt2;
        if(trust_nxt2_read_fd(fd, &result_nxt2) == KERN_SUCCESS)
        {
            if(result_nxt2.entitlements == NULL)
            {
                close(fd);
                CFRelease(executableString);
                return NULL;
            }
            
            if(result_nxt2.needsResign)
            {
                if(!trust_resign_with_fd(&fd, &result_nxt2))
                {
                    goto out_failure_release_nxt2;
                }
                else
                {
                    refresh = true;
                }
            }
            
            LCMachO *machO = LCMapMachOFromFDRO(dup(fd));
            if(machO == NULL)
            {
                goto out_failure_release_nxt2;
            }
            
            bool isAppleSigned = LCCheckCodeSignature(machO);
            LCUnmapMachO(machO);
            if(!isAppleSigned)
            {
                goto out_failure_release_nxt2;
            }
            
            /* check if blob was signed */
            if(!result_nxt2.isSigned || !result_nxt2.isValid || !result_nxt2.isCdHashValid)
            {
                goto out_failure_release_nxt2;
            }
            
            ksurface_trust_identity_t *identity = calloc(1, sizeof(ksurface_trust_identity_t));
            if(identity == NULL)
            {
                goto out_failure_release_nxt2;
            }
            
            strlcpy(identity->path, path, MAXPATHLEN);
            memcpy(identity->cdhash, result_nxt2.cdhash, USER_FSIGNATURES_CDHASH_LEN);
            
            identity->trustLevel = kPETrustLevelSignature;
            identity->entitlements = trust_identity_validate_entitlements(executableString, result_nxt2.entitlements);
            CFRelease(result_nxt2.entitlements);
            if(identity->entitlements == NULL)
            {
                vnode_inaccessible_close(fd, refresh);
                CFRelease(executableString);
                free(identity);
                return NULL;
            }
            identity->filePermissions = trust_identity_give_file_permissions(executableString, identity->entitlements);
            vnode_inaccessible_close(fd, refresh);
            return identity;
            
        out_failure_release_nxt2:
            vnode_inaccessible_close(fd, refresh);
            CFRelease(result_nxt2.entitlements);
            CFRelease(executableString);
            return NULL;
        }
        vnode_inaccessible_close(fd, refresh);
    }
#endif /* KSURFACE_CS_ALLOW_NXT2 */
    
    /* fallback */
    LCMachO *machO = LCMapMachO(path, true);
    if(machO == NULL)
    {
        CFRelease(executableString);
        return NULL;
    }
    
    bool isAppleSigned = LCCheckCodeSignature(machO);
    LCUnmapMachO(machO);
    if(!isAppleSigned)
    {
        return NULL;
    }
    
    CFMutableDictionaryRef entitlements = CFDictionaryCreateMutable(kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(entitlements == NULL)
    {
        CFRelease(executableString);
        errno = ENOMEM;
        return NULL;
    }
    CFDictionaryRef newEntitlements = trust_identity_validate_entitlements(executableString, entitlements); /* gives container access if applicable */
    CFRelease(entitlements);
    if(newEntitlements == NULL)
    {
        CFRelease(executableString);
        errno = ENOMEM;
        return NULL;
    }
    ksurface_trust_identity_t *identity = calloc(1, sizeof(ksurface_trust_identity_t));
    if(identity == NULL)
    {
        CFRelease(executableString);
        errno = ENOMEM;
        return NULL;
    }
    strlcpy(identity->path, path, MAXPATHLEN);
    
    identity->trustLevel = kPETrustLevelFallback;
    identity->entitlements = newEntitlements;
    identity->filePermissions = trust_identity_give_file_permissions(executableString, identity->entitlements);
    
    CFRelease(executableString);
    return identity;
}

LIBKERN_DEFINE_PATCHABLE(ksurface_trust_identity_t*, trust_identity_create_from_path_with_parent_identity, (const char *path,
                                                                                                            ksurface_trust_identity_t *parentIdentity))
{
    /* first we create the child's identity */
    ksurface_trust_identity_t *childIdentity = trust_identity_create_from_path(path);
    if(childIdentity == NULL)
    {
        return NULL;
    }
    
    /* entitlement inheritance */
    CFMutableDictionaryRef parentMergingEntitlements = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, parentIdentity->entitlements);
    if(parentMergingEntitlements == NULL)
    {
        return NULL;
    }
    
    CFMutableDictionaryRef childNewEntitlements = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, childIdentity->entitlements);
    if(childNewEntitlements == NULL)
    {
        CFRelease(parentMergingEntitlements);
        return NULL;
    }
    
    /*
     * only a platform identity may be able to
     * cause a process with higher identity
     * than it it self.
     */
    if(CFDictionaryGetValue(parentMergingEntitlements, kNXT2EntitlementPlatform) != kCFBooleanTrue)
    {
        /*
         * child gets nothing extra, removing
         * what parent doesnt have.
         */
        CFIndex childCount = CFDictionaryGetCount(childNewEntitlements);
        if(childCount > 0)
        {
            const void **childKeys = malloc((size_t)childCount * sizeof(*childKeys));
            if(childKeys == NULL)
            {
                CFRelease(childNewEntitlements);
                CFRelease(parentMergingEntitlements);
                return false;
            }
            CFDictionaryGetKeysAndValues(childNewEntitlements, childKeys, NULL);
            for(CFIndex index = 0; index < childCount; index++)
            {
                if(!CFDictionaryContainsKey(parentMergingEntitlements, childKeys[index]))
                {
                    CFDictionaryRemoveValue(childNewEntitlements, childKeys[index]);
                }
            }
            free(childKeys);
        }
    }
    
    if(parentIdentity != trust_identity_get_kernel() && /* the kernel cannot inherite entitlements */
       CFDictionaryGetValue(parentMergingEntitlements, kNXT2EntitlementProcessSpawnInheriteEntitlements) == kCFBooleanTrue)
    {
        /*
         * entitlements which shall be stripped from parent
         * merging entitlements, because they are just too
         * over powered.
         */
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementPlatform);
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementPlatformRoot);
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementPlatformUser);
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementPlatformGroup);
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementTaskForPid);
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementSystemTaskPorts);
        CFDictionaryRemoveValue(parentMergingEntitlements, kNXT2EntitlementSUGID);
    }
    else
    {
        /* not inheriting anything */
        CFDictionaryRemoveAllValues(parentMergingEntitlements);
    }
    
    CFIndex remainingParentCount = CFDictionaryGetCount(parentMergingEntitlements);
    if(remainingParentCount > 0)
    {
        const void **parentKeys = malloc((size_t)remainingParentCount * sizeof(*parentKeys));
        if(parentKeys == NULL)
        {
            CFRelease(childNewEntitlements);
            CFRelease(parentMergingEntitlements);
            return false;
        }
        CFDictionaryGetKeysAndValues(parentMergingEntitlements, parentKeys, NULL);
        for(CFIndex index = 0; index < remainingParentCount; index++)
        {
            CFTypeRef value = CFDictionaryGetValue(parentMergingEntitlements, parentKeys[index]);
            if(value == NULL)
            {
                continue;
            }
            
            if(value == kCFBooleanTrue || value == kCFBooleanFalse)
            {
                /* handling booleans */
                CFDictionaryAddValue(childNewEntitlements, parentKeys[index], value);
            }
            else if(CFGetTypeID(value) == CFArrayGetTypeID())
            {
                /* handling arrays */
                CFArrayRef childArray = CFDictionaryGetValue(childNewEntitlements, parentKeys[index]);
                if(childArray == NULL)
                {
                    /* not included */
                    CFDictionaryAddValue(childNewEntitlements, parentKeys[index], value);
                    continue;
                }
                
                if(CFGetTypeID(childArray) != CFArrayGetTypeID())
                {
                    /* reject */
                    continue;
                }
                
                /* merge */
                CFArrayRef parentArray = value;
                CFIndex childArrayCount = CFArrayGetCount(childArray);
                CFIndex parentArrayCount = CFArrayGetCount(parentArray);
                CFMutableArrayRef childNewArray = CFArrayCreateMutableCopy(kCFAllocatorDefault, childArrayCount + parentArrayCount, childArray);
                if(childNewArray == NULL)
                {
                    /* reject */
                    continue;
                }
                
                for(CFIndex indexParent = 0; indexParent < parentArrayCount; indexParent++)
                {
                    CFTypeRef parentValue = CFArrayGetValueAtIndex(parentArray, indexParent);
                    if(CFGetTypeID(parentValue) != CFStringGetTypeID())
                    {
                        /* reject */
                        continue;
                    }
                    
                    if(CFArrayContainsValue(childArray, CFRangeMake(0, childArrayCount), parentValue))
                    {
                        /* exists already */
                        continue;
                    }
                    
                    CFArrayAppendValue(childNewArray, parentValue);
                }
                
                CFDictionarySetValue(childNewEntitlements, parentKeys[index], childNewArray);
                /* FIXME: only allow narrower or same file sandbox permissions gathering (so we dont only use the kern_proc to do it) */
            }
        }
        free(parentKeys);
    }
    
    /* refreshing childIdentity */
    CFRelease(parentMergingEntitlements);
    CFRelease(childIdentity->entitlements);
    childIdentity->entitlements = childNewEntitlements;
    
    return childIdentity;
}

void trust_identity_destroy(ksurface_trust_identity_t *identity)
{
    if(identity == NULL)
    {
        return;
    }
    
    if(identity->entitlements != NULL)
    {
        CFRelease(identity->entitlements);
    }
    if(identity->filePermissions != NULL)
    {
        CFRelease(identity->filePermissions);
    }
    free(identity);
}
