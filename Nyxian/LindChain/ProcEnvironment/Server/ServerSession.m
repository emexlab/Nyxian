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

#import <mach/mach.h>
#import <LindChain/ProcEnvironment/Server/ServerSession.h>
#import <LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>
#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/Surface/trust/entitlement.h>
#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/proc/list.h>
#import <LindChain/ProcEnvironment/Surface/proc/proc.h>
#import <LindChain/ProcEnvironment/Surface/proc/permit.h>
#import <ksurface_config.h>

@interface ServerSession ()

@property (nonatomic,getter=proc) ksurface_proc_t *proc;

@end

@implementation ServerSession {
    pid_t _processIdentifier;
}

- (instancetype)initWithProcessidentifier:(pid_t)pid
{
    self = [super init];
    _processIdentifier = pid;
    return self;
}

- (ksurface_proc_t*)proc
{
    if(_proc == NULL)
    {
        /* attempting to get proc from ksurface */
        kern_return_t ret = proc_for_pid(_processIdentifier, &(_proc));
        if(ret != KERN_SUCCESS)
        {
            return NULL;
        }
    }
    
    return _proc;
}

/*
 posix_spawn
 */
- (void)spawnProcessWithPath:(NSString*)path
               withArguments:(NSArray<NSObject<NSSecureCoding,NSCopying>*>*)arguments
    withEnvironmentVariables:(NSDictionary *)environment
               withFileTable:(PEFileTable*)fileTable
        withWorkingDirectory:(NSString *)workingDirectory
              withSpawnFlags:(short)spawnFlags
             withSpawnPgroup:(pid_t)spawnPgroup
                   withReply:(void (^)(int64_t))reply
{
    static dispatch_queue_t spawnQueue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        spawnQueue = dispatch_queue_create("org.emexlabs.nyxian.oldserver.spawnqueue", DISPATCH_QUEUE_SERIAL);
    });
    __weak typeof(self) weakSelf = self;
    dispatch_async(spawnQueue, ^{
        __strong typeof(self) strongSelf = weakSelf;
        if(strongSelf == nil)
        {
            /* sead server session */
            return;
        }
        
        /* sanity checking proc */
        if(strongSelf.proc == NULL)
        {
            reply(-1);
            return;
        }
        
        if(path &&
           arguments &&
           environment &&
           workingDirectory &&
           (entitlement_got_entitlement(proc_getentitlements(strongSelf->_proc), kPEEntitlementFlagProcessSpawn) ||
            entitlement_got_entitlement(proc_getentitlements(strongSelf->_proc), kPEEntitlementFlagProcessSpawnSignedOnly)))
        {
            NSMutableDictionary *mutableItems = [[NSMutableDictionary alloc] initWithDictionary:@{
                @"PEExecutablePath": path,
                @"PEArguments": arguments,
                @"PEEnvironment": environment,
                @"PEWorkingDirectory": workingDirectory,
                @"PEPOSIXSpawnFlags": @(spawnFlags),
                @"PEPOSIXSpawnPgroup": @(spawnPgroup),
            }];
            
            if(fileTable != nil)
            {
                [mutableItems setObject:fileTable forKey:@"PEFileTable"];
            }
            
            /* invoking spawn */
            pid_t pid = [[PEProcessManager shared] spawnProcessWithItems:mutableItems withKernelSurfaceProcess:strongSelf->_proc];
            
            /* replying with pid of spawn */
            reply(pid);
            
            return;
        }
        
        reply(-1);
    });
}

/*
 App switcher services
 */
- (void)setSnapshot:(UIImage*)image
{
    /* null pointer check */
    if(image == nil)
    {
        return;
    }
    
    /* finding process */
    PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:_processIdentifier];
    if(process != nil)
    {
        /* setting snapshot */
        process.snapshot = image;
    }
}

- (void)dealloc
{
    /* null pointer check */
    if(_proc != NULL)
    {
        kvo_release(_proc);
    }
}

@end
