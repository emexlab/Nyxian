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

#import <LindChain/ProcEnvironment/PEExtension.h>
#import <LindChain/ProcEnvironment/Surface/surface.h>
#import <LindChain/ProcEnvironment/PEMachPort.h>
#import <LindChain/ProcEnvironment/Server/Server.h>
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/PELaunchServiceManager.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <ksurface_config.h>
#import <objc/runtime.h>

static const char kNSExtensionKey;
static const char kIdentifierKey;

@implementation FBProcess (ProcEnvironment)

- (NSString *)nsExtension
{
    return objc_getAssociatedObject(self, &kNSExtensionKey);
}

- (void)setNsExtension:(NSString *)nsExtension
{
    objc_setAssociatedObject(self, &kNSExtensionKey, nsExtension, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (NSString *)identifier
{
    return objc_getAssociatedObject(self, &kIdentifierKey);
}

- (void)setIdentifier:(NSString *)identifier
{
    objc_setAssociatedObject(self, &kIdentifierKey, identifier, OBJC_ASSOCIATION_COPY_NONATOMIC);
}

@end

NSBundle *PEGetLiveProcessBundle(void)
{
    static NSBundle *liveProcessBundle = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        liveProcessBundle = [NSBundle bundleWithPath:[NSBundle.mainBundle.builtInPlugInsPath stringByAppendingPathComponent:@"LiveProcess.appex"]];
    });
    return liveProcessBundle;
}

NSExtension *PEGetNSExtension(void)
{
    NSBundle *liveProcessBundle = PEGetLiveProcessBundle();
    if(liveProcessBundle == nil)
    {
        return nil;
    }
    
    /* must be one NSExtension per process, idk.. the class is weirdly designed */
    NSError* error = nil;
    NSExtension* extension = [NSExtension extensionWithIdentifier:liveProcessBundle.bundleIdentifier error:&error];
    if(error)
    {
        return nil;
    }
    extension.preferredLanguages = @[];
    return extension;
}

BOOL PEExtensionHasGetTaskAllowed(void)
{
    static BOOL hasGetTaskAllowed = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        PKHostPlugIn *plugin = [PEGetNSExtension() _plugIn];
        NSDictionary *entitlements = [plugin entitlements];
        NSNumber *getTaskAllowed = [entitlements objectForKey:@"get-task-allow"];
        hasGetTaskAllowed = [getTaskAllowed isKindOfClass:[NSNumber class]] && [getTaskAllowed boolValue];
    });
    return hasGetTaskAllowed;
}

FBProcess *PESpawnFBProcess(NSDictionary *items,
                            pid_t *processIdentifier,
                            int *processIdentifierVersion)
{
    assert(items != nil);
    
    NSExtension *extension = PEGetNSExtension();
    
    /* insert required items */
    NSMutableDictionary *mutableItems = [items mutableCopy];
    PEMachPort *syscallPort = [PEMachPort portWithPortName:syscall_server_get_port(ksurface->sys_server)];
    [syscallPort setSendOnce:YES];
    mutableItems[@"PESyscallPort"] = syscallPort;
    mutableItems[@"PEEndpoint"] = [Server getTicket];   /* MARK: deprecated and soon replaced with the syscall server entirely */
    NSMutableDictionary *env = [mutableItems[@"PEEnvironment"] mutableCopy];
    if(env == nil)
    {
        env = [NSMutableDictionary dictionary];
    }
    NSDictionary *defaults = @{
        @"HOME": [[[NXBootstrap shared] rootfsURL] path],
        @"CFFIXED_USER_HOME": [[[NXBootstrap shared] rootfsURL] path],
        @"TMPDIR": [[[[NXBootstrap shared] rootfsURL] URLByAppendingPathComponent:@"tmp"] path],
        @"NXROOT": [[[NXBootstrap shared] rootfsURL] path],
    };
    for(NSString *key in defaults)
    {
        if(env[key] == nil)
        {
            env[key] = defaults[key];
        }
    }
    mutableItems[@"PEEnvironment"] = env;
    
#if DEBUG && KSURFACE_KLOG_ENABLE_PROCESSES
    if(![mutableItems valueForKey:@"PEFileTable"])
    {
        extern int kfd;
        PEFileTable *fileTable = [PEFileTable emptyTable];
#if KSURFACE_PROCESSLOGGING_REDIRECT_STD
        [fileTable appendFileDescriptor:STDOUT_FILENO withMappingToLoc:STDOUT_FILENO];
        [fileTable appendFileDescriptor:STDERR_FILENO withMappingToLoc:STDERR_FILENO];
#else
        [fileTable appendFileDescriptor:kfd withMappingToLoc:STDOUT_FILENO];
        [fileTable appendFileDescriptor:kfd withMappingToLoc:STDERR_FILENO];
#endif /* KSURFACE_PROCESSLOGGING_REDIRECT_STD */
        [mutableItems setObject:fileTable forKey:@"PEFileTable"];
    }
#endif /* DEBUG && KSURFACE_KLOG_ENABLE_PROCESSES */
    
    NSExtensionItem *item = [NSExtensionItem new];
    item.userInfo = mutableItems;
    
    /*
     * invoke execution (if apple wrote this then
     * it wont hang most likely, apple please handle
     * the case where extension invoke takes too long).
     * isint that the moment in movies where exactly
     * something unexpected like that is the case.. ugh
     */
    NSError *error;
    NSUUID *identifier = [extension beginExtensionRequestWithInputItems:@[item] error:&error];
    if(error != nil || identifier == nil)
    {
        [extension _kill:SIGKILL];
        return nil;
    }
    
    /*
     * checking if process is still valid
     * we need its BSD process identifier.
     */
    pid_t pid = [extension pidForRequestIdentifier:identifier];
    if(pid <= 0)
    {
        [extension _kill:SIGKILL];
        return nil;
    }
    
    /* next step is creation of FBProcess */
    RBSProcessPredicate* predicate = [PrivClass(RBSProcessPredicate) predicateMatchingIdentifier:@(pid)];
    RBSProcessHandle *processHandle = [PrivClass(RBSProcessHandle) handleForPredicate:predicate error:&error];
    if(processHandle == nil || error != nil)
    {
        [extension _kill:SIGKILL];
        return nil;
    }
    
    audit_token_t at = processHandle.auditToken;    /* entry to validation */
    if(at.val[5] != pid)
    {
        [extension _kill:SIGKILL];
        return nil;
    }
    
    if(processIdentifier)
    {
        *processIdentifier = at.val[5];
    }
    if(processIdentifierVersion)
    {
        *processIdentifierVersion = at.val[7];
    }
    
    FBProcessManager *manager = [PrivClass(FBProcessManager) sharedInstance];
    FBProcess *process = [manager registerProcessForAuditToken:processHandle.auditToken];
    if(process == nil)
    {
        [extension _kill:SIGKILL];
        return nil;
    }
    
    process.nsExtension = extension;
    process.identifier = identifier;
    
    return process;
}
