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

#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceService.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceInternal.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/Utils/vnode.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <ksurface_abi.h>

@implementation LDEApplicationWorkspaceService

- (instancetype)init
{
    self = [super init];
    if(self)
    {
        [LDEApplicationWorkspaceInternal shared];
    }
    return self;
}

- (void)ping
{
    return;
}

- (void)openApplicationWithBundleID:(NSString*)bundleIdentifier
                          withReply:(void (^)(BOOL))reply
{
    if(liveshim_syscall(SYS_pectl, kPECTLCategoryUserInterface, kPECTLUserInterfaceOpenBundleIdentifier, [bundleIdentifier UTF8String], NULL, MACH_PORT_NULL) != 0)
    {
        reply(NO);
        return;
    }
    reply(YES);
}

- (void)utilityHomePathWithReply:(void (^)(NSString*))reply
{
    NSString *homePath = [NSHomeDirectory() stringByAppendingPathComponent:@"/var/mobile"];
    
    NSURL *homeURL = [NSURL fileURLWithPath:homePath];
    
    if(homeURL == nil)
    {
        reply(nil);
        return;
    }
    
    /* checking if homepath is indeed existing */
    BOOL isDirectory = NO;
    if(![[NSFileManager defaultManager] fileExistsAtPath:[homeURL path] isDirectory:&isDirectory])
create_home:
    {
        NSError *error = nil;
        [[NSFileManager defaultManager] createDirectoryAtURL:homeURL withIntermediateDirectories:YES attributes:nil error:&error];
        
        if(error != nil)
        {
            reply(nil);
            return;
        }
        
        /* bootstrapping home path */
        [[NSFileManager defaultManager] createDirectoryAtURL:[homeURL URLByAppendingPathComponent:@"Tmp"] withIntermediateDirectories:YES attributes:nil error:&error];
        
        if(error != nil)
        {
            [[NSFileManager defaultManager] removeItemAtURL:homeURL error:nil];
            reply(nil);
            return;
        }
    }
    else
    {
        /* it shall only be a directory */
        if(!isDirectory)
        {
            [[NSFileManager defaultManager] removeItemAtURL:homeURL error:nil];
            goto create_home;
        }
    }
    
    reply(homePath);
}

- (void)applicationInstalledWithBundleID:(NSString *)bundleID
                               withReply:(void (^)(BOOL))reply {
    reply([[LDEApplicationWorkspaceInternal shared] applicationInstalledWithBundleID:bundleID]);
}

- (void)deleteApplicationWithBundleID:(NSString *)bundleID
                            withReply:(void (^)(BOOL))reply {
    reply([[LDEApplicationWorkspaceInternal shared] deleteApplicationWithBundleID:bundleID]);
}

- (void)installApplicationWithArchiveHandle:(PEArchiveHandle*)archiveHandle
                                  withReply:(void (^)(BOOL))reply {
    /* validate object*/
    if(archiveHandle == NULL)
    {
        reply(NO);
        return;
    }
    
    /* running installation on background queue */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *tempBundle = nil;
        BOOL didInstall = NO;
        
        @try {
            tempBundle = [archiveHandle extractArchive];
            if(tempBundle != NULL)
            {
                didInstall = [[LDEApplicationWorkspaceInternal shared] installApplicationWithPayloadPath:tempBundle];
            }
        } @catch (NSException *exception) {
            NSLog(@"[installd] Exception during install: %@", exception);
            didInstall = NO;
        } @finally {
            if(tempBundle != NULL)
            {
                [fileManager removeItemAtPath:tempBundle error:nil];
            }
            reply(didInstall);
        }
    });
}

- (void)applicationObjectForBundleID:(NSString *)bundleID
                           withReply:(void (^)(LDEApplicationObject *))reply
{
    NSBundle *bundle = [[LDEApplicationWorkspaceInternal shared] applicationBundleForBundleID:bundleID];
    
    if(!bundle)
    {
        reply(nil);
        return;
    }
    
    reply([[LDEApplicationObject alloc] initWithNSBundle:bundle]);
}

- (void)applicationContainerForBundleID:(NSString*)bundleID
                              withReply:(void (^)(NSURL*))reply
{
    reply([[LDEApplicationWorkspaceInternal shared] applicationContainerForBundleID:bundleID]);
}

- (void)clearContainerForBundleID:(NSString *)bundleID
                        withReply:(void (^)(BOOL))reply
{
    reply([[LDEApplicationWorkspaceInternal shared] clearContainerForBundleID:bundleID]);
}

- (void)fastpathUtility:(PEFileHandle*)object
               withName:(NSString*)name
              withReply:(void (^)(NSString*,BOOL))reply;
{
    NSString *fastPath = [[[[LDEApplicationWorkspaceInternal shared] binaryURL] path] stringByAppendingPathComponent:name];
    [[NSFileManager defaultManager] removeItemAtPath:fastPath error:nil];
    [object writeOut:[[[[LDEApplicationWorkspaceInternal shared] binaryURL] path] stringByAppendingPathComponent:name]];
    bool cs_valid = false;
    LCMachO *machO = LCMapMachO(fastPath.fileSystemRepresentation, true);
    if(machO != nil)
    {
        cs_valid = LCCheckCodeSignature(machO);
        LCUnmapMachO(machO);
    }
    if(!cs_valid)
    {
        [[NSFileManager defaultManager] removeItemAtPath:fastPath error:nil];
    }
    else
    {
        vnode_refresh_with_path([fastPath UTF8String]);
    }
    reply(fastPath, cs_valid);
}

- (void)applicationObjectForExecutablePath:(NSString*)executablePath
                                 withReply:(void (^)(LDEApplicationObject*))reply
{
    NSString *potentialBundlePath = [executablePath stringByDeletingLastPathComponent];
    NSBundle *bundle = [NSBundle bundleWithURL:[NSURL fileURLWithPath:potentialBundlePath]];
    if(bundle == nil)
    {
        reply(nil);
        return;
    }
    
    LDEApplicationObject *application = [[LDEApplicationObject alloc] initWithNSBundle:bundle];
    reply(application);
}

+ (NSString*)servcieIdentifier
{
    return @"org.emexlabs.bootstrapd";
}

+ (Protocol*)serviceProtocol
{
    return @protocol(LDEApplicationWorkspaceService);
}

+ (Protocol *)observerProtocol {
    return @protocol(LDEApplicationWorkspaceObserver);
}

- (void)clientDidConnectWithConnection:(NSXPCConnection *)client
{
    id<LDEApplicationWorkspaceObserver> clientObject = client.remoteObjectProxy;
    LDEApplicationWorkspaceInternal *workspace = [LDEApplicationWorkspaceInternal shared];
    __block NSArray<NSBundle *> *snapshot;
    dispatch_sync(workspace.workspaceQueue, ^{
        snapshot = workspace.bundles.allValues;
    });
    for(NSBundle *bundle in snapshot)
    {
        [clientObject applicationWasInstalled:[[LDEApplicationObject alloc] initWithNSBundle:bundle]];
    }
    [clientObject applicationInitialPopulationDone];
}

@end
