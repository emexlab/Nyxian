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
#import <MobileDevelopmentKit/MobileDevelopmentKit.h>
#import <LiveProcessLegacy/LPLService.h>
#import <LiveProcessLegacy/LPLServiceProtocol.h>
#import <LiveProcessLegacy/LPLVRoot.h>

static NSString *ubid = nil;
static MDKDependencyScanner *dependencyScanner = nil;

@protocol NXCompilationServiceProtocol <NSObject>

- (void)executeJob:(MDKJob*)job withReply:(void (^)(BOOL success, NSArray<MDKDiagnostic*> *diagnostics, NSString *mainSource))reply;
- (void)setupDependencyScannerWithArguments:(NSArray<NSString*>*)arguments withReply:(void (^)(BOOL success))reply;
- (void)headersForFile:(MDKFile*)file withReply:(void (^)(NSArray<MDKFile*> *files))reply;
- (void)dependenciesForFile:(MDKFile*)file withReply:(void (^)(BOOL success, NSArray<MDKFile*> *files, NSArray<MDKDependency*> *dependencies))reply;

@end

@interface NXCompilationService : NSObject <NXCompilationServiceProtocol,PEServiceProtocol>
@end

@implementation NXCompilationService

- (void)executeJob:(MDKJob*)job
         withReply:(void (^)(BOOL success, NSArray<MDKDiagnostic*> *diagnostics, NSString *mainSource))reply
{
    MDKPthreadDispatch(^{
        NSArray<MDKDiagnostic*> *diagnostic = nil;
        NSString *mainSource = nil;
        BOOL success = [job executeJobWithOutDiagnostics:&diagnostic withOutMainSource:&mainSource];
        reply(success, diagnostic, mainSource);
    });
}

- (void)setupDependencyScannerWithArguments:(NSArray<NSString*>*)arguments
                                  withReply:(void (^)(BOOL success))reply
{
    dependencyScanner = [MDKDependencyScanner dependencyScannerWithArguments:arguments];
    if(dependencyScanner == nil)
    {
        reply(NO);
        return;
    }
    reply(YES);
}

- (void)headersForFile:(MDKFile*)file
             withReply:(void (^)(NSArray<MDKFile*> *files))reply
{
    MDKPthreadDispatch(^{
        reply([dependencyScanner headerFilesForFile:file]);
    });
}

- (void)dependenciesForFile:(MDKFile*)file
                  withReply:(void (^)(BOOL success, NSArray<MDKFile*> *files, NSArray<MDKDependency*> *dependencies))reply
{
    MDKPthreadDispatch(^{
        NSArray<MDKFile*> *outHeaders = nil;
        NSArray<MDKDependency*> *outDependencies = nil;
        BOOL didSucceed = [dependencyScanner dependenciesForFile:file withHeaderFilePaths:&outHeaders withDependencies:&outDependencies];
        reply(didSucceed, outHeaders, outDependencies);
    });
}

- (void)clientDidConnectWithConnection:(NSXPCConnection *)client
{
    return;
}

+ (Protocol *)observerProtocol
{
    return nil;
}

+ (NSString *)servcieIdentifier
{
    return ubid;
}

+ (Protocol *)serviceProtocol
{
    return @protocol(NXCompilationServiceProtocol);
}

@end

int main(int argc, char **argv)
{
    /* checking permissions */
    if(getuid() != 0 ||
       getgid() != 0)
    {
        if(setreuid(0, 0) != 0)
        {
            return 1;
        }
        if(setregid(0, 0) != 0)
        {
            return 1;
        }
    }
    
    /* getting vroot */
    const char *virtualRootPathCStr = liveshim_vroot();
    if(virtualRootPathCStr == NULL)
    {
        return 1;
    }
    
    NSString *virtualRootPath = [NSString stringWithCString:virtualRootPathCStr encoding:NSUTF8StringEncoding];
    if(virtualRootPath == NULL)
    {
        return 1;
    }
    
    NSString *nyxianRootPath = virtualRootPath.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
    if(nyxianRootPath == NULL)
    {
        return 1;
    }
    
    NSString *nyxianTmpDir = [nyxianRootPath stringByAppendingPathComponent:@"tmp"];
    if(nyxianTmpDir == NULL)
    {
        return 1;
    }
    
    /* setting env up */
    if(setenv("HOME", nyxianRootPath.UTF8String, 1) != 0 ||
       setenv("CFFIXED_USER_HOME", nyxianRootPath.UTF8String, 1) != 0)
    {
        return 1;
    }
    
    /* getting unique bootstrap identifier for port */
    const char *uniqueBootstrapRegistryIdentifier = getenv("PEUBID");
    if(uniqueBootstrapRegistryIdentifier == NULL)
    {
        return 1;
    }
    
    ubid = [NSString stringWithCString:uniqueBootstrapRegistryIdentifier encoding:NSUTF8StringEncoding];
    if(ubid == NULL)
    {
        return 1;
    }
    
    /* ready for compilation service =3 */
    return PEServiceMain(argc, argv, [NXCompilationService class]);
}
