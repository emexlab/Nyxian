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

#import "LDEApplicationWorkspaceInternal.h"
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <LindChain/Utils/Zip.h>
#import <Security/Security.h>
#import <LindChain/ProcEnvironment/PEFileTable.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceObserver.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LiveProcessLegacy/LPLLSDyld.h>

@implementation LDEApplicationWorkspaceInternal

- (instancetype)init
{
    self = [super init];
    
    // Setting up paths
    NSString *homeDir = NSHomeDirectory();
    self.applicationsURL = [NSURL fileURLWithPath:[homeDir stringByAppendingPathComponent:@"/var/containers/Bundle/Application"]];
    self.containersURL = [NSURL fileURLWithPath:[homeDir stringByAppendingPathComponent:@"/var/mobile/Containers/Data/Application"]];
    self.binaryURL = [NSURL fileURLWithPath:[homeDir stringByAppendingPathComponent:@"/usr/bin"]];
    setenv("TMPDIR", [NSURL fileURLWithPath:[homeDir stringByAppendingPathComponent:@"/var/mobile/tmp/bootstrapd"]].path.UTF8String, 1);
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    /* just clearing the pk container */
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSString *docContainerPath = [NSString stringWithFormat:@"%s/Documents", dyld_get_mmap_sandbox_map_exec_allowed_path()];
        NSString *tmpContainerPath = [NSString stringWithFormat:@"%s/tmp", dyld_get_mmap_sandbox_map_exec_allowed_path()];
        NSString *libraryContainerPath = [NSString stringWithFormat:@"%s/Library", dyld_get_mmap_sandbox_map_exec_allowed_path()];
        NSError *error;
        NSArray<NSString*> *pkContainerHomeDirectories = [fileManager contentsOfDirectoryAtPath:docContainerPath error:&error];
        for(NSString *dir in pkContainerHomeDirectories)
        {
            NSString *lastPathComponent = [dir lastPathComponent];
            NSString *newPath = [homeDir stringByAppendingPathComponent:lastPathComponent];
            [fileManager removeItemAtPath:newPath error:nil];
        }
        NSArray<NSString*> *pkContainerTmpDirectories = [fileManager contentsOfDirectoryAtPath:tmpContainerPath error:&error];
        for(NSString *dir in pkContainerTmpDirectories)
        {
            NSString *lastPathComponent = [dir lastPathComponent];
            NSString *newPath = [homeDir stringByAppendingPathComponent:lastPathComponent];
            [fileManager removeItemAtPath:newPath error:nil];
        }
        NSArray<NSString*> *pkContainerLibDirectories = [fileManager contentsOfDirectoryAtPath:libraryContainerPath error:&error];
        for(NSString *dir in pkContainerLibDirectories)
        {
            NSString *lastPathComponent = [dir lastPathComponent];
            NSString *newPath = [homeDir stringByAppendingPathComponent:lastPathComponent];
            [fileManager removeItemAtPath:newPath error:nil];
        }
    });
    
    // Enumerating all app bundles
    NSArray<NSURL*> *uuidURLs = [fileManager contentsOfDirectoryAtURL:self.applicationsURL includingPropertiesForKeys:nil options:0 error:nil];
    self.bundles = [[NSMutableDictionary alloc] init];
    for(NSURL *uuidURL in uuidURLs)
    {
        NSArray<NSString *> *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[uuidURL path] error:nil];

        for(NSString *item in contents)
        {
            if([[item pathExtension] isEqualToString:@"app"])
            {
                NSString *fullPath = [[uuidURL path] stringByAppendingPathComponent:item];
                NSBundle *bundle = [NSBundle bundleWithPath:fullPath];
                [self.bundles setObject:bundle forKey:bundle.bundleIdentifier];
            }
            else
            {
                /* what the user cant manage the user cant manage */
                [[NSFileManager defaultManager] removeItemAtURL:uuidURL error:nil];
            }
        }
    }
    
    self.workspaceQueue = dispatch_queue_create("org.emexlabs.bootstrapd.workspace", DISPATCH_QUEUE_SERIAL);
    
    [self purgeTemporaryDirectories];
    [self drainBlastbox];
    
    return self;
}

+ (LDEApplicationWorkspaceInternal*)shared
{
    static LDEApplicationWorkspaceInternal *applicationWorkspaceSingleton = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        applicationWorkspaceSingleton = [[LDEApplicationWorkspaceInternal alloc] init];
    });
    return applicationWorkspaceSingleton;
}

- (BOOL)doWeTrustThatBundle:(NSBundle*)bundle
{
    /*
     * checking for obvious thing lol, and checking for
     * info dictionary, every iOS app needs to have one.
     */
    if(bundle == nil ||
       bundle.infoDictionary == nil)
    {
        return NO;
    }
    
    /* checking if needed info keys exist */
    if(bundle.infoDictionary[@"CFBundleExecutable"] == nil ||
       bundle.infoDictionary[@"CFBundleIdentifier"] == nil)
    {
        return NO;
    }
    
    /* checking if info keys match the correct class type */
    if(![bundle.infoDictionary[@"CFBundleExecutable"] isKindOfClass:[NSString class]] ||
       ![bundle.infoDictionary[@"CFBundleIdentifier"] isKindOfClass:[NSString class]])
    {
        return NO;
    }
    
    /* now extracting key values */
    NSString *bundleIdentifier = bundle.infoDictionary[@"CFBundleIdentifier"];
    NSString *minimumVersion = bundle.infoDictionary[@"MinimumOSVersion"];
    
    /* executable path validation */
    NSString *executableName = bundle.infoDictionary[@"CFBundleExecutable"];
    NSString *lastPathComponent = bundle.executableURL.lastPathComponent;
    
    if(lastPathComponent == nil ||
       ![executableName isEqualToString:lastPathComponent] ||
       ![[NSFileManager defaultManager] isReadableFileAtPath:bundle.executablePath])
    {
        return NO;
    }
    
    /* bundle identifier validation */
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^[a-zA-Z][a-zA-Z0-9-]*(\\.[a-zA-Z0-9-]+)*$" options:0 error:nil];
    if(regex == nil)
    {
        return NO;
    }
    
    NSUInteger matches = [regex numberOfMatchesInString:bundleIdentifier options:0 range:NSMakeRange(0, bundleIdentifier.length)];
    if(matches == 0)
    {
        return NO;
    }
    
    /* minimum version validation */
    if(bundle.infoDictionary[@"MinimumOSVersion"] == nil &&
       ![bundle.infoDictionary[@"MinimumOSVersion"] isKindOfClass:[NSString class]])
    {
        /* some apps like cocoatop dont have that key */
        return YES;
    }
    
    NSArray *components = [minimumVersion componentsSeparatedByString:@"."];
    
    if(components == nil)
    {
        return NO;
    }
    
    NSOperatingSystemVersion requiredVersion = {
        components.count > 0 ? [components[0] integerValue] : 0,
        components.count > 1 ? [components[1] integerValue] : 0,
        components.count > 2 ? [components[2] integerValue] : 0
    };
    
    if(![[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:requiredVersion])
    {
        return NO;
    }
    
    return YES;
}

- (BOOL)installApplicationWithPayloadPath:(NSString*)payloadPath
{
    /* finding installable application bundle in the path */
    NSBundle *bundle = nil;
    NSArray<NSString *> *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:payloadPath error:nil];
    
    for(NSString *item in contents)
    {
        if([[item pathExtension] isEqualToString:@"app"])
        {
            NSString *fullPath = [payloadPath stringByAppendingPathComponent:item];
            bundle = [NSBundle bundleWithPath:fullPath];
            break;
        }
    }
    
    /* bundle validation */
    if(!bundle)
    {
        return NO;
    }
    
    /* next bundle validation */
    if(![self doWeTrustThatBundle:bundle])
    {
        return NO;
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    /* reinstall if such a app is already installed  */
    NSURL *installURL = nil;
    NSBundle *previousApplication = [self applicationBundleForBundleID:[bundle bundleIdentifier]];
    if(previousApplication)
    {
        /* need reinstallation */
        installURL = previousApplication.bundleURL;
        [fileManager removeItemAtURL:installURL error:nil];
        previousApplication = nil;
    }
    else
    {
        /* need new installation */
        installURL = [[self.applicationsURL URLByAppendingPathComponent:[[NSUUID UUID] UUIDString]] URLByAppendingPathComponent:[bundle.bundleURL lastPathComponent]];
    }
    
    /* install it at location */
    if(![fileManager createDirectoryAtURL:[installURL URLByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil] ||
       ![fileManager moveItemAtURL:bundle.bundleURL toURL:installURL error:nil])
    {
        return NO;
    }
    
    /* getting new bundle */
    bundle = [NSBundle bundleWithURL:installURL];
    
    /* checking weither bundle is valid */
    if(bundle == nil)
    {
        return NO;
    }
    
    /* notifying listeners about it */
    [self.bundles setObject:bundle forKey:bundle.bundleIdentifier];
    LDEApplicationObject *object = [[LDEApplicationObject alloc] initWithNSBundle:bundle];
    if(object != nil)
    {
        for(NSXPCConnection *client in [[ServiceServer sharedService] clients])
        {
            [client.remoteObjectProxy applicationWasInstalled:object];
        }
    }
    
    return YES;
}

- (BOOL)deleteApplicationWithBundleID:(NSString *)bundleID
{
    NSBundle *previousApplication = [self applicationBundleForBundleID:bundleID];
    
    if(previousApplication == nil)
    {
        return NO;
    }
    
    LDEApplicationObject *appObject = [[LDEApplicationObject alloc] initWithNSBundle:previousApplication];
    
    if(appObject == nil)
    {
        return NO;
    }
    
    [[NSFileManager defaultManager] removeItemAtURL:[[previousApplication bundleURL] URLByDeletingLastPathComponent] error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:[appObject containerPath] error:nil];
    [self.bundles removeObjectForKey:bundleID];
    
    for(NSXPCConnection *client in [[ServiceServer sharedService] clients])
    {
        [client.remoteObjectProxy applicationWithBundleIdentifierWasUninstalled:appObject.bundleIdentifier];
    }
    
    return YES;
}

- (BOOL)applicationInstalledWithBundleID:(NSString*)bundleID
{
    __block BOOL result = NO;
    dispatch_sync(self.workspaceQueue, ^{
        result = [self.bundles objectForKey:bundleID] ? YES : NO;
    });
    return result;
}

- (NSBundle*)applicationBundleForBundleID:(NSString *)bundleID
{
    __block NSBundle *result = nil;
    dispatch_sync(self.workspaceQueue, ^{
        result = [self.bundles objectForKey:bundleID];
    });
    return result;
}

- (NSURL*)applicationContainerForBundleID:(NSString *)bundleID
{
    /* gathering bundle */
    NSBundle *bundle = [self applicationBundleForBundleID:bundleID];
    if(bundle == nil)
    {
        return nil;
    }
    
    /* checking against container  */
    NSString *uuid = [[bundle.bundleURL URLByDeletingLastPathComponent] lastPathComponent];
    if(uuid == nil)
    {
        return nil;
    }
    
    NSURL *containerURL = [self.containersURL URLByAppendingPathComponent:uuid];
    
    /* creating if it doesnt exist */
    BOOL isDirectory = NO;
    if(![[NSFileManager defaultManager] fileExistsAtPath:[containerURL path] isDirectory:&isDirectory])
create_container:
    {
        NSError *error = nil;
        [[NSFileManager defaultManager] createDirectoryAtURL:containerURL withIntermediateDirectories:YES attributes:nil error:&error];
        if(error != nil)
        {
            return nil;
        }
    }
    else
    {
        /* it shall only be a directory */
        if(!isDirectory)
        {
            [[NSFileManager defaultManager] removeItemAtURL:containerURL error:nil];
            goto create_container;
        }
    }
    
    /* bootstrapping data container */
    NSArray *dirList = @[@"Library/Caches", @"Documents", @"SystemData", @"Tmp"];
    for(NSString *dir in dirList)
    {
        NSError *error = nil;
        [[NSFileManager defaultManager] createDirectoryAtURL:[containerURL URLByAppendingPathComponent:dir] withIntermediateDirectories:YES attributes:nil error:&error];
        if(error != nil)
        {
            [[NSFileManager defaultManager] removeItemAtURL:containerURL error:nil];
            return nil;
        }
    }
    
    return containerURL;
}

- (BOOL)clearContainerForBundleID:(NSString*)bundleID
{
    NSURL *containerURL = [self applicationContainerForBundleID:bundleID];
    [[NSFileManager defaultManager] removeItemAtURL:containerURL error:nil];
    return YES;
}

- (BOOL)blastItemAtURL:(NSURL *)url
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    if(![fileManager fileExistsAtPath:url.path])
    {
        return NO;
    }
    
    NSURL *graveURL = [[NSURL fileURLWithPath:NSTemporaryDirectory()] URLByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    if([fileManager moveItemAtURL:url toURL:graveURL error:nil])
    {
        return YES;
    }
    
    return [fileManager removeItemAtURL:url error:nil];
}

- (void)purgeTemporaryDirectories
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    if([self blastItemAtURL:[NSURL fileURLWithPath:NSTemporaryDirectory()]])
    {
        [fileManager createDirectoryAtURL:[NSURL fileURLWithPath:NSTemporaryDirectory()] withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    NSArray<NSURL *> *containerURLs = [fileManager contentsOfDirectoryAtURL:self.containersURL includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
    for(NSURL *containerURL in containerURLs)
    {
        NSNumber *isDirectory = nil;
        if(![containerURL getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:nil] ||
           !isDirectory.boolValue)
        {
            continue;
        }
        
        NSURL *containerTmpURL = [containerURL URLByAppendingPathComponent:@"Tmp"];
        if([self blastItemAtURL:containerTmpURL])
        {
            [fileManager createDirectoryAtURL:containerTmpURL withIntermediateDirectories:YES attributes:nil error:nil];
        }
    }
}

- (void)drainBlastbox
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        NSFileManager *fileManager = [[NSFileManager alloc] init];
        NSArray<NSURL *> *graves = [fileManager contentsOfDirectoryAtURL:[NSURL fileURLWithPath:NSTemporaryDirectory()] includingPropertiesForKeys:nil options:0 error:nil];
        for(NSURL *grave in graves)
        {
            [fileManager removeItemAtURL:grave error:nil];
        }
    });
}

@end
