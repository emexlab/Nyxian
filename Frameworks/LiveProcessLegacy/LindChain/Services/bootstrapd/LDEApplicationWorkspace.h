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

#ifndef LDEAPPLICATIONWORKSPACEPROXY_H
#define LDEAPPLICATIONWORKSPACEPROXY_H

#import <Foundation/Foundation.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceObserver.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationObject.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceService.h>

@interface LDEApplicationWorkspace : NSObject <LDEApplicationWorkspaceObserver>

@property (nonatomic,strong) NSXPCConnection *connection;

- (instancetype)init;
+ (instancetype)shared;

- (void)ping;

- (BOOL)openApplicationWithBundleID:(NSString*)bundleIdentifier;

- (BOOL)installApplicationAtBundlePath:(NSString*)bundlePath;
- (BOOL)installApplicationAtPackagePath:(NSString*)packagePath;
- (BOOL)deleteApplicationWithBundleID:(NSString*)bundleID;
- (BOOL)applicationInstalledWithBundleID:(NSString*)bundleID;
- (LDEApplicationObject*)applicationObjectForBundleID:(NSString*)bundleID;
- (NSArray<LDEApplicationObject*>*)allApplicationObjects;
- (BOOL)clearContainerForBundleID:(NSString*)bundleID;
- (NSString*)fastpathUtility:(NSString*)utilityPath;
- (LDEApplicationObject*)applicationObjectForExecutablePath:(NSString*)executablePath;
- (NSString*)utilityHomePath;

- (void)addObserver:(id<LDEApplicationWorkspaceObserver>)observer;
- (void)removeObserver:(id<LDEApplicationWorkspaceObserver>)observer;

@end

#endif /* LDEAPPLICATIONWORKSPACEPROXY_H */
