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

#ifndef LDEAPPLICATIONWORKSPACESERVICE_H
#define LDEAPPLICATIONWORKSPACESERVICE_H

#import <Foundation/Foundation.h>
#if __has_include(<LiveProcessLegacy/LPLService.h>)
#import <LiveProcessLegacy/LPLService.h>
#import <LindChain/ProcEnvironment/PEArchiveHandle.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationObject.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceObserver.h>

@protocol LDEApplicationWorkspaceService

@required
- (void)ping;

- (void)openApplicationWithBundleID:(NSString*)bundleIdentifier withReply:(void (^)(BOOL))reply;

- (void)installApplicationWithArchiveHandle:(PEArchiveHandle*)archiveHandle withReply:(void (^)(BOOL))reply;
- (void)deleteApplicationWithBundleID:(NSString*)bundleID withReply:(void (^)(BOOL))reply;
- (void)applicationInstalledWithBundleID:(NSString*)bundleID withReply:(void (^)(BOOL))reply;
- (void)applicationObjectForBundleID:(NSString*)bundleID withReply:(void (^)(LDEApplicationObject*))reply;
- (void)applicationContainerForBundleID:(NSString*)bundleID withReply:(void (^)(NSURL*))reply;
- (void)clearContainerForBundleID:(NSString*)bundleID withReply:(void (^)(BOOL))reply;
- (void)fastpathUtility:(PEFileHandle*)object withName:(NSString*)name withReply:(void (^)(NSString*,BOOL))reply;
- (void)applicationObjectForExecutablePath:(NSString*)executablePath withReply:(void (^)(LDEApplicationObject*))reply;
- (void)utilityHomePathWithReply:(void (^)(NSString*))reply;

@end

@interface LDEApplicationWorkspaceService : NSObject <LDEApplicationWorkspaceService,PEServiceProtocol>
@end

#endif /* __has_include(<LiveShim/Service.h>) */

#endif /* LDEAPPLICATIONWORKSPACESERVICE_H */
