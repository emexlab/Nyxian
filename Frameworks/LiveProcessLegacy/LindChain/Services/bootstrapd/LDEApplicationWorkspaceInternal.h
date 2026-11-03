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

#ifndef LDEAPPLICATIONWORKSPACE_H
#define LDEAPPLICATIONWORKSPACE_H

#import <Foundation/Foundation.h>
#import "LDEApplicationObject.h"

@interface LDEApplicationWorkspaceInternal : NSObject

@property (nonatomic,strong) NSURL *applicationsURL;
@property (nonatomic,strong) NSURL *containersURL;
@property (nonatomic,strong) NSURL *binaryURL;
@property (nonatomic,strong) dispatch_queue_t workspaceQueue;
@property (atomic,readwrite) NSMutableDictionary<NSString*,NSBundle*> *bundles;

- (instancetype)init;
+ (LDEApplicationWorkspaceInternal*)shared;

- (BOOL)installApplicationWithPayloadPath:(NSString*)bundlePath;
- (BOOL)deleteApplicationWithBundleID:(NSString*)bundleID;
- (BOOL)applicationInstalledWithBundleID:(NSString*)bundleID;
- (NSBundle*)applicationBundleForBundleID:(NSString*)bundleID;
- (NSURL*)applicationContainerForBundleID:(NSString *)bundleID;
- (BOOL)doWeTrustThatBundle:(NSBundle*)bundle;
- (BOOL)clearContainerForBundleID:(NSString*)bundleID;

@end

#endif /* LDEAPPLICATIONWORKSPACE_H */
