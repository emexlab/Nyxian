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

#ifndef PRPROCESS_H
#define PRPROCESS_H

#import <Foundation/Foundation.h>
#import <LindChain/Private/FoundationPrivate.h>
#import <LindChain/Private/UIKitPrivate.h>
#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/ProcEnvironment/PEFileTable.h>
#import <LindChain/ProcEnvironment/PEProcessObserver.h>
#import <LindChain/ProcEnvironment/Surface/proc/proc.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>

@interface PEProcess : NSObject <FBProcessObserver>

@property (nonatomic) ksurface_proc_t *proc;

@property (nonatomic,strong) FBProcess *process;
@property (nonatomic,strong) UIImage *snapshot;

@property (nonatomic,strong) LDEApplicationObject *applicationObject;
@property (nonatomic,strong) NSString *bundleIdentifier;
@property (nonatomic,strong) NSString *displayName;
@property (nonatomic,strong) NSString *executablePath;

@property (nonatomic,readonly) pid_t pid;
@property (nonatomic,readonly) int pidv;

- (instancetype)initWithItems:(NSDictionary*)items withKernelSurfaceProcess:(ksurface_proc_t*)proc;

- (void)sendSignal:(int)signal;

- (void)forceTerminate;
- (void)terminate;
- (void)suspend;
- (void)resume;

- (void)addObserver:(id<PEProcessObserver>)observer;
- (void)removeObserver:(id<PEProcessObserver>)observer;

@end

#endif /* PRPROCESS_H */
