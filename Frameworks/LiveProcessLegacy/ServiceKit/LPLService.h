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

#ifndef LPLSERVICE_H
#define LPLSERVICE_H

#import <Foundation/Foundation.h>
#import <LiveProcessLegacy/LPLServiceProtocol.h>

@interface ServiceServer : NSObject <NSXPCListenerDelegate>

@property (nonatomic,strong) Protocol *serverProtocol;
@property (nonatomic,strong) Protocol *observerProtocol;
@property (nonatomic,strong) Class instanceClass;
@property (nonatomic,strong) id instance;
@property (nonatomic,strong) NSXPCListener *listener;
@property (nonatomic) dispatch_once_t anonymousCraftOnce;
@property (nonatomic) NSMutableArray<NSXPCConnection*> *clients;

- (instancetype)initWithClass:(Class)instanceClass withServerProtocol:(Protocol *)serverProtocol withObserverProtocol:(Protocol *)observerProtocol;
+ (instancetype)sharedService;

- (NSXPCListenerEndpoint*)getEndpointForConnection;

@end

int PEServiceMain(int argc, char *argv[], Class<PEServiceProtocol> serviceClass);

#endif /* LPLSERVICE_H */
