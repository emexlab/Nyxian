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

#import <LiveProcessLegacy/LPLSyscall.h>
#import <LiveProcessLegacy/LPLService.h>
#import <Nyxian/LindChain/ProcEnvironment/Server/Server.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <ksurface_config.h>
#include <ksurface_abi.h>

static ServiceServer *singletonServiceServer = nil;

@implementation ServiceServer

- (instancetype)initWithClass:(Class)instanceClass
           withServerProtocol:(Protocol *)serverProtocol
         withObserverProtocol:(Protocol *)observerProtocol
{
    assert(instanceClass != NULL && serverProtocol != NULL);
    
    self = [super init];
    if(self)
    {
        _serverProtocol = serverProtocol;
        _observerProtocol = observerProtocol;
        _instanceClass = instanceClass;
        
        _listener = [[NSXPCListener alloc] init];
        _clients = [[NSMutableArray alloc] init];
        _instance = [[_instanceClass alloc] init];
        if(_listener == NULL || _clients == NULL || _instance == NULL)
        {
            return NULL;
        }
        
        singletonServiceServer = self;
    }
    return self;
}

+ (instancetype)sharedService
{
    return singletonServiceServer;
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
{
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:_serverProtocol];
    newConnection.exportedObject = _instance;
    newConnection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:_observerProtocol];
    [self.clients addObject:newConnection];
    [newConnection resume];
    [_instance clientDidConnectWithConnection:newConnection];
    return YES;
}

- (NSXPCListenerEndpoint*)getEndpointForConnection
{
    dispatch_once(&_anonymousCraftOnce, ^{
        _listener = [NSXPCListener anonymousListener];
        _listener.delegate = self;
        [_listener resume];
    });
    return _listener.endpoint;
}

@end

int PEServiceMain(int argc,
                  char *argv[],
                  Class<PEServiceProtocol> serviceClass)
{
    __block int ret = -1;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *serviceIdentifier = [serviceClass servcieIdentifier];
        Protocol *serviceProtocol = [serviceClass serviceProtocol];
        Protocol *clientProtocol = [serviceClass observerProtocol];
        
        if(serviceIdentifier != nil && serviceProtocol != nil)
        {
            ServiceServer *serviceServer = [[ServiceServer alloc] initWithClass:serviceClass withServerProtocol:serviceProtocol withObserverProtocol:clientProtocol];
            if(serviceServer == NULL)
            {
                return;
            }
            
            NSXPCListenerEndpoint *endpoint = [serviceServer getEndpointForConnection];
            mach_port_t port = xpc_endpoint_copy_listener_port_4sim(endpoint._endpoint);
            if(port == MACH_PORT_NULL)
            {
                return;
            }
            
            kern_return_t kr = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1);
            if(kr != KERN_SUCCESS)
            {
                return;
            }
            
            if(liveshim_syscall(SYS_pectl, kPECTLCategoryLaunchService, kPECTLLaunchServiceSetEndpoint, [serviceIdentifier UTF8String], NULL, port) != 0)
            {
                return;
            }
            
            ret = 1;
            CFRunLoopRun();
        }
    });
    
    return ret;
}
