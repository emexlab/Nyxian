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

#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspace.h>
#import <LindChain/Private/FoundationPrivate.h>
#import <LindChain/ProcEnvironment/Server/Server.h>
#import <LindChain/ProcEnvironment/PEArchiveHandle.h>
#import <LindChain/Utils/Zip.h>
#import <os/lock.h>
#if __has_include(<Nyxian-Swift.h>)
#define LIVEPROCESS 0
#import <LindChain/ProcEnvironment/PELaunchServiceManager.h>
#import <LindChain/ProcEnvironment/PEProcessManager.h>
#else
#include <ksurface_config.h>
#include <ksurface_abi.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#define LIVEPROCESS 1
#endif /* __has_include(<Nyxian-Swift.h>) */

@interface LDEApplicationWorkspace ()

@property (nonatomic) dispatch_semaphore_t syncSema;
@property (nonatomic) BOOL syncDone;
@property (nonatomic,strong) NSMutableDictionary<NSString*,LDEApplicationObject*> *applications;

@end

@implementation LDEApplicationWorkspace {
    NSHashTable<id<LDEApplicationWorkspaceObserver>> *_observers;
    os_unfair_lock _lock;
    os_unfair_lock _connectLock;
    os_unfair_lock _applicationsLock;
}

- (instancetype)init
{
    self = [super init];
    if(self)
    {
        _syncSema = dispatch_semaphore_create(0);
        _applications = [[NSMutableDictionary alloc] init];
        _observers = [[NSHashTable alloc] initWithOptions:NSPointerFunctionsWeakMemory | NSPointerFunctionsObjectPointerPersonality capacity:0];
        _lock = OS_UNFAIR_LOCK_INIT;
        _connectLock = OS_UNFAIR_LOCK_INIT;
        _applicationsLock = OS_UNFAIR_LOCK_INIT;
    }
    return self;
}

+ (instancetype)shared
{
    static LDEApplicationWorkspace *applicationWorkspaceSingleton = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        applicationWorkspaceSingleton = [[LDEApplicationWorkspace alloc] init];
    });
    return applicationWorkspaceSingleton;
}

- (BOOL)connect
{
    os_unfair_lock_lock(&_connectLock);
    if(_connection != NULL)
    {
        os_unfair_lock_unlock(&_connectLock);
        return YES;
    }
    
#if !LIVEPROCESS
    PELaunchServiceManager *serviceManager = [PELaunchServiceManager shared];
    _connection = [serviceManager connectToService:@"org.emexlabs.bootstrapd" protocol:@protocol(LDEApplicationWorkspaceService) observer:self observerProtocol:@protocol(LDEApplicationWorkspaceObserver)];
    
    os_unfair_lock_lock(&_applicationsLock);
    self.syncDone = NO;
    _syncSema = dispatch_semaphore_create(0);
    [_applications removeAllObjects];
    os_unfair_lock_unlock(&_applicationsLock);
#else
    extern NSObject<OS_xpc_object> *xpc_endpoint_create_mach_port_4sim(mach_port_t port);
    
    mach_port_t bootstrapd_port;
    if(liveshim_syscall(SYS_pectl, kPECTLCategoryLaunchService, kPECTLLaunchServiceGetEndpoint, "org.emexlabs.bootstrapd", NULL, MACH_PORT_NULL, &bootstrapd_port) != 0)
    {
        NSLog(@"failed looking up org.emexlabs.bootstrapd port: %s", strerror(errno));
        dispatch_semaphore_signal(_syncSema);   /* no permission */
        os_unfair_lock_unlock(&_connectLock);
        return NO;
    }
    
    NSXPCListenerEndpoint *endpoint = [[NSXPCListenerEndpoint alloc] init];
    endpoint._endpoint = xpc_endpoint_create_mach_port_4sim(bootstrapd_port);
    if(endpoint == nil || endpoint._endpoint == nil)
    {
        NSLog(@"failed craft NSXPCListenerEndpoint for org.emexlabs.bootstrapd port");
        dispatch_semaphore_signal(_syncSema);   /* something terrible happened? */
        os_unfair_lock_unlock(&_connectLock);
        return NO;
    }
    
    _connection = [[NSXPCConnection alloc] initWithListenerEndpoint:endpoint];
    if(_connection)
    {
        _connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(LDEApplicationWorkspaceService)];
        _connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(LDEApplicationWorkspaceObserver)];
        _connection.exportedObject = self;
    }
#endif /* !LIVEPROCESS */
    
    if(_connection)
    {
        __weak typeof(self) weakSelf = self;
        _connection.interruptionHandler = ^{
            [weakSelf disconnect];
        };
        
        _connection.invalidationHandler = ^{
            [weakSelf disconnect];
        };
        
        [_connection resume];
    }
    
    os_unfair_lock_unlock(&_connectLock);
    
    os_unfair_lock_lock(&_applicationsLock);
    self.syncDone = NO;
    _syncSema = dispatch_semaphore_create(0);
    [_applications removeAllObjects];
    os_unfair_lock_unlock(&_applicationsLock);
    return _connection != nil;
}

- (void)disconnect
{
    os_unfair_lock_lock(&_connectLock);
    [_connection invalidate];
    _connection = nil;
    os_unfair_lock_unlock(&_connectLock);
    
    os_unfair_lock_lock(&_applicationsLock);
    if(!self.syncDone)
    {
        self.syncDone = YES;
        [_applications removeAllObjects];
        dispatch_semaphore_signal(_syncSema);
    }
    os_unfair_lock_unlock(&_applicationsLock);
}

- (void)ping
{
    [self connect];
    
    [_connection.remoteObjectProxy ping];
}

- (BOOL)openApplicationWithBundleID:(NSString*)bundleIdentifier
{
    [self connect];
    
    __block BOOL result = NO;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [proxy openApplicationWithBundleID:bundleIdentifier withReply:^(BOOL replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    if(failed)
    {
        [self disconnect];
        return NO;
    }
    return result;
}

- (BOOL)installApplicationAtBundlePath:(NSString*)bundlePath
{
    [self connect];
    
    __block BOOL result = NO;
    __block BOOL failed = NO;
    PEArchiveHandle *archiveObject = [PEArchiveHandle objectForDirectoryAtPath:bundlePath];
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [proxy installApplicationWithArchiveHandle:archiveObject withReply:^(BOOL replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    if(failed)
    {
        [self disconnect];
        return NO;
    }
    return result;
}

- (BOOL)installApplicationAtPackagePath:(NSString*)packagePath
{
    [self connect];
    
    __block BOOL result = NO;
    __block BOOL failed = NO;
    PEArchiveHandle *handle = [PEArchiveHandle handleForFileAtPath:packagePath];
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [proxy installApplicationWithArchiveHandle:handle withReply:^(BOOL replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    if(failed)
    {
        [self disconnect];
        return NO;
    }
    return result;
}

- (BOOL)deleteApplicationWithBundleID:(NSString *)bundleID
{
    [self connect];
    
    __block BOOL result = NO;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [proxy deleteApplicationWithBundleID:bundleID withReply:^(BOOL replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return NO;
    }
    return result;
}

- (BOOL)applicationInstalledWithBundleID:(NSString *)bundleID
{
    [self connect];
    
    __block BOOL result = NO;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [proxy applicationInstalledWithBundleID:bundleID withReply:^(BOOL replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return NO;
    }
    return result;
}

- (LDEApplicationObject*)applicationObjectForBundleID:(NSString*)bundleID
{
    [self connect];
    
    __block LDEApplicationObject *result = nil;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [_connection.remoteObjectProxy applicationObjectForBundleID:bundleID withReply:^(LDEApplicationObject *replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return nil;
    }
    return result;
}

- (NSArray<LDEApplicationObject*>*)allApplicationObjects
{
    [self connect];
    
    BOOL done;
    os_unfair_lock_lock(&_applicationsLock);
    done = self.syncDone;
    os_unfair_lock_unlock(&_applicationsLock);
    if(!done)
    {
        dispatch_semaphore_wait(self.syncSema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)));
    }
    os_unfair_lock_lock(&_applicationsLock);
    NSArray<LDEApplicationObject*> *applications = [_applications.allValues copy];
    os_unfair_lock_unlock(&_applicationsLock);
    return applications;
}

- (BOOL)clearContainerForBundleID:(NSString *)bundleID
{
    [self connect];
    
    __block BOOL result = NO;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [_connection.remoteObjectProxy clearContainerForBundleID:bundleID withReply:^(BOOL replyResult){
            result = replyResult;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return NO;
    }
    return result;
}

- (NSString*)fastpathUtility:(NSString*)utilityPath
{
    [self connect];
    
    __block NSString *fastpath = nil;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [_connection.remoteObjectProxy fastpathUtility:[PEFileHandle handleForFileAtPath:utilityPath] withName:[utilityPath lastPathComponent] withReply:^(NSString *fastPathRet, BOOL fastSigned){
            fastpath = fastSigned ? fastPathRet : nil;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return nil;
    }
    return fastpath;
}

- (LDEApplicationObject*)applicationObjectForExecutablePath:(NSString*)executablePath
{
    [self connect];
    
    __block LDEApplicationObject *application = nil;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [_connection.remoteObjectProxy applicationObjectForExecutablePath:executablePath withReply:^(LDEApplicationObject *applicationReply){
            application = applicationReply;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return nil;
    }
    return application;
}

- (NSString*)utilityHomePath
{
    [self connect];
    
    __block NSString *utilityHomePath = nil;
    __block BOOL failed = NO;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }];
    
    if(proxy == NULL)
    {
        /* semaphores remember the signal, it doesnt have to catch them in time */
        failed = YES;
        dispatch_semaphore_signal(sema);
    }
    else
    {
        [_connection.remoteObjectProxy utilityHomePathWithReply:^(NSString *reply){
            utilityHomePath = reply;
            dispatch_semaphore_signal(sema);
        }];
    }
    
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
    if(failed)
    {
        [self disconnect];
        return nil;
    }
    return utilityHomePath;
}

- (void)applicationInitialPopulationDone
{
    [self enumerateObservers:^(id<LDEApplicationWorkspaceObserver> observer) {
        [observer applicationInitialPopulationDone];
    }];
    @synchronized(self)
    {
        self.syncDone = YES;
    }
    dispatch_semaphore_signal(self.syncSema);
}

- (void)applicationWasInstalled:(LDEApplicationObject*)app
{
    [self enumerateObservers:^(id<LDEApplicationWorkspaceObserver> observer) {
        [observer applicationWasInstalled:app];
    }];
    os_unfair_lock_lock(&_applicationsLock);
    [self.applications setObject:app forKey:app.bundleIdentifier];
    os_unfair_lock_unlock(&_applicationsLock);
    
}

- (void)applicationWithBundleIdentifierWasUninstalled:(NSString*)bundleIdentifier
{
#if HOST_ENV
    PEProcess *process = [[PEProcessManager shared] processForBundleIdentifier:bundleIdentifier];
    if(process)
    {
        [process forceTerminate];
    }
#endif /* HOST_ENV */
    [self enumerateObservers:^(id<LDEApplicationWorkspaceObserver> observer) {
        [observer applicationWithBundleIdentifierWasUninstalled:bundleIdentifier];
    }];
    os_unfair_lock_lock(&_applicationsLock);
    [self.applications removeObjectForKey:bundleIdentifier];
    os_unfair_lock_unlock(&_applicationsLock);
}

- (void)enumerateObservers:(void (^)(id<LDEApplicationWorkspaceObserver> observer))block
{
    os_unfair_lock_lock(&_lock);
    NSArray<id<LDEApplicationWorkspaceObserver>> *snapshot = _observers.allObjects;
    os_unfair_lock_unlock(&_lock);
    for(id<LDEApplicationWorkspaceObserver> observer in snapshot)
    {
        block(observer);
    }
}

- (void)addObserver:(id<LDEApplicationWorkspaceObserver>)observer
{
    NSParameterAssert(observer);
    os_unfair_lock_lock(&_lock);
    [_observers addObject:observer];
    os_unfair_lock_unlock(&_lock);
}

- (void)removeObserver:(id<LDEApplicationWorkspaceObserver>)observer
{
    os_unfair_lock_lock(&_lock);
    [_observers removeObject:observer];
    os_unfair_lock_unlock(&_lock);
}

@end
