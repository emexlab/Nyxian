/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#import <LindChain/ProcEnvironment/PELaunchService.h>
#import <LindChain/ProcEnvironment/PEProcessManager.h>
#import <LindChain/IDEFoundation/NXPlist.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <os/lock.h>
#import <ksurface_config.h>

@interface PELaunchServiceInstance (Private)

- (instancetype)initWithItems:(NSDictionary*)items;

@end

@implementation PELaunchService {
    os_unfair_lock _lock;
    NSXPCListenerEndpoint *_endpoint;
    NSDictionary *_dictionary;
    NSTimeInterval _lastLaunchTime;
    NSUInteger _restartCount;
}

+ (instancetype)launchServiceWithPlistPath:(NSString*)plistPath
{
    return [[self alloc] initWithPlistPath:plistPath];
}

- (instancetype)initWithPlistPath:(NSString*)plistPath
{
    self = [super init];
    if(self)
    {
        _instances = [[NSMutableArray alloc] init];
        _lock = OS_UNFAIR_LOCK_INIT;
        NXPlist *plist = [[NXPlist alloc] initWithPlistPath:plistPath withVariables:@{
            @"NXROOT": NXBootstrap.shared.rootfsURL.path,
            @"BLROOT": NSBundle.mainBundle.bundlePath,
        }];
        
        if(plist == NULL)
        {
            return nil;
        }
        
        _dictionary = plist.dictionary;
        if(_dictionary == NULL)
        {
            return nil;
        }
        
        /* TODO: add sanitization */
        NSMutableDictionary *mutableDictionary = [_dictionary mutableCopy];
        mutableDictionary[@"PEExecutablePath"] = [_dictionary varObjectForKey:@"PEExecutablePath"];
        _dictionary = [mutableDictionary copy];
        _executablePath = _dictionary[@"PEExecutablePath"];
        _serviceIdentifier = _dictionary[@"PEServiceIdentifier"];
        _autoRestart = [((NSNumber*)[_dictionary valueForKey:@"PEShouldAutorestart"]) boolValue];
        _enabled = [((NSNumber*)[_dictionary valueForKey:@"PEEnabled"]) boolValue];
        _isMultiInstanceDaemon = [((NSNumber*)[_dictionary valueForKey:@"PEIsMultiInstanceDaemon"]) boolValue];
        
        if(_executablePath == NULL || _serviceIdentifier == NULL)
        {
            return nil;
        }
        
        if(_enabled)
        {
            if(![self newInstance])
            {
                return nil;
            }
        }
    }
    return self;
}

- (BOOL)isServiceWithServiceIdentifier:(NSString*)serviceIdentifier
{
    return [_serviceIdentifier isEqualToString:serviceIdentifier];
}

- (PELaunchServiceInstance*)newInstance
{
    NSDictionary *items = _dictionary;
    
    NSMutableDictionary *mutable = [_dictionary mutableCopy];
    
    NSString *ubid = [[NSUUID UUID] UUIDString];
    [mutable setObject:ubid forKey:@"PEUBID"];  /* generating unique bootstrap registry identifier */
    NSMutableDictionary *env = [mutable[@"PEEnvironment"] mutableCopy];
    if(env == nil)
    {
        env = [NSMutableDictionary dictionary];
    }
    NSDictionary *defaults = @{
        @"PEUBID": ubid,
    };
    for(NSString *key in defaults)
    {
        if(env[key] == nil)
        {
            env[key] = defaults[key];
        }
    }
    mutable[@"PEEnvironment"] = env;
    
#if DEBUG && KSURFACE_KLOG_ENABLE_DAEMONS
    extern int kfd;
    PEFileTable *fileTable = [PEFileTable emptyTable];
#if KSURFACE_PROCESSLOGGING_REDIRECT_STD
    [fileTable appendFileDescriptor:STDOUT_FILENO withMappingToLoc:STDOUT_FILENO];
    [fileTable appendFileDescriptor:STDERR_FILENO withMappingToLoc:STDERR_FILENO];
#else
    [fileTable appendFileDescriptor:kfd withMappingToLoc:STDOUT_FILENO];
    [fileTable appendFileDescriptor:kfd withMappingToLoc:STDERR_FILENO];
#endif /* KSURFACE_PROCESSLOGGING_REDIRECT_STD */
    mutable[@"PEFileTable"] = fileTable;
#endif /* DEBUG && KSURFACE_KLOG_ENABLE_DAEMONS */
    items = [mutable copy];
    
    os_unfair_lock_lock(&_lock);
    PELaunchServiceInstance *instance = [[PELaunchServiceInstance alloc] initWithItems:items];
    instance.delegate = self;
    
    _lastLaunchTime = NSDate.timeIntervalSinceReferenceDate;
    [self.instances addObject:instance];
    
    if(![instance launch])
    {
        [self.instances removeObject:instance];
        os_unfair_lock_unlock(&_lock);
        return nil;
    }
    os_unfair_lock_unlock(&_lock);
    return instance;
}

- (void)instanceDidExit:(PELaunchServiceInstance *)instance
           withWaitCode:(int)code
{
    os_unfair_lock_lock(&_lock);
    [_instances removeObject:instance];
    if(!self.autoRestart)
    {
        os_unfair_lock_unlock(&_lock);
        return;
    }
    
    NSTimeInterval now = NSDate.timeIntervalSinceReferenceDate;
    if(now - _lastLaunchTime < 1.0)
    {
        _restartCount++;
    }
    else
    {
        _restartCount = 0;
    }
    if(_restartCount > 5)
    {
        os_unfair_lock_unlock(&_lock);
        return;
    }
    os_unfair_lock_unlock(&_lock);
    
    NSTimeInterval delay = MIN(pow(2.0, _restartCount) * 0.1, 30.0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self newInstance];
    });
}

@end
