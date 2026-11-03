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

#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/Shims/proxy.h>
#include <signal.h>
#include <errno.h>
#import <LindChain/ProcEnvironment/Surface/sys/syscall.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <ksurface_config.h>

#define PROXY_TYPE_REPLY(type) ^(void (^reply)(type))

NSObject<ServerProtocol> *hostProcessProxy = nil;

static int64_t sync_call_int64(void (^invoke)(void (^reply)(int64_t)))
{
    __block int64_t result = -1;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    invoke(^(int64_t val){
        result = val;
        dispatch_semaphore_signal(sem);
    });
    
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return result;
}

int64_t environment_proxy_spawn_process_at_path(NSString *path,
                                                NSArray *arguments,
                                                NSDictionary *environment,
                                                PEFileTable *fileTable,
                                                NSString *workingDirectory,
                                                short spawnFlags,
                                                pid_t spawnPgroup)
{
    return sync_call_int64(PROXY_TYPE_REPLY(int64_t){
        [hostProcessProxy spawnProcessWithPath:path withArguments:arguments withEnvironmentVariables:environment withFileTable:fileTable withWorkingDirectory:workingDirectory withSpawnFlags:spawnFlags withSpawnPgroup:spawnPgroup withReply:reply];
    });
}

void environment_proxy_set_snapshot(UIImage *snapshot)
{
    [hostProcessProxy setSnapshot:snapshot];
}
