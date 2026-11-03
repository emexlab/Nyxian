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

#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/Surface/libkern/relax.h>
#import <LindChain/ProcEnvironment/Surface/libkern/task_handoff.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCBootstrap.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <LiveProcessLegacy/LPLVRoot.h>
#import <LiveProcessLegacy/LPLLSPatchcache.h>
#import <LindChain/Utils/CFTools.h>
#import <ksurface_config.h>
#import <dlfcn.h>
#import <sys/resource.h>
#import <objc/runtime.h>
#include <Frameworks/libpatchfind/libpatchfind.h>

#if !HOST_ENV

#pragma mark - Special client extra symbols

void environment_client_connect_to_host(NSXPCListenerEndpoint *endpoint)
{
    // FIXME: We cannot check the environment if the environment is not setup yet
    if(hostProcessProxy) return;
    NSXPCConnection* connection = [[NSXPCConnection alloc] initWithListenerEndpoint:endpoint];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ServerProtocol)];
    connection.interruptionHandler = ^{
        NSLog(@"Connection to app interrupted");
        exit(0);
    };
    connection.invalidationHandler = ^{
        NSLog(@"Connection to app invalidated");
        exit(0);
    };
    
    [connection activate];
    hostProcessProxy = connection.remoteObjectProxy;
}

void environment_client_connect_to_syscall_proxy(PEMachPort *port)
{
    syscall_client_t *client = liveshim_syscall_client_create([port port]);
    if(client == NULL)
    {
        return;
    }
    syscallProxy = client;
}

#pragma mark - Initilizer

void PEInsertLibrariesIfNeeded(void)
{
    const char *librariesToInsert = getenv("DYLD_INSERT_LIBRARIES");
    if(librariesToInsert == NULL)
    {
        return;
    }
    
    NSString *nsLibrariesToInsert = [NSString stringWithCString:librariesToInsert encoding:NSUTF8StringEncoding];
    NSArray<NSString*> *librariesToInsertArray = [nsLibrariesToInsert componentsSeparatedByString:@":"];
    for(NSString *library in librariesToInsertArray)
    {
        void *handle = dlopen([library UTF8String], RTLD_GLOBAL | RTLD_NOW);
        if(handle == NULL)
        {
            const char *error = dlerror();
            fprintf(stderr, "%s\n", error);
            __builtin_unreachable();
        }
    }
}

static bool cf_main_bundle_slots(uint64_t bundle_off,
                                 uint64_t bundle_inited_off,
                                 CFBundleRef **bundle,
                                 bool **bundle_inited)
{
    Dl_info info;
    if(bundle_off == 0 || bundle_inited_off == 0 ||
       dladdr((const void *)CFBundleGetMainBundle, &info) == 0)
    {
        return false;
    }
    *bundle = (CFBundleRef *)((uintptr_t)info.dli_fbase + bundle_off);
    *bundle_inited = (bool *)((uintptr_t)info.dli_fbase + bundle_inited_off);
    return true;
}

static NSBundle * __unsafe_unretained *ns_main_bundle_slot(uint64_t off)
{
    if(off == 0)
    {
        return NULL;
    }
    Method m = class_getClassMethod(NSBundle.class, @selector(mainBundle));
    Dl_info info;
    if(dladdr((const void *)method_getImplementation(m), &info) == 0)
    {
        return NULL;
    }
    return (NSBundle * __unsafe_unretained *)(void *)((uintptr_t)info.dli_fbase + off);
}

void PEOverwriteExecutablePath(NSString *executablePath)
{
    /* first overwrite executable path */
    LCOverwriteExecutablePath(executablePath);
    
    if(!ksurface_user_patchcache_load())
    {
        /* I'm sorry, I cannot locate the patchcache */
        return;
    }
    
    /* fast CFBundle force reinit */
    CFBundleRef *bundle = NULL;
    bool *inited_bundle = NULL;
    if(!cf_main_bundle_slots(patchcache[kCFBundleMainOffset], patchcache[kCFBundleMainInitedOffset], &bundle, &inited_bundle))
    {
        return;
    }
    *bundle = nil;
    *inited_bundle = false;
    
    /* fast NSBundle force reinit */
    NSBundle * __unsafe_unretained *nsMainBundle = ns_main_bundle_slot(patchcache[kNSBundleMainOffset]);
    *nsMainBundle = nil;
}

int environment_init(EnvironmentExec exec,
                     NSString *executablePath,
                     int argc,
                     char *argv[])
{
    assert(executablePath != nil && argv != NULL);
    
    __block int retval = 0;
    
    /* making sure this is only initilized once */
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        /*
         * iOS usually only allows us to have 200~ ish
         * files opened, we need to bypass that by raising
         * the rlimit.
         */
        struct rlimit rl;
        if(getrlimit(RLIMIT_NOFILE, &rl) == 0)
        {
            rlim_t target = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > 65536) ? 65536 : rl.rlim_max;
            if(rl.rlim_cur < target)
            {
                struct rlimit want = rl;
                want.rlim_cur = target;
                if(setrlimit(RLIMIT_NOFILE, &want) != 0)
                {
                    want.rlim_cur = 10240;
                    if(want.rlim_max != RLIM_INFINITY && want.rlim_max < want.rlim_cur)
                    {
                        want.rlim_cur = want.rlim_max;
                    }
                    setrlimit(RLIMIT_NOFILE, &want);
                }
            }
        }
        
        /*
         * initializing subsystems of the guest, basically
         * fixes apple API's that usually wouldn't work in
         * jailed iOS, constructing a new reality in which
         * processes have capabilities on other processes
         * that exist within the same reality.
         */
        environment_posix_spawn_init();
        environment_vfork_init();
        environment_application_init();
        
        /*
         * since PEProcess needs to register this process
         * first, we gonna have to wait.
         * TODO: create something like a process placeholder to confirm that spawning processes is allowed otherwise a forkbomb would cause continious killing and spawning of NXExtension child
         */
        for(unsigned attempt = 0; liveshim_syscall(SYS_getppid) < 0; attempt++)
        {
            /*
             * every attempt is a round trip through the host's syscall
             * workers, which every other process needs too. registration
             * usually lands within a few attempts, after that back off.
             */
            if(attempt < 32)
            {
                relax();
            }
            else
            {
                usleep(100);
            }
        }
        
        /* handoffs task port */
        task_handoff(MACH_PORT_NULL, NULL);
        
        /*
         * since this is not XNU spawning the process
         * directly for us using fork() + exec() the
         * executable path will be off, so we'll have
         * to overwrite it our selves, basically its
         * a puppet theater show where we present what
         * the executable it self and other executables
         * expect of the values to be.
         */
        PEOverwriteExecutablePath(executablePath);
        
        /* technically this could be a DYLD_INSERT_LIBRARIES */
        const char *vroot = liveshim_vroot();
        if(vroot != NULL)
        {
            char rtpatchPath[PATH_MAX];
            snprintf(rtpatchPath, sizeof(rtpatchPath), "%s/boot/rtpatch", vroot);
            if(access(rtpatchPath, R_OK) == 0)
            {
                /* now load the runtime patch! */
                void *handle = dlopen(rtpatchPath, RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
                if(handle == NULL)
                {
                    const char *error = dlerror();
                    fprintf(stderr, "%s\n", error);
                    __builtin_unreachable();
                }
            }
        }
        
        PEInsertLibrariesIfNeeded();
        
        /* invoking code execution or let it return */
        if(exec == EnvironmentExecLiveContainer)
        {
            retval = LCBootstrapMain(executablePath, argc, argv);
        }
    });
    
    return retval;
}

#endif /* !HOST_ENV */
