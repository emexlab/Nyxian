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
#import <LiveShim/LiveShimSyscall.h>
#import <LiveShim/vroot.h>
#import <LindChain/Utils/CFTools.h>
#import <ksurface_config.h>
#import <dlfcn.h>
#import <sys/resource.h>

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

void PEOverwriteExecutablePath(NSString *executablePath)
{
    /* literally swapping CFBundle CFRuntime instances */
    CFBundleRef currentMainCFBundle = CFBundleGetMainBundle();
    if(currentMainCFBundle == NULL)
    {
        goto skip_to_exec_override;
    }
    CFAllocatorRef allocator = CFGetAllocator(currentMainCFBundle); /* doesnt matter if zero */
    CFURLRef urlRef = CFURLCreateWithFileSystemPath(allocator, (__bridge CFStringRef)[executablePath stringByDeletingLastPathComponent], kCFURLPOSIXPathStyle, true);
    if(urlRef == NULL)
    {
        goto skip_to_exec_override;
    }
    CFBundleRef guestMainCFBundle = CFBundleCreate(allocator, urlRef);
    CFRelease(urlRef);  /* took a reference of it most probably */
    if(guestMainCFBundle == NULL)
    {
        goto skip_to_exec_override;
    }
    
    /*
     * Swaps both bundles simply, not leaking any memory
     * as both internal states are stable by CFRuntime it
     * self we can safely exploit that angle to swap both
     * and release the original bundle. To my knowledge
     * CFBundle also doesn't cary any extra inline
     * buffers but relies on other CF types.
     */
    assert(CFSwap(currentMainCFBundle, guestMainCFBundle));
    CFRelease(guestMainCFBundle);                   /* destroys the real bundle, sounds like swizzling x3 */
    
skip_to_exec_override:
    LCOverwriteExecutablePath(executablePath);
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
        {
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
        }
        
        /*
         * initializing subsystems of the guest, basically
         * fixes apple API's that usually wouldn't work in
         * jailed iOS, constructing a new reality in which
         * processes have capabilities on other processes
         * that exist within the same reality.
         */
        #if KSURFACE_SYS_PROC_ENABLED
        environment_posix_spawn_init();
        environment_vfork_init();
        #endif /* KSURFACE_SYS_PROC_ENABLED */
        environment_application_init();
        
        /*
         * since PEProcess needs to register this process
         * first, we gonna have to wait.
         * TODO: create something like a process placeholder to confirm that spawning processes is allowed otherwise a forkbomb would cause continious killing and spawning of NXExtension child
         */
        while(liveshim_syscall(SYS_getppid) < 0)
        {
            relax();
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
        
        /* loading rtpatch into guest process */
        NSString *nyxianRoot = [NSString stringWithCString:liveshim_vroot() encoding:NSUTF8StringEncoding];
        if(nyxianRoot != NULL)
        {
            NSString *shimPath = [nyxianRoot stringByAppendingString:@"/boot/rtpatch"];
            if([[NSFileManager defaultManager] fileExistsAtPath:shimPath])
            {
                /* now load the shimcache! */
                void *handle = dlopen(shimPath.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
                if(handle == NULL)
                {
                    printf("dlopen: %s\n", dlerror());
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
