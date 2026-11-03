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

#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <LindChain/ProcEnvironment/litehook/litehook.h>
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/Shims/proxy.h>
#import <LindChain/ProcEnvironment/Shims/posix_spawn.h>
#import <LindChain/ProcEnvironment/Surface/surface.h>
#import <LindChain/ProcEnvironment/PEFileTable.h>
#import <LiveProcessLegacy/LPLService.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspaceInternal.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <LiveProcessLegacy/LPLLSDyld.h>
#import <ksurface_config.h>
#include <crt_externs.h>

bool performHookDyldApi(const char* functionName, uint32_t adrpOffset, void** origFunction, void* hookFunction);

static NSExtensionContext *lcExtensionContext;

@interface LiveProcessHandler : NSObject<NSExtensionRequestHandling>

@end

@implementation LiveProcessHandler

- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context
{
    lcExtensionContext = context;
    /* returns control back to LiveContainerMain */
    CFRunLoopStop(CFRunLoopGetMain());
}

@end

extern char **environ;
void clear_environment(void)
{
    while(environ[0] != NULL)
    {
        char *eq = strchr(environ[0], '=');
        if(eq)
        {
            size_t len = eq - environ[0];
            char key[len + 1];
            strncpy(key, environ[0], len);
            key[len] = '\0';
            
            if(unsetenv(key) != 0)
            {
                environ++;
            }
        }
        else
        {
            environ++;
        }
    }
}

void overwriteEnvironmentProperties(NSDictionary *enviroDict)
{
    if(enviroDict)
    {
        clear_environment();
        
        for (NSString *key in enviroDict)
        {
            NSString *value = enviroDict[key];
            setenv([key UTF8String], [value UTF8String], 0);
        }
    }
}

void overwriteArguments(NSArray<NSObject<NSSecureCoding,NSCopying>*> *arguments,
                        int *argc,
                        char ***argv)
{
    assert(argc != NULL && argv != NULL);
    
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"
    [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:arguments ? arguments : @[]];
#pragma clang diagnostic pop
    
    if(!arguments || arguments.count < 1)
    {
        *argc = 0;
        return;
    }
    
    NSInteger count = arguments.count;
    *argc = (int)count;
    
    *argv = malloc(sizeof(char *) * (count + 1));
    for(NSInteger i = 0; i < count; i++)
    {
        NSObject<NSSecureCoding,NSCopying> *arg = arguments[i];
        
        if([arg isKindOfClass:[NSString class]])
        {
            (*argv)[i] = strdup(((NSString*)arg).UTF8String);
        }
    }
    (*argv)[count] = NULL;
}

int LiveProcessMain(int argc, char *argv[])
{
    /* let NSExtensionContext initialize, once it's done it will call CFRunLoopStop */
    CFRunLoopRun();
    NSDictionary *appInfo = [lcExtensionContext.inputItems.firstObject userInfo];
    
#if !DEBUG
    /* destroying payload once MARK: this is removed in debug mode to easier test vulnerabilities  */
    lcExtensionContext = nil;
#endif /* !DEBUG */
    
    NSXPCListenerEndpoint* endpoint = appInfo[@"PEEndpoint"];
    NSString* executablePath = appInfo[@"PEExecutablePath"];
    NSDictionary *environmentDictionary = appInfo[@"PEEnvironment"];
    NSArray *argumentDictionary = appInfo[@"PEArguments"];
    PEFileTable *fileTable = appInfo[@"PEFileTable"];
    PEMachPort *syscallPort = appInfo[@"PESyscallPort"];
    NSString *workingDirectory = appInfo[@"PEWorkingDirectory"];
    
    /*
     * file descriptors first: they are already ours (xpc fds) and need no
     * sandbox extension, this way a failure below reaches the guest's stderr
     * (a TTY or a pipe of the host) instead of vanishing.
     */
    if([fileTable isKindOfClass:[PEFileTable class]])
    {
        /* apply file descriptor map passed from host environment */
        [fileTable apply];
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
    }
    
    /* for the start */
    NSDictionary *filePermissions = appInfo[@"PEFilePermissions"];
    NSUInteger permissionIndex = 0;
    for(NSData *filePermission in filePermissions)
    {
        extern int64_t sandbox_extension_consume(const char *token);
        int64_t handle = sandbox_extension_consume((const char *)filePermission.bytes);
        if(handle < 0)
        {
            fprintf(stderr, "LiveProcess: sandbox extension %lu of %lu could not be consumed (%s), not starting %s\n",
                    (unsigned long)permissionIndex + 1, (unsigned long)filePermissions.count, strerror(errno),
                    executablePath.fileSystemRepresentation ?: "?");
            return 1;
        }
        permissionIndex++;
    }
    
    /* destroy the payload once in for all */
    appInfo = nil;
    
    assert(endpoint != nil && executablePath != nil && syscallPort != nil);
    
    /* setting working directory correctly */
    if(workingDirectory != nil &&
       [workingDirectory isKindOfClass:[NSString class]])
    {
        /* was passed, setting to destination */
        chdir([workingDirectory UTF8String]);
    }
    else
    {
        /* wasnt passed, setting to root */
        chdir([[NSHomeDirectory() stringByAppendingPathComponent:@"/Documents"] UTF8String]);
    }
    
    /*
     * connecting to the host environment which serves
     * the guest environment.
     */
    environment_client_connect_to_host(endpoint);   /* will soon vanish */
    environment_client_connect_to_syscall_proxy(syscallPort);
    
    /* overwriting environment and arguments */
    overwriteEnvironmentProperties(environmentDictionary);
    overwriteArguments(argumentDictionary, &argc, &argv);
    
    /* set libc stuff correctly for constructors */
    *_NSGetArgc() = argc;
    *_NSGetArgv() = argv;
    
    /* set libc stuff correctly for some shell utils */
    if(argv != NULL && *argv != NULL && argv[0] != NULL && argv[0][0] != '\0')
    {
        char *name = strrchr(argv[0], '/');
        *_NSGetProgname() = name != NULL ? name + 1 : argv[0];
    }
    
#if DEBUG
    setenv("DYLD_MMAP_SANDBOX_EXEC_ALLOWED_PATH", dyld_get_mmap_sandbox_map_exec_allowed_path(), 0);
#endif /* DEBUG */
    
    /*
     * path for normal spawns (they go through LC, thanks to
     * Duy Tran and his research <3), anyways this goes through
     * LC and when the main symbol returns then we get its return
     * value which we redirect to the env.
     */
    return environment_init(EnvironmentExecLiveContainer, executablePath, argc, argv);
}

/* this is our fake UIApplicationMain called from _xpc_objc_uimain (xpc_main) */
__attribute__((visibility("default")))
int UIApplicationMain(int argc,
                      char * argv[],
                      NSString * principalClassName,
                      NSString * delegateClassName)
{
    exit(LiveProcessMain(argc, argv));
}

/* literally redirecting UIApplicationMain to our own one */
DEFINE_HOOK(dlsym, void*, (void* dyldApiInstancePtr,
                           void* handle,
                           const char* symbol))
{
    /* checking if process is looking for it */
    if(symbol && !strcmp(symbol, "UIApplicationMain"))
    {
        performHookDyldApi("dlsym", 2, (void**)&orig_dlsym, orig_dlsym);
        return (void*)&UIApplicationMain;   /* should not break jailbreak compatibility */
    }
    
    /* pass it to the real one */
    __attribute__((musttail)) return orig_dlsym(dyldApiInstancePtr, handle, symbol);
}

/* Extension entry point */
CF_EXPORT int NXLegacyExtensionMain(int argc,
                                    char * argv[],
                                    int (*systemExtensionMain)(int, char **))
{
    /* bluntly removing validation entirely (trust ur caller) */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundeclared-selector"
    method_setImplementation(class_getInstanceMethod(NSClassFromString(@"NSXPCDecoder"), @selector(_validateAllowedClass:forKey:allowingInvocations:)), imp_implementationWithBlock(^BOOL(id self, Class cls, NSString *key, BOOL allowingInvocations){
        return YES;
    }));
#pragma clang diagnostic pop
    
    /*
     * hook dlopen to catch UIKit framework load and trick it
     * into thinking that our UIApplicationMain is the real
     * legitimate one
     */
    performHookDyldApi("dlsym", 2, (void**)&ORIG_FUNC(dlsym), HOOK_FUNC(dlsym));
    
    /*
     * call the real NSExtensionMain, which calls
     * then our UIApplicationMain.
     */
    if(systemExtensionMain == NULL) return 1;
    return systemExtensionMain(argc, argv);
}
