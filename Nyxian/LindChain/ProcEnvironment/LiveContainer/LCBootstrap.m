/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2023 - 2026 LiveContainer
 Copyright (C) 2026 emexlab

 This file is part of LiveContainer.

 LiveContainer is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 LiveContainer is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#import <LindChain/Private/FoundationPrivate.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/utils.h>
#import <LindChain/ProcEnvironment/LiveContainer/Tweaks/DyldHook.h>

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#import <LiveProcessLegacy/LPLLSDyld.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdlib.h>
#import <LindChain/ProcEnvironment/litehook/litehook.h>
#import <LindChain/ProcEnvironment/LiveContainer/Tweaks/Tweaks.h>
#include <mach-o/ldsyms.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationObject.h>
#import <LindChain/ProcEnvironment/Surface/surface.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCBootstrap.h>
#import <malloc/malloc.h>
#import <LindChain/Utils/CFTools.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#include <ksurface_config.h>
#include <ksurface_abi.h>

#import <LindChain/ProcEnvironment/Utils/PEMachOUtils.h>

#include <Frameworks/libpatchfind/libpatchfind.h>

typedef struct {
    void *gap_0x0[2];                  // 0x00, 0x08
    char *mainExecutablePath_old;      // 0x10
    void *gap_0x18;                    // 0x18
    char *mainExecutablePath_18_4;     // 0x20
    size_t mainExecutablePathLen_27_0; // 0x28
} DyldConfig;
typedef struct {
    void *gap_0x0;
    DyldConfig *dyldConfig;
} DyldAPI;

int hook__NSGetExecutablePath_overwriteExecPath(DyldAPI* dyldApiInstancePtr,
                                                char* newPath,
                                                uint32_t* bufsize)
{
    assert(dyldApiInstancePtr != 0);
    DyldConfig* dyldConfig = dyldApiInstancePtr->dyldConfig;
    assert(dyldConfig != 0);
    
    char** mainExecutablePathPtr = 0;
    if(dyldConfig->mainExecutablePath_old != 0 && dyldConfig->mainExecutablePath_old[0] == '/')
    {
        mainExecutablePathPtr = &(dyldConfig->mainExecutablePath_old);
    }
    else if (dyldConfig->mainExecutablePath_18_4 != 0 && dyldConfig->mainExecutablePath_18_4[0] == '/')
    {
        mainExecutablePathPtr = &(dyldConfig->mainExecutablePath_18_4);
    }
    else
    {
        assert(mainExecutablePathPtr != 0);
    }
    
    kern_return_t ret = builtin_vm_protect(mach_task_self(), (mach_vm_address_t)dyldConfig, sizeof(dyldConfig), false, PROT_READ | PROT_WRITE);
    if(ret != KERN_SUCCESS)
    {
        assert(os_tpro_is_supported());
        os_thread_self_restrict_tpro_to_rw();
    }
    *mainExecutablePathPtr = newPath;
    
    if(@available(iOS 27.0, *))
    {
        dyldConfig->mainExecutablePathLen_27_0 = strlen(newPath);
    }
    
    if(ret != KERN_SUCCESS)
    {
        os_thread_self_restrict_tpro_to_ro();
    }
    return 0;
}

void LCOverwriteExecutablePath(NSString *executablePath)
{
    char *buf = strdup(executablePath.fileSystemRepresentation);
    if(buf != NULL)
    {
        /*
         * dyld4 stores executable path in a different place (iOS 15.0 +)
         * https://github.com/apple-oss-distributions/dyld/blob/ce1cc2088ef390df1c48a1648075bbd51c5bbc6a/dyld/DyldAPIs.cpp#L802
         */
        int (*orig__NSGetExecutablePath)(void* dyldPtr, char* buf, uint32_t* bufsize);
        performHookDyldApiFast(kDyldNSGetExecutablePathVTFN, (void**)&orig__NSGetExecutablePath, hook__NSGetExecutablePath_overwriteExecPath);
        _NSGetExecutablePath(buf, NULL);
        performHookDyldApiFast(kDyldNSGetExecutablePathVTFN, nil, orig__NSGetExecutablePath);
        
        /* overwriting remaining upper systems */
        NSString *procName = [executablePath lastPathComponent];
        NSProcessInfo.processInfo.processName = procName;
        
        /* overwriting more CF shit */
        const char *slash = strrchr(buf, '/');
        *_CFGetProgname() = slash ? (char *)slash + 1 : buf;
        *_CFGetProcessPath() = buf;
        
        /* swift needs it too */
        Class swiftNSProcessInfo = NSClassFromString(@"_NSSwiftProcessInfo");
        if(swiftNSProcessInfo)
        {
            /* swizzle the arguments method to return the ObjC arguments */
            SEL selector = @selector(arguments);
            method_setImplementation(class_getInstanceMethod(swiftNSProcessInfo, selector), class_getMethodImplementation(NSProcessInfo.class, selector));
        }
    }
}

void dyld_verifier_failed_callback(int fd,
                                   bool *deny_open)
{
    /* rolling back */
    if(liveshim_syscall(SYS_pectl, kPECTLCategoryCodeSigning, kPECTLCodeSigningDropAllEntitlements, NULL, NULL, MACH_PORT_NULL) != 0 ||
       liveshim_syscall(SYS_setgid, 501) != 0 ||
       liveshim_syscall(SYS_setuid, 501) != 0)
    {
        /* didn't succeed in rolling back primitives, trying to make dlopen fail */
        *deny_open = true;
    }
}

int LCBootstrapMain(NSString *executablePath,
                    int argc,
                    char *argv[])
{
    if(executablePath == nil)
    {
        return 1;
    }
    
    /* preload executable to bypass RT_NOLOAD */
    static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
    os_unfair_lock_lock(&lock);
    
    int64_t ret = -1;
    char cdhash[USER_FSIGNATURES_CDHASH_LEN];
    static atomic_flag initialSpawnFlag = ATOMIC_FLAG_INIT;
    bool initialSpawn = atomic_flag_test_and_set(&initialSpawnFlag);
    if(!initialSpawn)
    {
        ret = liveshim_syscall(SYS_pectl, kPECTLCategoryCodeSigning, kPECTLCodeSigningGetCDHash, cdhash, NULL, MACH_PORT_NULL);
    }
    appMainImageIndex = _dyld_image_count();
    /* makes sure the binary gets loaded that is meant to have the ksurface capabilities */
    int flags = RTLD_LAZY | RTLD_GLOBAL | RTLD_FIRST | RTLD_NODELETE;
    void *guestHandle = ret != 0 ? dlopen(executablePath.fileSystemRepresentation, flags) : dlopen_cdhash_verified(executablePath.fileSystemRepresentation, flags, cdhash, dyld_verifier_failed_callback);
    appExecutableHandle = guestHandle;
    if(!guestHandle || (uint64_t)guestHandle > 0xf00000000000)
    {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }
    
    /* find main */
    int (*guestMain)(int, char**, char **, const char *) = PEGetMachOEntryPointOfHeader(guestHandle)?: dlsym(guestHandle, "main");
    assert(guestHandle != NULL);
    
    /* mark the bundle as executable. */
    CFBundleSetBinaryType(CFBundleGetMainBundle(), __CFBundleDYLDExecutableBinary);
    
    /* now applying LC hooks */
    if(!initialSpawn)
    {
        NUDGuestHooksInit();    /* FIXME: this is a 20ms bottleneck */
        NSFMGuestHooksInit();
        UIKitGuestHooksInit();
        initDead10ccFix();
        DyldHooksInit();
    }
    
    extern char **environ;
    return guestMain(argc, argv, environ, executablePath.fileSystemRepresentation);
}
