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

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#import <LindChain/ProcEnvironment/litehook/litehook.h>
#import "LCMachOUtils.h"
#import "../utils.h"
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/Surface/trust/cdhash.h>
#import <LindChain/ProcEnvironment/LiveContainer/Tweaks/Tweaks.h>
#import <LindChain/ProcEnvironment/LiveContainer/Tweaks/DyldHook.h>
#import <LindChain/Utils/CFTools.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <LiveProcessLegacy/LPLLSPatchcache.h>
#import <LiveProcessLegacy/LPLLSDyld.h>
#import <ksurface_config.h>
#import <ksurface_abi.h>
#import <Broadpatch/Broadpatch.h>
#include <Frameworks/libpatchfind/libpatchfind.h>

static const char *gHostImageNeedles[] = {
    "/Nyxian.app/PlugIns/LiveProcess.appex/LiveProcess",
    "/Nyxian.app/PlugIns/LiveProcess.appex/Frameworks/LiveShim.framework/LiveShim",
    "/mntfs/bootfs/rtpatch"
};

static bool isHostImagePath(const char *path)
{
    if(!path)
    {
        return false;
    }
    for(size_t i = 0; i < sizeof(gHostImageNeedles)/sizeof(*gHostImageNeedles); i++)
    {
        if(strstr(path, gHostImageNeedles[i]))
        {
            return true;
        }
    }
    return false;
}

typedef struct {
    uint32_t platform;
    uint32_t version;
} dyld_build_version_t;

uint32_t lcImageIndex = 0;
uint32_t appMainImageIndex = 0;
uint32_t guestAppSdkVersion = 0;
uint32_t guestAppSdkVersionSet = 0;

void* appExecutableHandle = 0;
void overwriteAppExecutableFileType(void);
static inline bool isHiddenReal(uint32_t r);

DEFINE_HOOK(_dyld_image_count, uint32_t, (void)) {
    if(appMainImageIndex == 0)
    {
        return ORIG_FUNC(_dyld_image_count)();
    }
    uint32_t real = ORIG_FUNC(_dyld_image_count)(), hidden = 0;
    for(uint32_t r = 0; r < real; r++)
    {
        if(isHiddenReal(r))
        {
            hidden++;
        }
    }
    return real - hidden;
}

static uint32_t translateImageIndex(uint32_t guestIndex)
{
    if(appMainImageIndex == 0)
    {
        return guestIndex;
    }
    if(guestIndex == 0)
    {
        overwriteAppExecutableFileType();
        return appMainImageIndex;
    }
    
    uint32_t real = ORIG_FUNC(_dyld_image_count)();
    uint32_t seen = 0;
    for(uint32_t r = 0; r < real; r++)
    {
        if(r == appMainImageIndex)
        {
            continue;
        }
        if(isHiddenReal(r))
        {
            continue;
        }
        if(++seen == guestIndex)
        {
            return r;
        }
    }
    return real ? real - 1 : 0;
}

DEFINE_HOOK(_dyld_get_image_header, const struct mach_header*, (uint32_t image_index))
{
    __attribute__((musttail)) return ORIG_FUNC(_dyld_get_image_header)(translateImageIndex(image_index));
}

DEFINE_HOOK(dlsym, void*, (void * __handle,
                           const char * __symbol))
{
    if(__handle == (void*)RTLD_MAIN_ONLY)
    {
        if(strcmp(__symbol, MH_EXECUTE_SYM) == 0)
        {
            overwriteAppExecutableFileType();
            return (void*)ORIG_FUNC(_dyld_get_image_header)(appMainImageIndex);
        }
        __handle = appExecutableHandle;
    }
    else if (__handle != (void*)RTLD_SELF && __handle != (void*)RTLD_NEXT)
    {
        void* ans = ORIG_FUNC(dlsym)(__handle, __symbol);
        if(!ans)
        {
            return 0;
        }
        for(int i = 0; i < gRebindCount; i++)
        {
            global_rebind rebind = gRebinds[i];
            if(ans == rebind.replacee)
            {
                return rebind.replacement;
            }
        }
        return ans;
    }
    
    __attribute__((musttail)) return ORIG_FUNC(dlsym)(__handle, __symbol);
}

DEFINE_HOOK(_dyld_get_image_vmaddr_slide, intptr_t, (uint32_t image_index))
{
    __attribute__((musttail)) return ORIG_FUNC(_dyld_get_image_vmaddr_slide)(translateImageIndex(image_index));
}

DEFINE_HOOK(_dyld_get_image_name, const char*, (uint32_t image_index))
{
    __attribute__((musttail)) return ORIG_FUNC(_dyld_get_image_name)(translateImageIndex(image_index));
}

static inline bool isHiddenReal(uint32_t r)
{
    if(r == appMainImageIndex)
    {
        return false;
    }
    return isHostImagePath(ORIG_FUNC(_dyld_get_image_name)(r));
}

LIBKERN_PATCH(void *, dlopen_hook, (void* dyldApiInstancePtr,
                                    const char *__path,
                                    int __mode),
{
    /* check CS */
    LCMachO *machO = LCMapMachO(__path, true);
    if(machO == nil)
    {
        /* need to jump forward so that there is a dlerror in the end of the day */
        goto just_try;
    }
    
    bool cs_valid = LCCheckCodeSignature(machO);
    LCUnmapMachO(machO);
    if(!cs_valid)
    {
        /* sign if invalid */
        int fd = open(__path, O_RDWR);
        if(fd >= 0)
        {
            liveshim_syscall(SYS_sign, fd);
            close(fd);
        }
    }
    
just_try:
    /* continue with opening */
    return LIBKERN_ORIG(dlopen_hook)(dyldApiInstancePtr, __path, __mode);
});

bool hook_dyld_program_sdk_at_least(void* dyldApiInstancePtr,
                                    dyld_build_version_t version)
{
    /* we are targeting ios, so we hard code 2 */
    switch(version.platform)
    {
        case 0xffffffff:
            return version.version <= guestAppSdkVersionSet;
        case 2:
            return version.version <= guestAppSdkVersion;
        default:
            return false;
    }
}

uint32_t hook_dyld_get_program_sdk_version(void* dyldApiInstancePtr)
{
    return guestAppSdkVersion;
}

void overwriteAppExecutableFileType(void)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        struct mach_header_64 *header = (struct mach_header_64*) orig__dyld_get_image_header(appMainImageIndex);
        kern_return_t kr = builtin_vm_protect(mach_task_self(), (vm_address_t)header, sizeof(header), false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
        if(kr != KERN_SUCCESS)
        {
            return;
        }
        header->filetype = MH_EXECUTE;
        builtin_vm_protect(mach_task_self(), appMainImageIndex, sizeof(struct mach_header), false, PROT_READ);
    });
}

static dyld_build_version_t getDyldImageBuildVersion(const struct mach_header *mh)
{
    dyld_build_version_t result = { .platform = 0xffffffff, .version = 0 };

    assert(mh != NULL);
    
    const uint8_t *ptr = ((const uint8_t *)mh) + sizeof(struct mach_header_64);
    uint32_t ncmds = mh->ncmds;

    for(uint32_t i = 0; i < ncmds; i++)
    {
        const struct load_command *lc = (const struct load_command *)ptr;

        if(lc->cmd == LC_BUILD_VERSION)
        {
            const struct build_version_command *bvc = (const struct build_version_command *)ptr;
            result.platform = bvc->platform;
            result.version  = bvc->sdk;
            return result;
        }
        ptr += lc->cmdsize;
    }

    ptr = ((const uint8_t *)mh) + sizeof(struct mach_header_64);

    for(uint32_t i = 0; i < ncmds; i++)
    {

        const struct load_command *lc = (const struct load_command *)ptr;

        if(lc->cmd == LC_VERSION_MIN_IPHONEOS ||
           lc->cmd == LC_VERSION_MIN_MACOSX)
        {
            const struct version_min_command *vm = (const struct version_min_command *)ptr;
            result.platform = 0xffffffff;
            result.version  = vm->sdk;
            return result;
        }

        ptr += lc->cmdsize;
    }

    return result;
}

bool initGuestSDKVersionInfo(void)
{
    void* dyldBase = getDyldBase();
    // it seems Apple is constantly changing findVersionSetEquivalent's signature so we directly search sVersionMap instead
    uint32_t *versionMapPtr = (uint32_t*)LCFindSymbolOffsetUnsafe("__ZN5dyld3L11sVersionMapE", dyldBase);
    if(!versionMapPtr) {
#if !TARGET_OS_SIMULATOR
        const char* dyldPath = "/usr/lib/dyld";
        uint64_t offset = 0;
        if(@available(iOS 27.0, *)) {
            offset = LCFindSymbolOffset(dyldPath, "__ZN5dyld311sVersionMapE");
        } else {
            offset = LCFindSymbolOffset(dyldPath, "__ZN5dyld3L11sVersionMapE");
        }
#else
        void *result = litehook_find_symbol(dyldBase, "__ZN5dyld3L11sVersionMapE");
        uint64_t offset = (uint64_t)result - (uint64_t)dyldBase;
#endif
        assert(offset);
        versionMapPtr = dyldBase + offset;
    }
    
    assert(versionMapPtr);
    // however sVersionMap's struct size is also unknown, but we can figure it out
    // we assume the size is 10K so we won't need to change this line until maybe iOS 40
    uint32_t* versionMapEnd = versionMapPtr + 2560;
    // ensure the first is versionSet and the third is iOS version (5.0.0)
    assert(versionMapPtr[0] == 0x07db0901 && versionMapPtr[2] == 0x00050000);
    // get struct size. we assume size is smaller then 128. appearently Apple won't have so many platforms
    uint32_t size = 0;
    for(int i = 1; i < 128; ++i) {
        // find the next versionSet (for 6.0.0)
        if(versionMapPtr[i] == 0x07dc0901) {
            size = i;
            break;
        }
    }
    assert(size);
    
    NSOperatingSystemVersion currentVersion = [[NSProcessInfo processInfo] operatingSystemVersion];
    uint32_t maxVersion = ((uint32_t)currentVersion.majorVersion << 16) | ((uint32_t)currentVersion.minorVersion << 8);
    
    uint32_t candidateVersion = 0;
    uint32_t candidateVersionEquivalent = 0;
    uint32_t newVersionSetVersion = 0;
    for(uint32_t* nowVersionMapItem = versionMapPtr; nowVersionMapItem < versionMapEnd; nowVersionMapItem += size) {
        newVersionSetVersion = nowVersionMapItem[2];
        if (newVersionSetVersion > guestAppSdkVersion) { break; }
        candidateVersion = newVersionSetVersion;
        candidateVersionEquivalent = nowVersionMapItem[0];
        if(newVersionSetVersion >= maxVersion) { break; }
    }
    
    if (newVersionSetVersion == 0xffffffff && candidateVersion == 0) {
        candidateVersionEquivalent = newVersionSetVersion;
    }

    guestAppSdkVersionSet = candidateVersionEquivalent;
    
    return true;
}

LIBKERN_DEFINE_PATCHABLE(void, DyldHooksInit, (void))
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        int imageCount = _dyld_image_count();
        for(int i = 0; i < imageCount; ++i)
        {
            const struct mach_header* currentImageHeader = _dyld_get_image_header(i);
            if(currentImageHeader->filetype == MH_EXECUTE)
            {
                lcImageIndex = i;
                break;
            }
        }
        
        DO_HOOK_GLOBAL(dlsym);
        DO_HOOK_GLOBAL(_dyld_image_count);
        DO_HOOK_GLOBAL(_dyld_get_image_header);
        DO_HOOK_GLOBAL(_dyld_get_image_vmaddr_slide);
        DO_HOOK_GLOBAL(_dyld_get_image_name);
        LIBKERN_INSTALL_PATCH(dlopen_hook);
        
        guestAppSdkVersion = getDyldImageBuildVersion((void*)ORIG_FUNC(_dyld_get_image_header)(appMainImageIndex)).version;
        if(!initGuestSDKVersionInfo() ||
           !performHookDyldApiFast(kDyldProgramSDKAtLeastVTFN, NULL, hook_dyld_program_sdk_at_least) ||
           !performHookDyldApiFast(kDyldGetProgramSDKVersionVTFN, NULL, hook_dyld_get_program_sdk_version))
        {
            exit(0);
        }
        return;
    });
}
