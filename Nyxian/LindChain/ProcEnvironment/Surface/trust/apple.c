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

/* ----------------------------------------------------------------------
 *  Project Headers
 * -------------------------------------------------------------------- */
#if !CLIENT_ENV
#include <LindChain/ProcEnvironment/Surface/trust/apple.h>
#endif /* !CLIENT_ENV */
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ----------------------------------------------------------------------
 *  Types
 * -------------------------------------------------------------------- */

typedef const struct __SecCode *SecStaticCodeRef;
typedef uint32_t SecCSFlags;

extern const CFStringRef kSecCodeInfoEntitlementsDict;
typedef struct __SecRequirement * SecRequirementRef;

#if !__NXTOOL

enum {
    kSecCSDefaultFlags = 0,
    kSecCSSigningInformation = 1 << 1,
    kSecCSRequirementInformation = 1 << 2,
};

#endif /* !__NXTOOL */

/* ----------------------------------------------------------------------
 *  Function Prototypes
 * -------------------------------------------------------------------- */
OSStatus SecStaticCodeCreateWithPath(CFURLRef path, SecCSFlags flags, SecStaticCodeRef *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef *information);

/* ----------------------------------------------------------------------
 *  Functions
 * -------------------------------------------------------------------- */
#if !CLIENT_ENV && !__NXTOOL
CFDictionaryRef CopyAppleCSEntitlementsForPath(CFStringRef path,
                                               OSStatus *outErr)
{
    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path, kCFURLPOSIXPathStyle, false);
    if(!url)
    {
        return NULL;
    }
    
    SecStaticCodeRef code = NULL;
    OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if(st != errSecSuccess)
    {
        if(outErr)
        {
            *outErr = st;
            return NULL;
        }
    }
    
    CFDictionaryRef info = NULL;
    st = SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSRequirementInformation, &info);
    CFRelease(code);
    if(st != errSecSuccess)
    {
        if(outErr)
        {
            *outErr = st;
        }
        return NULL;
    }
    
    CFDictionaryRef ents = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    if(ents)
    {
        CFRetain(ents);
    }
    CFRelease(info);
    if(outErr)
    {
        *outErr = errSecSuccess;
    }
    return ents;
}

CFTypeRef AppleCSTypeSanizizeKey(CFDictionaryRef appleCSEntitlements,
                                 CFStringRef key,
                                 CFTypeID type)
{
    CFTypeRef value = CFDictionaryGetValue(appleCSEntitlements, key);
    if(value == NULL)
    {
        return NULL;
    }
    
    if(CFGetTypeID(value) == type)
    {
        return value;
    }
    return NULL;
}

CFDictionaryRef ExtractNXT2OutOfAppleCSEntitlements(CFDictionaryRef appleCSEntitlements)
{
    if(appleCSEntitlements == NULL)
    {
        return NULL;
    }
    
    CFMutableArrayRef roPaths = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if(roPaths == NULL)
    {
        return NULL;
    }
    
    CFMutableArrayRef rwPaths = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if(rwPaths == NULL)
    {
        CFRelease(roPaths);
        return NULL;
    }
    
    CFMutableArrayRef lsGetAllowed = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    if(lsGetAllowed == NULL)
    {
        CFRelease(rwPaths);
        CFRelease(roPaths);
        return NULL;
    }
    
    CFMutableDictionaryRef newNXT2Entitlements = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(newNXT2Entitlements == NULL)
    {
        CFRelease(lsGetAllowed);
        CFRelease(rwPaths);
        CFRelease(roPaths);
        return NULL;
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("get-task-allow")) == kCFBooleanTrue)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementGetTaskAllow, kCFBooleanTrue);
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("task_for_pid-allow")) == kCFBooleanTrue)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementTaskForPid, kCFBooleanTrue);
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.system-task-ports")) == kCFBooleanTrue)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementSystemTaskPorts, kCFBooleanTrue);
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("platform-application")) == kCFBooleanTrue)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementPlatform, kCFBooleanTrue);
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("proc_info-allow")) == kCFBooleanTrue)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementProcessEnumeration, kCFBooleanTrue);
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.private.security.no-sandbox")) == kCFBooleanTrue ||
       CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.private.security.no-container")) == kCFBooleanTrue ||
       CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.private.security.container-required")) == kCFBooleanFalse)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementProcessEnumeration, kCFBooleanTrue);
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementProcessKill, kCFBooleanTrue);
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementProcessSpawnSignedOnly, kCFBooleanTrue);
        
        /* they can read rootfs */
        CFArrayAppendValue(roPaths, CFSTR("$(NXROOT)"));
    }
    
    CFArrayRef absoluteRwPaths = CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.security.exception.files.absolute-path.read-write"));
    if(absoluteRwPaths != NULL && CFGetTypeID(absoluteRwPaths) == CFArrayGetTypeID())
    {
        CFIndex count = CFArrayGetCount(absoluteRwPaths);
        for(CFIndex index = 0; index < count; index++)
        {
            CFStringRef absoluteRwPath = CFArrayGetValueAtIndex(absoluteRwPaths, index);
            if(CFGetTypeID(absoluteRwPath) == CFStringGetTypeID())
            {
                CFMutableStringRef pathStr = CFStringCreateMutable(kCFAllocatorDefault, 0);
                if(pathStr != NULL)
                {
                    CFStringAppend(pathStr, CFSTR("$(NXROOT)"));
                    CFStringAppend(pathStr, absoluteRwPath);
                    CFArrayAppendValue(rwPaths, pathStr);
                    CFRelease(pathStr);
                }
            }
        }
    }
    
    CFArrayRef absoluteRoPaths = CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.security.exception.files.absolute-path.read-only"));
    if(absoluteRoPaths != NULL && CFGetTypeID(absoluteRoPaths) == CFArrayGetTypeID())
    {
        CFIndex count = CFArrayGetCount(absoluteRoPaths);
        for(CFIndex index = 0; index < count; index++)
        {
            CFStringRef absoluteRoPath = CFArrayGetValueAtIndex(absoluteRoPaths, index);
            if(CFGetTypeID(absoluteRoPath) == CFStringGetTypeID())
            {
                CFMutableStringRef pathStr = CFStringCreateMutable(kCFAllocatorDefault, 0);
                if(pathStr != NULL)
                {
                    CFStringAppend(pathStr, CFSTR("$(NXROOT)"));
                    CFStringAppend(pathStr, absoluteRoPath);
                    CFArrayAppendValue(roPaths, pathStr);
                    CFRelease(pathStr);
                }
            }
        }
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.private.MobileContainerManager.allowed")) == kCFBooleanTrue)
    {
        CFArrayAppendValue(lsGetAllowed, CFSTR("org.emexlabs.bootstrapd"));
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.private.security.storage.AppDataContainers")) == kCFBooleanTrue)
    {
        CFArrayAppendValue(rwPaths, CFSTR("$(ROOTFS)/var/mobile/Containers/Data/Application"));
    }
    
    if(CFDictionaryGetValue(appleCSEntitlements, CFSTR("com.apple.private.security.storage.AppBundles")) == kCFBooleanTrue)
    {
        CFArrayAppendValue(rwPaths, CFSTR("$(ROOTFS)/var/containers/Bundle/Application"));
    }
    
    CFArrayRef temporarySBXException = AppleCSTypeSanizizeKey(appleCSEntitlements, CFSTR("com.apple.security.temporary-exception.sbpl"), CFArrayGetTypeID());
    if(temporarySBXException != NULL)
    {
        CFIndex temporarySBXExceptionCount = CFArrayGetCount(temporarySBXException);
        for(CFIndex index = 0; index < temporarySBXExceptionCount; index++)
        {
            CFTypeRef value = CFArrayGetValueAtIndex(temporarySBXException, index);
            if(CFEqual(value, CFSTR("(allow signal)")))
            {
                CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementProcessKill, kCFBooleanTrue);
            }
            else if(CFStringHasPrefix(value, CFSTR("(allow process-info")))
            {
                CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementProcessEnumeration, kCFBooleanTrue);
            }
        }
    }
    
    if(CFArrayGetCount(roPaths) > 0)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementSandboxFileRead, roPaths);
    }
    if(CFArrayGetCount(rwPaths) > 0)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementSandboxFileReadWrite, rwPaths);
    }
    if(CFArrayGetCount(lsGetAllowed) > 0)
    {
        CFDictionaryAddValue(newNXT2Entitlements, kNXT2EntitlementLaunchServicesGetEndpointAllowList, lsGetAllowed);
    }
    CFRelease(lsGetAllowed);
    CFRelease(roPaths);
    CFRelease(rwPaths);
    
    return newNXT2Entitlements;
}
#endif /* !CLIENT_ENV && !__NXTOOL */

kern_return_t CDHashMatchesCodeDirectory(const uint8_t *base,
                                         size_t size,
                                         const uint8_t expected_cdhash[USER_FSIGNATURES_CDHASH_LEN])
{
    bool CDHashOfMachO(const uint8_t *base, size_t size, uint8_t out[USER_FSIGNATURES_CDHASH_LEN]);
    uint8_t actual_cdhash[USER_FSIGNATURES_CDHASH_LEN];
    if(!CDHashOfMachO(base, size, actual_cdhash))
    {
        return KERN_FAILURE;
    }
    
    if(memcmp(actual_cdhash, expected_cdhash, size) == 0)
    {
        return KERN_SUCCESS;
    }
    
    return KERN_DENIED;
}

kern_return_t CDHashMatchesCodeDirectoryFD(int fd,
                                           const uint8_t expected_cdhash[USER_FSIGNATURES_CDHASH_LEN])
{
    if(fd < 0 || expected_cdhash == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    struct stat st;
    if(fstat(fd, &st) != 0 || st.st_size <= 0)
    {
        return KERN_FAILURE;
    }
    
    size_t size = (size_t)st.st_size;
    const uint8_t *base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(base == MAP_FAILED)
    {
        return KERN_FAILURE;
    }
    
    kern_return_t kr = CDHashMatchesCodeDirectory(base, size, expected_cdhash);
    munmap((void *)base, size);
    return kr;
}

kern_return_t CDHashMatchesCodeDirectoryOfPath(const char *path,
                                               const uint8_t expected_cdhash[USER_FSIGNATURES_CDHASH_LEN])
{
    kern_return_t kr = KERN_FAILURE;
    
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        return kr;
    }
    
    kr = CDHashMatchesCodeDirectoryFD(fd, expected_cdhash);
    close(fd);
    return kr;
}
