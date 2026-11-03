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
#import <LiveProcessLegacy/LPLShim.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <Broadpatch/Broadpatch.h>

NSMutableDictionary *SecItemPrepare(CFDictionaryRef query)
{
    NSMutableDictionary *queryCopy = ((__bridge NSDictionary *)query).mutableCopy;
    NSString *accessGroup = queryCopy[(__bridge id)kSecAttrAccessGroup];
    NSString *account = queryCopy[(__bridge id)kSecAttrAccount];
    
    if(!accessGroup)
    {
        accessGroup = [[NSBundle mainBundle] bundleIdentifier];
    }
    if(account)
    {
        [queryCopy removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
        [queryCopy removeObjectForKey:(__bridge id)kSecAttrAccount];
        queryCopy[(__bridge id)kSecAttrAccount] = [NSString stringWithFormat:@"%@@%@", accessGroup, account];
    }
    else
    {
        [queryCopy removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
    }
    
    return queryCopy;
}

/* will later be ksurface syscalls (safe finally) */
LIBKERN_PATCH(OSStatus, SecItemAdd, (CFDictionaryRef query,
                                     CFTypeRef *result),
{
    return LIBKERN_ORIG(SecItemAdd)((__bridge CFDictionaryRef)SecItemPrepare(query), result);
});

LIBKERN_PATCH(OSStatus, SecItemCopyMatching, (CFDictionaryRef query,
                                              CFTypeRef *result),
{
    return LIBKERN_ORIG(SecItemCopyMatching)((__bridge CFDictionaryRef)SecItemPrepare(query), result);
});

LIBKERN_PATCH(OSStatus, SecItemUpdate, (CFDictionaryRef query,
                                        CFTypeRef *result),
{
    return LIBKERN_ORIG(SecItemUpdate)((__bridge CFDictionaryRef)SecItemPrepare(query), result);
});

LIBKERN_PATCH(OSStatus, SecItemDelete, (CFDictionaryRef query),
{
    return LIBKERN_ORIG(SecItemDelete)((__bridge CFDictionaryRef)SecItemPrepare(query));
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(SecItemAdd);
    LIBKERN_INSTALL_PATCH(SecItemCopyMatching);
    LIBKERN_INSTALL_PATCH(SecItemUpdate);
    LIBKERN_INSTALL_PATCH(SecItemDelete);
}
