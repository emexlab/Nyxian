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

#import "NXROMRollback.h"
#import "NXBootLockdown.h"
#import <Security/Security.h>
#include <limits.h>
#include <os/lock.h>

BOOL NXROMIdentifierIsValid(id identifier)
{
    if(![identifier isKindOfClass:NSString.class] || ![identifier length] || [identifier length] > 255)
    {
        return NO;
    }
    
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"];
    if([identifier rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound)
    {
        return NO;
    }
    
    NSArray *components = [identifier componentsSeparatedByString:@"."];
    if(components.count < 2)
    {
        return NO;
    }
    
    for(NSString *part in components) if (!part.length)
    {
        return NO;
    }
    
    return YES;
}

NSNumber *NXROMParseSecurityVersion(id value)
{
    if(![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID() || CFNumberIsFloatType((__bridge CFNumberRef)value) || [value longLongValue] <= 0 || [value unsignedLongLongValue] > INT64_MAX)
    {
        return nil;
    }
    return @([value unsignedLongLongValue]);
}

static BOOL NXROMRollbackFail(NSError **error,
                              NSString *message)
{
    if(error)
    {
        *error = [NSError errorWithDomain:@"org.emexlabs.rom.rollback" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    }
    return NO;
}

static NSDictionary *NXROMRollbackQuery(void)
{
    return @{ (__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService:@"org.emexlabs.nyxian.rom-rollback", (__bridge id)kSecAttrAccount:@"signed-rom-security-floor.v1", (__bridge id)kSecAttrSynchronizable:@NO };
}

static NSDictionary *NXROMRollbackRead(BOOL *missing,
                                       NSError **error)
{
    *missing = NO;
    NSMutableDictionary *query = [NXROMRollbackQuery() mutableCopy];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if(status == errSecItemNotFound)
    {
        *missing = YES;
        return nil;
    }
    
    if(status != errSecSuccess)
    {
        if(result)
        {
            CFRelease(result);
        }
        NXROMRollbackFail(error,[NSString stringWithFormat:@"Could not read the ROM security floor from Keychain (%d).",(int)status]);
        return nil;
    }
    
    id data = CFBridgingRelease(result);
    id body = [data isKindOfClass:NSData.class] ? [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL] : nil;
    if(![body isKindOfClass:NSDictionary.class] || ![body[@"format"] isEqual:@1] || !NXROMParseSecurityVersion(body[@"securityVersion"]) || ![body[@"digest"] isKindOfClass:NSData.class] || [body[@"digest"] length] != 32)
    {
        NXROMRollbackFail(error, @"ROM security floor is malformed; refusing to reset rollback protection.");
        return nil;
    }
    
    id identifier = body[@"identifier"], floors = body[@"romFloors"];
    if((identifier || floors) && (!NXROMIdentifierIsValid(identifier) || ![floors isKindOfClass:NSDictionary.class]))
    {
        NXROMRollbackFail(error, @"ROM identity/security history is malformed.");
        return nil;
    }
    if(floors)
    {
        for(id name in floors)
        {
            id record = floors[name];
            if(!NXROMIdentifierIsValid(name) || ![record isKindOfClass:NSDictionary.class] || !NXROMParseSecurityVersion(record[@"securityVersion"]) || ![record[@"digest"] isKindOfClass:NSData.class] || [record[@"digest"] length] != 32)
            {
                NXROMRollbackFail(error, @"ROM identity/security history is malformed.");
                return nil;
            }
        }
        NSDictionary *current = floors[identifier];
        if(![current[@"securityVersion"] isEqual:body[@"securityVersion"]] || ![current[@"digest"] isEqual:body[@"digest"]])
        {
            NXROMRollbackFail(error, @"Active ROM security floor does not match its identity history.");
            return nil;
        }
    }
    return body;
}

static BOOL NXROMRollbackCandidateValid(uint64_t version,
                                        NSData *digest,
                                        NSError **error)
{
    if(version == 0 || version > INT64_MAX || ![digest isKindOfClass:NSData.class] || digest.length != 32)
    {
        return NXROMRollbackFail(error,@"ROM has no valid signed security version or release identity; legacy ROMs are blocked.");
    }
    return YES;
}

static BOOL NXROMRollbackPolicyFail(NSError **error,
                                    NSString *message)
{
    if(error)
    {
        *error = [NSError errorWithDomain:@"org.emexlabs.rom.rollback" code:2 userInfo:@{NSLocalizedDescriptionKey:message}];
    }
    return NO;
}

static BOOL NXROMRollbackCompare(uint64_t version,
                                 NSData *digest,
                                 NSDictionary *floor,
                                 NSError **error)
{
    uint64_t minimum = [floor[@"securityVersion"] unsignedLongLongValue];
    if(version < minimum)
    {
        return NXROMRollbackPolicyFail(error,[NSString stringWithFormat:@"ROM downgrade blocked: security version %llu is below the device minimum %llu.", (unsigned long long)version, (unsigned long long)minimum]);
    }
    if(version == minimum && ![digest isEqual:floor[@"digest"]])
    {
        return NXROMRollbackPolicyFail(error,[NSString stringWithFormat:@"Security version %llu already belongs to a different signed ROM. Increase NXRomSecurityVersion and rebuild/sign this release.", (unsigned long long)version]);
    }
    return YES;
}

BOOL NXROMRollbackCheck(uint64_t version,
                        NSData *digest,
                        BOOL allowUninitialized,
                        NSError **error)
{
    if(!NXROMRollbackCandidateValid(version, digest, error))
    {
        return NO;
    }
    
    BOOL missing = NO;
    NSDictionary *floor = NXROMRollbackRead(&missing,error);
    if(missing)
    {
        return allowUninitialized ? YES : NXROMRollbackFail(error, @"ROM security floor is missing; use the updated bootloader to flash or activate a signed ROM.");
    }
    return floor && NXROMRollbackCompare(version,digest,floor,error);
}

static NSDictionary *NXROMFloorForIdentifier(NSDictionary *body,
                                             NSString *identifier)
{
    if(!body || !identifier || !body[@"identifier"])
    {
        return body;
    }
    return body[@"romFloors"][identifier];
}

BOOL NXROMRollbackCheckForIdentifier(NSString *identifier, uint64_t version, NSData *digest, BOOL allowUninitialized, NSError **error)
{
    if(!NXROMIdentifierIsValid(identifier))
    {
        return NXROMRollbackFail(error, @"ROM has no valid NXRomIdentifier.");
    }
    if (!NXROMRollbackCandidateValid(version, digest, error)) return NO;
    BOOL missing = NO;
    NSDictionary *body = NXROMRollbackRead(&missing, error);
    if (!missing && !body) return NO;
    NSDictionary *floor = NXROMFloorForIdentifier(body, identifier);
    if (!floor) return allowUninitialized ? YES : NXROMRollbackFail(error, @"No security floor is recorded for this NXRomIdentifier; flash or activate the ROM first.");
    return NXROMRollbackCompare(version, digest, floor, error);
}

#if NX_ROM_BOOTLOADER

static os_unfair_lock NXROMRollbackCommitLock = OS_UNFAIR_LOCK_INIT;

NX_BOOT_ONLY static BOOL NXROMRollbackCommitLocked(NSString *identifier,
                                                   uint64_t version,
                                                   NSData *digest,
                                                   BOOL manual,
                                                   NSError **error)
{
    BOOL missing = NO;
    NSDictionary *floor = NXROMRollbackRead(&missing, error);
    NSDictionary *selected = NXROMFloorForIdentifier(floor, identifier);
    if(!missing && (!floor || (selected && !manual && !NXROMRollbackCompare(version, digest, selected, error))))
    {
        return NO;
    }
    
    if((!identifier || [floor[@"identifier"] isEqual:identifier]) && floor && version==[floor[@"securityVersion"] unsignedLongLongValue] && [digest isEqual:floor[@"digest"]])
    {
        return YES;
    }
    
    NSMutableDictionary *body = [@{@"format":@1,@"securityVersion":@(version), @"digest":digest } mutableCopy];
    if(identifier)
    {
        NSMutableDictionary *floors = [floor[@"romFloors"] mutableCopy] ?: [NSMutableDictionary dictionary];
        floors[identifier] = @{@"securityVersion":@(version), @"digest":digest};
        body[@"identifier"] = identifier;
        body[@"romFloors"] = floors;
    }
    else if (floor[@"identifier"])
    {
        return NXROMRollbackFail(error, @"Identity-aware ROM security state cannot be changed without NXRomIdentifier.");
    }
    NSData *data=[NSPropertyListSerialization dataWithPropertyList:body format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if(!data)
    {
        return NO;
    }
    
    OSStatus status;
    if(missing)
    {
        NSMutableDictionary *item=[NXROMRollbackQuery() mutableCopy];
        item[(__bridge id)kSecValueData] = data;
        item[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
        status = SecItemAdd((__bridge CFDictionaryRef)item,NULL);
    }
    else
    {
        status = SecItemUpdate((__bridge CFDictionaryRef)NXROMRollbackQuery(),(__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});
    }
    
    if(status != errSecSuccess)
    {
        return NXROMRollbackFail(error,[NSString stringWithFormat:@"Could not persist the ROM security floor in Keychain (%d); installation was not committed.", (int)status]);
    }
    
    return YES;
}

NX_BOOT_ONLY static BOOL NXROMRollbackCommit(NSString *identifier,
                                             uint64_t version,
                                             NSData *digest,
                                             BOOL manual,
                                             NSError **error)
{
    if(identifier && !NXROMIdentifierIsValid(identifier)) return NXROMRollbackFail(error, @"ROM has no valid NXRomIdentifier.");
    if(!NXROMRollbackCandidateValid(version, digest, error))
    {
        return NO;
    }
    
    os_unfair_lock_lock(&NXROMRollbackCommitLock);
    BOOL committed = NXROMRollbackCommitLocked(identifier, version, digest, manual, error);
    os_unfair_lock_unlock(&NXROMRollbackCommitLock);
    return committed;
}

NX_BOOT_ONLY BOOL NXROMRollbackBootCommit(uint64_t version,
                                          NSData *digest,
                                          NSError **error)
{
    return NXROMRollbackCommit(nil, version, digest, NO, error);
}

NX_BOOT_ONLY BOOL NXROMRollbackBootManualCommit(uint64_t version,
                                                NSData *digest,
                                                NSError **error)
{
    return NXROMRollbackCommit(nil, version, digest, YES, error);
}

NX_BOOT_ONLY BOOL NXROMRollbackBootCommitForIdentifier(NSString *identifier,
                                                       uint64_t version,
                                                       NSData *digest,
                                                       NSError **error)
{
    return NXROMIdentifierIsValid(identifier) ? NXROMRollbackCommit(identifier, version, digest, NO, error) : NXROMRollbackFail(error, @"Invalid NXRomIdentifier.");
}
NX_BOOT_ONLY BOOL NXROMRollbackBootManualCommitForIdentifier(NSString *identifier,
                                                             uint64_t version,
                                                             NSData *digest,
                                                             NSError **error)
{
    return NXROMIdentifierIsValid(identifier) ? NXROMRollbackCommit(identifier, version, digest, YES, error) : NXROMRollbackFail(error, @"Invalid NXRomIdentifier.");
}

#endif /* NX_ROM_BOOTLOADER */
