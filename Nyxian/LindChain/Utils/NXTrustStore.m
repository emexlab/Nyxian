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

#import "NXTrustStore.h"

#if NX_ROM_BOOTLOADER

#import "NXTrustStoreRootKeys.h"
#import "NXROMRollback.h"
#import "NXBootLockdown.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#include <os/lock.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static const char NXTrustStoreDomain[] = "NXROM-TRUSTSTORE-v1";
static const NSUInteger NXTrustStoreMaxSize = 1024 * 1024;
static const NSUInteger NXTrustStoreMaxKeys = 256;
static const NSUInteger NXTrustStoreMaxRevoked = 4096;

static os_unfair_lock NXTrustStoreLock = OS_UNFAIR_LOCK_INIT;
static NSDictionary *NXTrustStoreCache;

static NSError *NXTrustStoreError(NSString *message)
{
    return [NSError errorWithDomain:@"org.emexlabs.nyxian.truststore" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
}

static BOOL NXTrustStoreFail(NSError **error,
                             NSString *message)
{
    if(error)
    {
        *error = NXTrustStoreError(message);
    }
    return NO;
}

NSString *NXTrustStoreDownloadedPath(void)
{
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Boot/TrustStore/truststore.plist"];
}

NSURL *NXTrustStoreUpdateURL(void)
{
    return [NSURL URLWithString:@"https://emexlabs.org/switzach/truststore/truststore.plist"];
}

static NSString *NXTrustStoreBundledPath(void)
{
    return [NSBundle.mainBundle pathForResource:@"Shared/TrustStore/truststore" ofType:@"plist"];
}

static NSData *NXTrustStoreSHA256(NSData *data)
{
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

static SecKeyRef NXTrustStoreCreateKey(NSData *raw)
{
    if(raw.length != 65 || ((const unsigned char *)raw.bytes)[0] != 0x04)
    {
        return NULL;
    }
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom, (__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPublic, (__bridge id)kSecAttrKeySizeInBits:@256};
    return SecKeyCreateWithData((__bridge CFDataRef)raw, (__bridge CFDictionaryRef)attributes, NULL);
}

static NSData *NXTrustStoreReadFile(NSString *path)
{
    if(path == nil)
    {
        return nil;
    }
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0)
    {
        return nil;
    }
    struct stat st;
    if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || (NSUInteger)st.st_size > NXTrustStoreMaxSize)
    {
        close(fd);
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    ssize_t got = pread(fd, data.mutableBytes, data.length, 0);
    close(fd);
    return got == (ssize_t)data.length ? data : nil;
}

NSDictionary *NXTrustStoreParse(NSData *data,
                                NSError **error)
{
    if(![data isKindOfClass:NSData.class] || data.length == 0 || data.length > NXTrustStoreMaxSize)
    {
        NXTrustStoreFail(error, @"TrustStore is empty or too large.");
        return nil;
    }
    
    id envelope = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
    NSData *payload = [envelope isKindOfClass:NSDictionary.class] ? envelope[@"payload"] : nil;
    NSData *signature = [envelope isKindOfClass:NSDictionary.class] ? envelope[@"signature"] : nil;
    NSData *rootID = [envelope isKindOfClass:NSDictionary.class] ? envelope[@"rootKey"] : nil;
    if(![envelope isKindOfClass:NSDictionary.class] || ![envelope[@"format"] isEqual:@1] ||
       ![payload isKindOfClass:NSData.class] || ![signature isKindOfClass:NSData.class] || ![rootID isKindOfClass:NSData.class] ||
       signature.length < 8 || signature.length > 72 || rootID.length != CC_SHA256_DIGEST_LENGTH)
    {
        NXTrustStoreFail(error, @"Not a TrustStore.");
        return nil;
    }
    
    NSData *root = nil;
    for(size_t i = 0; i < NX_TRUSTSTORE_ROOT_KEY_COUNT; i++)
    {
        NSData *candidate = [NSData dataWithBytes:NXTrustStoreRootKeys[i] length:65];
        if([NXTrustStoreSHA256(candidate) isEqualToData:rootID])
        {
            root = candidate;
            break;
        }
    }
    if(root == nil)
    {
        NXTrustStoreFail(error, NX_TRUSTSTORE_ROOT_KEY_COUNT ? @"TrustStore is signed by a root key this bootloader does not have." : @"This bootloader has no TrustStore root key.");
        return nil;
    }
    
    CC_SHA256_CTX hash;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, NXTrustStoreDomain, sizeof(NXTrustStoreDomain));
    CC_SHA256_Update(&hash, payload.bytes, (CC_LONG)payload.length);
    CC_SHA256_Final(digest, &hash);
    SecKeyRef key = NXTrustStoreCreateKey(root);
    BOOL valid = key && SecKeyVerifySignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, (__bridge CFDataRef)[NSData dataWithBytes:digest length:sizeof(digest)], (__bridge CFDataRef)signature, NULL);
    if(key)
    {
        CFRelease(key);
    }
    if(!valid)
    {
        NXTrustStoreFail(error, @"TrustStore signature does not verify.");
        return nil;
    }
    
    id body = [NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:NULL error:NULL];
    NSNumber *version = [body isKindOfClass:NSDictionary.class] ? NXROMParseSecurityVersion(body[@"version"]) : nil;
    NSArray *entries = [body isKindOfClass:NSDictionary.class] ? body[@"keys"] : nil;
    if(![body isKindOfClass:NSDictionary.class] || ![body[@"format"] isEqual:@1] || version == nil ||
       ![entries isKindOfClass:NSArray.class] || entries.count == 0 || entries.count > NXTrustStoreMaxKeys)
    {
        NXTrustStoreFail(error, @"TrustStore payload is malformed.");
        return nil;
    }
    
    NSMutableArray<NSDictionary *> *keys = [NSMutableArray array];
    NSMutableSet<NSData *> *seen = [NSMutableSet set];
    for(NSDictionary *entry in entries)
    {
        NSString *name = [entry isKindOfClass:NSDictionary.class] ? entry[@"name"] : nil;
        NSData *publicKey = [entry isKindOfClass:NSDictionary.class] ? entry[@"publicKey"] : nil;
        id roms = [entry isKindOfClass:NSDictionary.class] ? entry[@"roms"] : nil;
        id usesTSS = [entry isKindOfClass:NSDictionary.class] ? entry[@"tss"] : nil;
        SecKeyRef check = [publicKey isKindOfClass:NSData.class] ? NXTrustStoreCreateKey(publicKey) : NULL;
        if(check)
        {
            CFRelease(check);
        }
        if(![name isKindOfClass:NSString.class] || name.length == 0 || check == NULL || [seen containsObject:publicKey])
        {
            NXTrustStoreFail(error, @"TrustStore has a malformed key.");
            return nil;
        }
        if(roms != nil)
        {
            if(![roms isKindOfClass:NSArray.class] || [roms count] == 0)
            {
                NXTrustStoreFail(error, @"TrustStore key has a malformed roms list.");
                return nil;
            }
            for(id rom in roms)
            {
                if(!NXROMIdentifierIsValid(rom))
                {
                    NXTrustStoreFail(error, @"TrustStore key has a malformed roms list.");
                    return nil;
                }
            }
        }
        if(usesTSS != nil && (![usesTSS isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)usesTSS) != CFBooleanGetTypeID()))
        {
            NXTrustStoreFail(error, @"TrustStore key has a malformed tss setting.");
            return nil;
        }
        [seen addObject:publicKey];
        NSMutableDictionary *key2 = [@{@"id":NXTrustStoreSHA256(publicKey), @"publicKey":publicKey, @"name":name, @"tss":@(usesTSS == nil || [usesTSS boolValue])} mutableCopy];
        if(roms != nil)
        {
            key2[@"roms"] = [roms copy];
        }
        [keys addObject:key2];
    }
    NSMutableDictionary<NSData *, NSNumber *> *revoked = [NSMutableDictionary dictionary];
    id revokedEntries = body[@"revoked"];
    if(revokedEntries != nil)
    {
        if(![revokedEntries isKindOfClass:NSArray.class] || [revokedEntries count] > NXTrustStoreMaxRevoked)
        {
            NXTrustStoreFail(error, @"TrustStore has a malformed revocation list.");
            return nil;
        }
        for(id entry in revokedEntries)
        {
            NSData *digest2 = [entry isKindOfClass:NSDictionary.class] ? entry[@"digest"] : nil;
            id boot = [entry isKindOfClass:NSDictionary.class] ? entry[@"boot"] : nil;
            if(![digest2 isKindOfClass:NSData.class] || digest2.length != CC_SHA256_DIGEST_LENGTH || (boot != nil && ![boot isKindOfClass:NSNumber.class]))
            {
                NXTrustStoreFail(error, @"TrustStore has a malformed revocation list.");
                return nil;
            }
            NXTrustStoreRevocation level = [boot boolValue] ? NXTrustStoreRevocationBoot : NXTrustStoreRevocationInstall;
            if(revoked[digest2].integerValue < level)
            {
                revoked[digest2] = @(level);
            }
        }
    }
    
    NSMutableArray<NSDictionary *> *tss = [NSMutableArray array];
    id tssEntries = body[@"tss"];
    if(tssEntries != nil)
    {
        if(![tssEntries isKindOfClass:NSArray.class] || [tssEntries count] > NXTrustStoreMaxKeys)
        {
            NXTrustStoreFail(error, @"TrustStore has a malformed TSS key list.");
            return nil;
        }
        for(id entry in tssEntries)
        {
            NSString *name = [entry isKindOfClass:NSDictionary.class] ? entry[@"name"] : nil;
            NSData *publicKey = [entry isKindOfClass:NSDictionary.class] ? entry[@"publicKey"] : nil;
            SecKeyRef check = [publicKey isKindOfClass:NSData.class] ? NXTrustStoreCreateKey(publicKey) : NULL;
            if(check)
            {
                CFRelease(check);
            }
            if(![name isKindOfClass:NSString.class] || name.length == 0 || check == NULL)
            {
                NXTrustStoreFail(error, @"TrustStore has a malformed TSS key.");
                return nil;
            }
            [tss addObject:@{@"id":NXTrustStoreSHA256(publicKey), @"publicKey":publicKey, @"name":name}];
        }
    }
    
    NSMutableDictionary *store = [@{@"version":version, @"keys":keys, @"revoked":revoked, @"tss":tss} mutableCopy];
    if([body[@"issued"] isKindOfClass:NSDate.class])
    {
        store[@"issued"] = body[@"issued"];
    }
    return store;
}

static NSDictionary *NXTrustStoreFloorQuery(void)
{
    return @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService:@"org.emexlabs.nyxian.truststore", (__bridge id)kSecAttrAccount:@"truststore-version-floor.v1", (__bridge id)kSecAttrSynchronizable:@NO};
}

static BOOL NXTrustStoreReadFloor(uint64_t *floor,
                                  BOOL *missing)
{
    *floor = 0;
    *missing = NO;
    NSMutableDictionary *query = [NXTrustStoreFloorQuery() mutableCopy];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if(status == errSecItemNotFound)
    {
        *missing = YES;
        return YES;
    }
    id data = result ? CFBridgingRelease(result) : nil;
    if(status != errSecSuccess || ![data isKindOfClass:NSData.class])
    {
        return NO;
    }
    id body = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
    NSNumber *version = [body isKindOfClass:NSDictionary.class] && [body[@"format"] isEqual:@1] ? NXROMParseSecurityVersion(body[@"version"]) : nil;
    if(version == nil)
    {
        return NO;
    }
    *floor = version.unsignedLongLongValue;
    return YES;
}

NX_BOOT_ONLY static BOOL NXTrustStoreWriteFloor(uint64_t version,
                                                NSError **error)
{
    uint64_t floor = 0;
    BOOL missing = NO;
    BOOL readable = NXTrustStoreReadFloor(&floor, &missing);
    if(readable && !missing && floor >= version)
    {
        return YES;
    }
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:@{@"format":@1, @"version":@(version)} format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if(data == nil)
    {
        return NXTrustStoreFail(error, @"Could not encode the TrustStore version floor.");
    }
    OSStatus status;
    if(missing)
    {
        NSMutableDictionary *item = [NXTrustStoreFloorQuery() mutableCopy];
        item[(__bridge id)kSecValueData] = data;
        item[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
        status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }
    else
    {
        status = SecItemUpdate((__bridge CFDictionaryRef)NXTrustStoreFloorQuery(), (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});
    }
    if(status != errSecSuccess)
    {
        return NXTrustStoreFail(error, [NSString stringWithFormat:@"Could not store the TrustStore version floor in the Keychain (%d).", (int)status]);
    }
    return YES;
}

static NSDictionary *NXTrustStoreLoad(void)
{
    uint64_t floor = 0;
    BOOL missing = NO;
    BOOL readable = NXTrustStoreReadFloor(&floor, &missing);
    uint64_t minimum = MAX(floor, (uint64_t)NX_TRUSTSTORE_MIN_VERSION);
    
    NSDictionary *best = nil;
    NSString *source = nil;
    for(NSString *name in @[@"downloaded", @"bundled"])
    {
        NSData *data = NXTrustStoreReadFile([name isEqual:@"downloaded"] ? NXTrustStoreDownloadedPath() : NXTrustStoreBundledPath());
        NSDictionary *store = data ? NXTrustStoreParse(data, NULL) : nil;
        uint64_t version = [store[@"version"] unsignedLongLongValue];
        if(store == nil || version < minimum || (best && version <= [best[@"version"] unsignedLongLongValue]))
        {
            continue;
        }
        best = store;
        source = name;
    }
    
    NSMutableDictionary *status;
    if(best && readable)
    {
        status = [best mutableCopy];
        status[@"source"] = source;
    }
    else
    {
        status = [@{@"version":@0, @"source":@"none", @"keys":@[]} mutableCopy];
    }
    status[@"floor"] = readable ? @(floor) : @(UINT64_MAX);
    return status;
}

static NSDictionary *NXTrustStoreCurrent(void)
{
    os_unfair_lock_lock(&NXTrustStoreLock);
    NSDictionary *current = NXTrustStoreCache;
    os_unfair_lock_unlock(&NXTrustStoreLock);
    if(current)
    {
        return current;
    }
    NSDictionary *loaded = NXTrustStoreLoad();
    os_unfair_lock_lock(&NXTrustStoreLock);
    if(NXTrustStoreCache == nil)
    {
        NXTrustStoreCache = loaded;
    }
    current = NXTrustStoreCache;
    os_unfair_lock_unlock(&NXTrustStoreLock);
    return current;
}

static void NXTrustStoreInvalidate(void)
{
    os_unfair_lock_lock(&NXTrustStoreLock);
    NXTrustStoreCache = nil;
    os_unfair_lock_unlock(&NXTrustStoreLock);
}

NSArray<NSDictionary *> *NXTrustStoreTrustedKeys(void)
{
    return NXTrustStoreCurrent()[@"keys"];
}

NSArray<NSDictionary *> *NXTrustStoreTSSKeys(void)
{
    NSArray *tss = NXTrustStoreCurrent()[@"tss"];
    return [tss isKindOfClass:NSArray.class] ? tss : @[];
}

NSDictionary *NXTrustStoreStatus(void)
{
    NSDictionary *current = NXTrustStoreCurrent();
    NSMutableDictionary *status = [current mutableCopy];
    status[@"keys"] = @([current[@"keys"] count]);
    status[@"names"] = [current[@"keys"] valueForKey:@"name"];
    status[@"revoked"] = @([current[@"revoked"] count]);
    status[@"tss"] = @(NXTrustStoreTSSKeys().count);
    return status;
}

NXTrustStoreRevocation NXTrustStoreReleaseRevocation(NSData *digest)
{
    if(![digest isKindOfClass:NSData.class])
    {
        return NXTrustStoreRevocationNone;
    }
    NSNumber *level = NXTrustStoreCurrent()[@"revoked"][digest];
    return level ? (NXTrustStoreRevocation)level.integerValue : NXTrustStoreRevocationNone;
}

NX_BOOT_ONLY BOOL NXTrustStoreInstall(NSData *data,
                                      NSError **error)
{
    NSDictionary *store = NXTrustStoreParse(data, error);
    if(store == nil)
    {
        return NO;
    }
    
    uint64_t version = [store[@"version"] unsignedLongLongValue];
    NSDictionary *current = NXTrustStoreCurrent();
    uint64_t trusted = [current[@"version"] unsignedLongLongValue];
    uint64_t floor = [current[@"floor"] unsignedLongLongValue];
    if(version < (uint64_t)NX_TRUSTSTORE_MIN_VERSION)
    {
        return NXTrustStoreFail(error, [NSString stringWithFormat:@"TrustStore version %llu is older than this bootloader accepts.", version]);
    }
    if(version <= trusted || (floor != UINT64_MAX && version < floor))
    {
        return NXTrustStoreFail(error, [NSString stringWithFormat:@"TrustStore version %llu is not newer than the trusted version %llu.", version, MAX(trusted, floor == UINT64_MAX ? 0 : floor)]);
    }
    
    NSString *path = NXTrustStoreDownloadedPath();
    NSError *failure = nil;
    if(![NSFileManager.defaultManager createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:&failure] ||
       ![data writeToFile:path options:NSDataWritingAtomic error:&failure])
    {
        return NXTrustStoreFail(error, [@"Could not save the TrustStore: " stringByAppendingString:failure.localizedDescription ?: @"unknown error"]);
    }
    if(!NXTrustStoreWriteFloor(version, error))
    {
        return NO;
    }
    
    NXTrustStoreInvalidate();
    if([NXTrustStoreCurrent()[@"version"] unsignedLongLongValue] != version)
    {
        return NXTrustStoreFail(error, @"The installed TrustStore is not the trusted one after installing it.");
    }
    
    return YES;
}

NX_BOOT_ONLY BOOL NXTrustStoreCommitFloor(NSError **error)
{
    NSDictionary *current = NXTrustStoreCurrent();
    uint64_t version = [current[@"version"] unsignedLongLongValue];
    if(version == 0)
    {
        return YES;
    }
    return NXTrustStoreWriteFloor(version, error);
}

#endif /* NX_ROM_BOOTLOADER */
