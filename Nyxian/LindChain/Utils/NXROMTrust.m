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

#import "NXROMTrust.h"
#import "NXROMRollback.h"
#import "NXBootLockdown.h"
#if NX_ROM_BOOTLOADER
#import "NXTrustStore.h"
#import "NXBootPolicy.h"
#endif /* NX_ROM_BOOTLOADER */
#import "NXROMFileHash.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

extern bool CDHashOfFD(int fd, uint8_t out[20]) __attribute__((weak_import));

static NSString *const NXROMSealName = @".nx-rom-seal.plist";
static NSString *const NXROMFilesName = @"NXRomFiles.plist";
static const char NXROMFilesDomain[] = "NXROM-FILES-v1";
static const char NXROMArchiveDomain[] = "NXROM-ARCHIVE-v1";
static const char NXROMSealDomain[] = "NXROM-BOOT-SEAL-v1";

struct __attribute__((packed)) NXROMFooter
{
    unsigned char signature[72];
    uint64_t length;
    uint32_t signatureLength;
    char magic[8];
};

static BOOL NXROMFail(NSError **error,
                      NSString *message)
{
    if(error)
    {
        *error = [NSError errorWithDomain:@"org.emexlabs.rom.signature" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    }
    return NO;
}

static BOOL NXROMConstantEqual(NSData *a,
                               NSData *b)
{
    if(a.length != b.length)
    {
        return NO;
    }
    
    const unsigned char *x = a.bytes, *y = b.bytes;
    unsigned char difference=0;
    for(NSUInteger i = 0; i < a.length; i++)
    {
        difference |= x[i] ^ y[i];
    }
    
    return difference == 0;
}

static NSDictionary *NXROMTrustedKeyForProof(NSDictionary *proof)
{
    if(![proof isKindOfClass:NSDictionary.class])
    {
        return nil;
    }
    
    NSData *digest = proof[@"digest"],
    *signature = proof[@"signature"];
    if(![digest isKindOfClass:NSData.class] || digest.length!=CC_SHA256_DIGEST_LENGTH || ![signature isKindOfClass:NSData.class] || signature.length < 8 || signature.length > 72)
    {
        return nil;
    }
    
#if NX_ROM_BOOTLOADER
    NSArray<NSDictionary *> *keys = NXTrustStoreTrustedKeys();
#else
    NSArray<NSDictionary *> *keys = @[@{@"publicKey":[NSData dataWithBytes:NXROMPublicKey length:sizeof(NXROMPublicKey)]}];
#endif /* NX_ROM_BOOTLOADER */
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom, (__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPublic, (__bridge id)kSecAttrKeySizeInBits:@256};
    for(NSDictionary *entry in keys)
    {
        SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)entry[@"publicKey"], (__bridge CFDictionaryRef)attributes, NULL);
        if(!key)
        {
            continue;
        }
        BOOL valid = SecKeyVerifySignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, (__bridge CFDataRef)digest, (__bridge CFDataRef)signature, NULL);
        CFRelease(key);
        if(valid)
        {
            return entry;
        }
    }
    
    return nil;
}

static BOOL NXROMTrustStoreOff(void)
{
#if NX_ROM_BOOTLOADER
    return !NXBootPolicyTrustStoreValidation();
#else
    return NO;
#endif /* NX_ROM_BOOTLOADER */
}

static BOOL NXROMVerifyProof(NSDictionary *proof)
{
    if(NXROMTrustedKeyForProof(proof) != nil)
    {
        return YES;
    }
    if(!NXROMTrustStoreOff() || ![proof isKindOfClass:NSDictionary.class])
    {
        return NO;
    }
    NSData *digest = proof[@"digest"];
    id signature = proof[@"signature"];
    return [digest isKindOfClass:NSData.class] && digest.length == CC_SHA256_DIGEST_LENGTH && (signature == nil || ([signature isKindOfClass:NSData.class] && [signature length] <= 72));
}

BOOL NXROMProofIsTrusted(NSDictionary *proof)
{
    return NXROMTrustedKeyForProof(proof) != nil;
}

BOOL NXROMProofRequiresTicket(NSDictionary *proof)
{
#if NX_ROM_BOOTLOADER
    if(!NXBootPolicyTSSValidation())
    {
        return NO;
    }
    
    NSDictionary *signer = NXROMTrustedKeyForProof(proof);
    if(signer == nil)
    {
        return !NXROMTrustStoreOff();
    }
    
    return ![signer[@"tss"] isEqual:@NO];
#else
    return YES;
#endif /* NX_ROM_BOOTLOADER */
}

NSDictionary *NXROMArchiveProofForFD(int fd,
                                     NSError **error)
{
    struct stat before,after;
    struct NXROMFooter footer;
    if(fstat(fd,&before)!=0 || !S_ISREG(before.st_mode) || before.st_size < (off_t)sizeof(footer) || pread(fd,&footer,sizeof(footer) , before.st_size - sizeof(footer)) != sizeof(footer))
    {
        NXROMFail(error, @"ROM archive is missing or unreadable.");
        return nil;
    }
    
    uint64_t length = OSSwapLittleToHostInt64(footer.length);
    uint32_t signatureLength = OSSwapLittleToHostInt32(footer.signatureLength);
    NSString *footerProblem = nil;
    if(memcmp(footer.magic, "NXROM001", 8) != 0 || length != (uint64_t)before.st_size - sizeof(footer) || length < 22 || signatureLength < 8 || signatureLength > sizeof(footer.signature))
    {
        footerProblem = @"ROM release signature is missing or malformed.";
    }
    else
    {
        for(size_t i = signatureLength; i < sizeof(footer.signature);i++)
        {
            if(footer.signature[i] != 0)
            {
                footerProblem = @"ROM signature padding is invalid.";
                break;
            }
        }
    }
    
    if(footerProblem != nil)
    {
        if(!NXROMTrustStoreOff())
        {
            NXROMFail(error, footerProblem);
            return nil;
        }
        length = (uint64_t)before.st_size;
        signatureLength = 0;
    }
    
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, NXROMArchiveDomain, sizeof(NXROMArchiveDomain));
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    for(uint64_t offset = 0; offset < length;)
    {
        size_t count = (size_t)MIN((uint64_t)sizeof(buffer),length-offset);
        ssize_t received = pread(fd, buffer,count, (off_t)offset);
        if(received <= 0)
        {
            NXROMFail(error, @"Could not read the signed ROM archive.");
            return nil;
        }
        
        CC_SHA256_Update(&hash,buffer,(CC_LONG)received);
        offset += (uint64_t)received;
    }
    
    CC_SHA256_Final(digest,&hash);
    if(fstat(fd,&after) != 0 || before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec)
    {
        NXROMFail(error, @"ROM archive changed during verification.");
        return nil;
    }
    
    NSDictionary *proof = @{ @"digest":[NSData dataWithBytes:digest length:sizeof(digest)], @"signature":[NSData dataWithBytes:footer.signature length:signatureLength] };
    if(!NXROMVerifyProof(proof))
    {
        NXROMFail(error, @"ROM release signature does not match any trusted release key.");
        return nil;
    }
    
#if NX_ROM_BOOTLOADER
    if(NXTrustStoreReleaseRevocation(proof[@"digest"]) != NXTrustStoreRevocationNone)
    {
        NXROMFail(error, @"This ROM release was revoked by its publisher and can't be installed anymore.");
        return nil;
    }
#endif /* NX_ROM_BOOTLOADER */
    
    return proof;
}

NSDictionary *NXROMArchiveProof(NSString *path,
                                NSError **error)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0)
    {
        NXROMFail(error, @"Could not open the ROM archive without following a symlink.");
        return nil;
    }
    NSDictionary *proof = NXROMArchiveProofForFD(fd, error);
    close(fd);
    return proof;
}

static NSData *NXROMHashFile(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if(fd < 0)
    {
        return nil;
    }
    
    if(fstat(fd,&st) != 0 || !S_ISREG(st.st_mode))
    {
        close(fd);
        return nil;
    }
    
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    unsigned char buffer[65536], digest[CC_SHA256_DIGEST_LENGTH];
    ssize_t count;
    while((count = read(fd,buffer, sizeof(buffer))) > 0)
    {
        CC_SHA256_Update(&hash, buffer, (CC_LONG)count);
    }
    
    close(fd);
    if(count < 0)
    {
        return nil;
    }
    
    CC_SHA256_Final(digest, &hash);
    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

static NSDictionary *NXROMRecord(NSString *path,
                                 NSError **error)
{
    struct stat st;
    if(lstat(path.fileSystemRepresentation, &st)!=0)
    {
        NXROMFail(error, @"ROM entry is missing.");
        return nil;
    }
    
    NSMutableDictionary *record = [@{@"mode":@(st.st_mode&07777)} mutableCopy];
    if(S_ISREG(st.st_mode))
    {
        NSData *hash = NXROMHashFile(path);
        if(!hash)
        {
            NXROMFail(error, @"Could not hash ROM file.");
            return nil;
        }
        
        record[@"type"] = @"file"; record[@"hash"] = hash;
        int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        uint32_t magic = 0; unsigned char cdhash[20];
        if(fd < 0)
        {
            NXROMFail(error, @"Could not read ROM executable.");
            return nil;
        }
        
        ssize_t count = pread(fd,&magic,sizeof(magic),0);
        BOOL macho = count == sizeof(magic) && (magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        if(macho && (!CDHashOfFD || !CDHashOfFD(fd,cdhash)))
        {
            close(fd);
            NXROMFail(error, @"ROM executable has no readable CodeDirectory hash.");
            return nil;
        }
        
        close(fd);
        if(macho)
        {
            record[@"cdhash"] = [NSData dataWithBytes:cdhash length:sizeof(cdhash)];
        }
    }
    else if(S_ISDIR(st.st_mode))
    {
        record[@"type"] = @"directory";
    }
    else if(S_ISLNK(st.st_mode))
    {
        NSString *target = [NSFileManager.defaultManager destinationOfSymbolicLinkAtPath:path error:error];
        if(!target)
        {
            return nil;
        }
        record[@"type"] = @"symlink";
        record[@"target"] = target;
    }
    else
    {
        NXROMFail(error, @"ROM contains an unsupported filesystem entry.");
        return nil;
    }
    
    return record;
}

static NSDictionary *NXROMInventory(NSString *root,
                                    NSError **error)
{
    char canonical[PATH_MAX];
    if(!realpath(root.fileSystemRepresentation, canonical))
    {
        NXROMFail(error, @"Could not resolve ROM root.");
        return nil;
    }
    
    root = [NSString stringWithUTF8String:canonical];
    struct stat st;
    if(lstat(root.fileSystemRepresentation, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        NXROMFail(error, @"ROM root is not a directory.");
        return nil;
    }
    
    NSMutableDictionary *inventory = [NSMutableDictionary dictionary];
    __block BOOL failed = NO;
    NSDirectoryEnumerator *enumerator = [NSFileManager.defaultManager enumeratorAtURL:[NSURL fileURLWithPath:root isDirectory:YES]
        includingPropertiesForKeys:nil options:0 errorHandler:^BOOL(NSURL *url, NSError *failure){
        failed=YES;
        return NO;
    }];
    if(!enumerator)
    {
        NXROMFail(error, @"Could not enumerate ROM files.");
        return nil;
    }
    
    NSString *prefix = [root stringByAppendingString:@"/"];
    for(NSURL *entry in enumerator)
    {
        if(![entry.path hasPrefix:prefix])
        {
            NXROMFail(error, [NSString stringWithFormat:@"ROM path outside root: %@ / %@", entry.path, prefix]);
            return nil;
        }
        
        NSString *relative=[entry.path substringFromIndex:prefix.length];
        if([relative isEqual:NXROMSealName])
        {
            continue;
        }
        
        NSDictionary *record = NXROMRecord(entry.path, error);
        if(!record)
        {
            return nil;
        }
        
        if([record[@"type"] isEqual:@"symlink"])
        {
            [enumerator skipDescendants];
        }
        inventory[relative]=record;
    }
    
    if(failed)
    {
        NXROMFail(error, @"ROM enumeration failed.");
        return nil;
    }
    
    return inventory;
}

NX_BOOT_ONLY static NSData *NXROMSealMAC(NSData *payload,
                                         NSData *key)
{
    CCHmacContext context;
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmacInit(&context, kCCHmacAlgSHA256, key.bytes, key.length);
    CCHmacUpdate(&context, NXROMSealDomain, sizeof(NXROMSealDomain));
    CCHmacUpdate(&context, payload.bytes, payload.length);
    CCHmacFinal(&context, mac);
    return [NSData dataWithBytes:mac length:sizeof(mac)];
}

static NSDictionary *NXROMReadSeal(NSString *root,
                                   NSData *key,
                                   BOOL requireVendor,
                                   NSError **error)
{
    NSString *path = [root stringByAppendingPathComponent:NXROMSealName];
    struct stat st;
    if(key.length < 32 || lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 32 * 1024 * 1024)
    {
        NXROMFail(error, @"Bootloader ROM seal is missing or invalid; reflash using the updated bootloader.");
        return nil;
    }
    
    NSData *sealData=[NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:error];
    id decoded = sealData ? [NSPropertyListSerialization propertyListWithData:sealData options:NSPropertyListImmutable format:NULL error:error] : nil;
    if(![decoded isKindOfClass:NSDictionary.class])
    {
        NXROMFail(error, @"Malformed ROM boot seal.");
        return nil;
    }
    
    NSDictionary *seal = decoded;
    NSData *payload = seal[@"payload"], *mac = seal[@"mac"];
    if(![payload isKindOfClass:NSData.class] || ![mac isKindOfClass:NSData.class] || !NXROMConstantEqual(mac, NXROMSealMAC(payload, key)))
    {
        NXROMFail(error, @"ROM boot seal authentication failed.");
        return nil;
    }
    
    NSDictionary *body = [NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:NULL error:error];
    if(![body isKindOfClass:NSDictionary.class] || ![body[@"format"] isEqual:@1] || ![body[@"inventory"] isKindOfClass:NSDictionary.class])
    {
        NXROMFail(error, @"ROM boot seal payload is invalid.");
        return nil;
    }
    
    NSDictionary *proof=body[@"releaseProof"];
    if((requireVendor || proof != nil) && !NXROMVerifyProof(proof))
    {
        NXROMFail(error,@"ROM boot seal has no release signature by a trusted key.");
        return nil;
    }
    
    return body;
}

NSDictionary *NXROMSealedReleaseProof(NSString *root,
                                      NSData *key,
                                      NSError **error)
{
    return NXROMReadSeal(root, key, YES, error)[@"releaseProof"];
}

NSData *NXROMSealedSigningContext(NSString *root,
                                  NSData *key,
                                  NSError **error)
{
    NSDictionary *body = NXROMReadSeal(root, key, YES, error);
    id context = body[@"signingContext"];
    if(context && (![context isKindOfClass:NSData.class] || [context length] != 32))
    {
        NXROMFail(error, @"ROM signing identity metadata is malformed.");
        return nil;
    }
    
    return context;
}
NSDictionary *NXROMSealedReleaseIdentity(NSString *root,
                                         NSData *key,
                                         NSError **error)
{
    NSDictionary *body = NXROMReadSeal(root, key, YES, error);
    if(!body)
    {
        return nil;
    }
    
    NSString *path = [root stringByAppendingPathComponent:@"manifest.plist"];
    NSDictionary *record = NXROMRecord(path, error);
    if(!record || ![record[@"type"] isEqual:@"file"] || ![record isEqual:body[@"inventory"][@"manifest.plist"]])
    {
        NXROMFail(error, @"ROM manifest does not match its authenticated seal.");
        return nil;
    }
    
    NSDictionary *manifest = [NSDictionary dictionaryWithContentsOfFile:path];
    NSNumber *version = NXROMParseSecurityVersion(manifest[@"NXRomSecurityVersion"]);
    if(!version || !NXROMIdentifierIsValid(manifest[@"NXRomIdentifier"]))
    {
        NXROMFail(error, @"ROM has no valid NXRomIdentifier/NXRomSecurityVersion; legacy ROMs cannot bypass rollback protection.");
        return nil;
    }
    
    NSDictionary *signer = NXROMTrustedKeyForProof(body[@"releaseProof"]);
    NSArray *roms = signer[@"roms"];
    if((!signer && !NXROMTrustStoreOff()) || (roms && ![roms containsObject:manifest[@"NXRomIdentifier"]]))
    {
        NXROMFail(error, [NSString stringWithFormat:@"%@ is not signed by a release key trusted for it.", manifest[@"NXRomIdentifier"]]);
        return nil;
    }
    
    return @{@"identifier":manifest[@"NXRomIdentifier"], @"securityVersion":version, @"digest":body[@"releaseProof"][@"digest"]};
}

BOOL NXROMVerifySeal(NSString *root,
                     NSData *key,
                     BOOL requireVendor,
                     NSError **error)
{
    NSDictionary *body = NXROMReadSeal(root,key,requireVendor,error);
    if(!body)
    {
        return NO;
    }
    
    NSDictionary *actual = NXROMInventory(root,error);
    if(!actual || ![actual isEqual:body[@"inventory"]])
    {
        return NXROMFail(error,@"ROM integrity mismatch: files, permissions, or symlinks changed after flash.");
    }
    
    return YES;
}

BOOL NXROMVerifySealedFile(NSString *root,
                           NSString *relative,
                           NSData *key,
                           NSError **error)
{
    NSDictionary *body = NXROMReadSeal(root, key, YES, error);
    if(!body || ![relative isEqual:@"binpack/usr/bin/otaupd"])
    {
        return NO;
    }
    
    NSString *parent = relative.stringByDeletingLastPathComponent;
    while(parent.length && ![parent isEqual:@"."])
    {
        NSDictionary *expectedParent = body[@"inventory"][parent];
        NSDictionary *actualParent = NXROMRecord([root stringByAppendingPathComponent:parent],error);
        if(![expectedParent[@"type"] isEqual:@"directory"] || ![actualParent isEqual:expectedParent])
        {
            return NO;
        }
        parent = parent.stringByDeletingLastPathComponent;
    }
    
    NSDictionary *actual = NXROMRecord([root stringByAppendingPathComponent:relative],error);
    NSDictionary *expected = body[@"inventory"][relative];
    return actual && [expected[@"type"] isEqual:@"file"] && [actual isEqual:expected];
}

static NSDictionary<NSString *, NSDictionary *> *NXROMNXT2Entitlements(NSDictionary *manifest)
{
    NSMutableDictionary *entitlements = [NSMutableDictionary dictionary];
    id paths = manifest[@"NXRomPaths"];
    if(![paths isKindOfClass:NSArray.class])
    {
        return entitlements;
    }
    for(NSDictionary *entry in paths)
    {
        if(![entry isKindOfClass:NSDictionary.class] || ![entry[@"NXRequiresCodeSigning"] isEqual:@YES]
           || ![entry[@"NXT2Entitlements"] isKindOfClass:NSDictionary.class])
        {
            continue;
        }
        id path = entry[@"NXPath"];
        for(id one in [path isKindOfClass:NSArray.class] ? path : (path ? @[path] : @[]))
        {
            if([one isKindOfClass:NSString.class])
            {
                entitlements[one] = entry[@"NXT2Entitlements"];
            }
        }
    }
    
    return entitlements;
}

static BOOL NXROMFileListFail(NSError **error, NSString *format, ...) NS_FORMAT_FUNCTION(2,3);
static BOOL NXROMFileListFail(NSError **error, NSString *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    return NXROMFail(error, message);
}

BOOL NXROMVerifyFileList(NSString *root,
                         NSDictionary *proof,
                         BOOL checkNXT2,
                         NSError **error)
{
    NSDictionary *signer = NXROMTrustedKeyForProof(proof);
    if(signer == nil && !NXROMTrustStoreOff())
    {
        return NXROMFail(error, @"ROM has no release signature by a trusted key.");
    }
    
    char canonical[PATH_MAX];
    if(!realpath(root.fileSystemRepresentation, canonical))
    {
        return NXROMFail(error, @"Could not resolve ROM root.");
    }
    root = [NSString stringWithUTF8String:canonical];
    
    NSString *listPath = [root stringByAppendingPathComponent:NXROMFilesName];
    struct stat st;
    if(lstat(listPath.fileSystemRepresentation, &st) != 0 && errno == ENOENT && NXROMTrustStoreOff())
    {
        /* TrustStore validation off: a ROM without a list has nothing to be compared with (the seal still is) */
        return YES;
    }
    if(lstat(listPath.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 64 * 1024 * 1024)
    {
        return NXROMFail(error, @"This ROM has no signed file list.");
    }
    NSData *listData = [NSData dataWithContentsOfFile:listPath options:NSDataReadingUncached error:NULL];
    id listing = listData ? [NSPropertyListSerialization propertyListWithData:listData options:NSPropertyListImmutable format:NULL error:NULL] : nil;
    NSData *payload = [listing isKindOfClass:NSDictionary.class] ? listing[@"payload"] : nil;
    NSData *signature = [listing isKindOfClass:NSDictionary.class] ? listing[@"signature"] : nil;
    if(![listing isKindOfClass:NSDictionary.class] || ![listing[@"format"] isEqual:@1] || ![payload isKindOfClass:NSData.class]
       || (signer != nil && (![signature isKindOfClass:NSData.class] || signature.length < 8 || signature.length > 72)))
    {
        return NXROMFail(error, @"The ROM's signed file list is malformed.");
    }
    
    if(signer != nil)
    {
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256_CTX hash;
        CC_SHA256_Init(&hash);
        CC_SHA256_Update(&hash, NXROMFilesDomain, sizeof(NXROMFilesDomain));
        CC_SHA256_Update(&hash, payload.bytes, (CC_LONG)payload.length);
        CC_SHA256_Final(digest, &hash);
        NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom, (__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPublic, (__bridge id)kSecAttrKeySizeInBits:@256};
        SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)signer[@"publicKey"], (__bridge CFDictionaryRef)attributes, NULL);
        BOOL signedByDeveloper = key && SecKeyVerifySignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, (__bridge CFDataRef)[NSData dataWithBytes:digest length:sizeof(digest)], (__bridge CFDataRef)signature, NULL);
        if(key)
        {
            CFRelease(key);
        }
        if(!signedByDeveloper)
        {
            return NXROMFail(error, @"The ROM's file list isn't signed by the key that signed the release.");
        }
    }
    NSDictionary *body = [NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:NULL error:NULL];
    NSDictionary *files = [body isKindOfClass:NSDictionary.class] ? body[@"files"] : nil;
    if(![body isKindOfClass:NSDictionary.class] || ![body[@"format"] isEqual:@1] || ![files isKindOfClass:NSDictionary.class])
    {
        return NXROMFail(error, @"The ROM's signed file list is malformed.");
    }
    
    NSData *manifestData = [NSData dataWithContentsOfFile:[root stringByAppendingPathComponent:@"manifest.plist"] options:NSDataReadingUncached error:NULL];
    uint8_t manifestHash[32];
    char reason[160] = "";
    NSDictionary *manifestEntry = files[@"manifest.plist"];
    if(!manifestData || ![manifestEntry isKindOfClass:NSDictionary.class] || !NXROMFileHash(manifestData.bytes, manifestData.length, "manifest.plist", manifestHash, reason, sizeof(reason))
       || ![manifestEntry[@"type"] isEqual:@"file"]
       || ![manifestEntry[@"hash"] isEqual:[NSData dataWithBytes:manifestHash length:sizeof(manifestHash)]])
    {
        return NXROMFail(error, @"The ROM's manifest isn't the one its developer signed.");
    }
    
    NSDictionary *manifest = [NSPropertyListSerialization propertyListWithData:manifestData options:NSPropertyListImmutable format:NULL error:NULL];
    if(![manifest isKindOfClass:NSDictionary.class] || ![body[@"identifier"] isEqual:manifest[@"NXRomIdentifier"]]
       || ![body[@"version"] isEqual:manifest[@"NXRomVersion"]] || ![body[@"securityVersion"] isEqual:manifest[@"NXRomSecurityVersion"]])
    {
        return NXROMFail(error, @"The ROM's signed file list is for another release.");
    }
    
    NSArray *roms = signer[@"roms"];
    if(roms && ![roms containsObject:manifest[@"NXRomIdentifier"]])
    {
        return NXROMFileListFail(error, @"%@ is not signed by a release key trusted for it.", manifest[@"NXRomIdentifier"]);
    }
    
    NSDictionary *entitlements = checkNXT2 ? NXROMNXT2Entitlements(manifest) : nil;
    
    __block BOOL failed = NO;
    NSDirectoryEnumerator *enumerator = [NSFileManager.defaultManager enumeratorAtURL:[NSURL fileURLWithPath:root isDirectory:YES]
        includingPropertiesForKeys:nil options:0 errorHandler:^BOOL(NSURL *url, NSError *failure){
        failed = YES;
        return NO;
    }];
    if(!enumerator)
    {
        return NXROMFail(error, @"Could not enumerate ROM files.");
    }
    NSString *prefix = [root stringByAppendingString:@"/"];
    NSUInteger seen = 0;
    for(NSURL *entry in enumerator)
    {
        if(![entry.path hasPrefix:prefix])
        {
            return NXROMFail(error, @"ROM path outside root.");
        }
        NSString *relative = [entry.path substringFromIndex:prefix.length];
        if([relative isEqual:NXROMSealName] || [relative isEqual:NXROMFilesName])
        {
            continue;
        }
        NSDictionary *expected = files[relative];
        if(![expected isKindOfClass:NSDictionary.class])
        {
            return NXROMFileListFail(error, @"This ROM has %@, which its developer didn't sign.", relative);
        }
        seen++;
        if(lstat(entry.path.fileSystemRepresentation, &st) != 0)
        {
            return NXROMFail(error, @"ROM entry is missing.");
        }
        if(S_ISDIR(st.st_mode))
        {
            if(![expected[@"type"] isEqual:@"directory"])
            {
                return NXROMFileListFail(error, @"%@ isn't what its developer signed.", relative);
            }
            continue;
        }
        if(S_ISLNK(st.st_mode))
        {
            [enumerator skipDescendants];
            NSString *target = [NSFileManager.defaultManager destinationOfSymbolicLinkAtPath:entry.path error:NULL];
            if(![expected[@"type"] isEqual:@"symlink"] || ![expected[@"target"] isEqual:target])
            {
                return NXROMFileListFail(error, @"%@ isn't what its developer signed.", relative);
            }
            continue;
        }
        if(!S_ISREG(st.st_mode) || ![expected[@"type"] isEqual:@"file"])
        {
            return NXROMFileListFail(error, @"%@ isn't what its developer signed.", relative);
        }
        NSData *data = [NSData dataWithContentsOfFile:entry.path options:NSDataReadingMappedIfSafe error:NULL];
        uint8_t fileHash[32];
        if(!data || !NXROMFileHash(data.bytes, data.length, relative.lastPathComponent.fileSystemRepresentation, fileHash, reason, sizeof(reason)))
        {
            return NXROMFileListFail(error, @"%@ can't be checked: %s.", relative, reason);
        }
        if(![expected[@"hash"] isEqual:[NSData dataWithBytes:fileHash length:sizeof(fileHash)]])
        {
            return NXROMFileListFail(error, @"%@ was changed after its developer signed it.", relative);
        }
        if(checkNXT2 && NXROMFileKindOf(data.bytes, data.length) == NXROMFileKindMachO)
        {
            const uint8_t *plist = NULL;
            size_t plistLength = 0;
            if(!NXROMFileNXT2Plist(data.bytes, data.length, &plist, &plistLength))
            {
                return NXROMFileListFail(error, @"%@ has a malformed entitlements blob.", relative);
            }
            NSDictionary *wanted = entitlements[relative];
            id present = plist ? [NSPropertyListSerialization propertyListWithData:[NSData dataWithBytes:plist length:plistLength] options:NSPropertyListImmutable format:NULL error:NULL] : nil;
            if(wanted ? ![present isEqual:wanted] : plist != NULL)
            {
                return NXROMFileListFail(error, @"%@ has entitlements its developer didn't give it.", relative);
            }
        }
    }
    if(failed)
    {
        return NXROMFail(error, @"ROM enumeration failed.");
    }
    if(seen != files.count)
    {
        return NXROMFail(error, @"Files its developer signed are missing from this ROM.");
    }
    
    return YES;
}

#if NX_ROM_BOOTLOADER

NX_BOOT_ONLY static BOOL NXROMWriteSealInternal(NSString *root,
                                   NSDictionary *proof,
                                   NSData *key,
                                   NSData *context,
                                   NSError **error)
{
    if(key.length < 32 || (proof && !NXROMVerifyProof(proof)))
    {
        return NXROMFail(error,@"Cannot seal ROM with invalid keys or release proof.");
    }
    
    NSDictionary *inventory = NXROMInventory(root,error);
    if(!inventory)
    {
        return NO;
    }
    
    NSMutableDictionary *body = [@{@"format":@1,@"inventory":inventory} mutableCopy];
    if(proof)
    {
        body[@"releaseProof"] = proof;
    }
    
    if(context)
    {
        body[@"signingContext"] = context;
    }
    
    NSData *payload = [NSPropertyListSerialization dataWithPropertyList:body format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if(!payload)
    {
        return NO;
    }
    
    NSData *seal = [NSPropertyListSerialization dataWithPropertyList:@{@"payload":payload,@"mac":NXROMSealMAC(payload, key)} format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if(!seal || ![seal writeToFile:[root stringByAppendingPathComponent:NXROMSealName] options:NSDataWritingAtomic error:error])
    {
        return NO;
    }
    
    return NXROMVerifySeal(root, key, proof != nil, error);
}

NX_BOOT_ONLY BOOL NXROMWriteSeal(NSString *root,
                    NSDictionary *proof,
                    NSData *key,
                    NSError **error)
{
    return NXROMWriteSealInternal(root, proof, key, nil, error);
}

NX_BOOT_ONLY BOOL NXROMWriteSealWithSigningContext(NSString *root,
                                      NSDictionary *proof,
                                      NSData *key,
                                      NSData *context,
                                      NSError **error)
{
    if(!proof || ![context isKindOfClass:NSData.class] || context.length!=32)
    {
        return NXROMFail(error,@"Invalid boot signing identity fingerprint.");
    }
    return NXROMWriteSealInternal(root,proof,key,context,error);
}

#endif /* NX_ROM_BOOTLOADER */
