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

#import "NXROMTicket.h"

#if NX_ROM_BOOTLOADER

#import "NXTrustStore.h"
#import "NXDeviceIdentity.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

static const char NXROMTicketDomain[] = "NXROM-TSS-TICKET-v1";
static const NSUInteger NXROMTicketMaxSize = 64 * 1024;

static id NXROMTicketFail(NSError **error,
                          NSInteger code,
                          NSString *message)
{
    if(error)
    {
        *error = [NSError errorWithDomain:@"org.emexlabs.rom.ticket" code:code userInfo:@{NSLocalizedDescriptionKey:message}];
    }
    return nil;
}

static NSString *NXROMTicketHex(NSData *data)
{
    const unsigned char *bytes = data.bytes;
    NSMutableString *text = [NSMutableString stringWithCapacity:data.length * 2];
    for(NSUInteger i = 0; i < data.length; i++)
    {
        [text appendFormat:@"%02x", bytes[i]];
    }
    return text;
}

NSURL *NXROMTicketServerURL(void)
{
    return [NSURL URLWithString:@"https://developer.emexlabs.org/api/v1/tss"];
}

NSData *NXROMTicketNewNonce(void)
{
    NSMutableData *nonce = [NSMutableData dataWithLength:32];
    if(SecRandomCopyBytes(kSecRandomDefault, nonce.length, nonce.mutableBytes) != errSecSuccess)
    {
        return nil;
    }
    return nonce;
}

NSData *NXROMTicketRequestBody(NSString *rom,
                               NSData *digest,
                               NSData *nonce,
                               NSError **error)
{
    NSString *uniqueID = NXDeviceUniqueID(error);
    if(uniqueID == nil)
    {
        return nil;
    }
    if(digest.length != CC_SHA256_DIGEST_LENGTH || nonce.length != 32)
    {
        return NXROMTicketFail(error, 1, @"Can't ask for an install ticket without the release's digest and a nonce.");
    }
    return [NSJSONSerialization dataWithJSONObject:@{@"uniqueID":uniqueID, @"rom":rom, @"digest":NXROMTicketHex(digest), @"nonce":NXROMTicketHex(nonce)} options:0 error:error];
}

NSDictionary *NXROMTicketVerify(NSData *ticket,
                                NSString *rom,
                                NSData *digest,
                                NSData *nonce,
                                NSError **error)
{
    if(![ticket isKindOfClass:NSData.class] || ticket.length == 0 || ticket.length > NXROMTicketMaxSize)
    {
        return NXROMTicketFail(error, 2, @"The install ticket is missing or too large.");
    }
    
    id envelope = [NSPropertyListSerialization propertyListWithData:ticket options:NSPropertyListImmutable format:NULL error:NULL];
    NSData *payload = [envelope isKindOfClass:NSDictionary.class] ? envelope[@"payload"] : nil;
    NSData *signature = [envelope isKindOfClass:NSDictionary.class] ? envelope[@"signature"] : nil;
    NSData *keyID = [envelope isKindOfClass:NSDictionary.class] ? envelope[@"key"] : nil;
    if(![envelope isKindOfClass:NSDictionary.class] || ![envelope[@"format"] isEqual:@1] ||
       ![payload isKindOfClass:NSData.class] || ![signature isKindOfClass:NSData.class] || ![keyID isKindOfClass:NSData.class] ||
       signature.length < 8 || signature.length > 72 || keyID.length != CC_SHA256_DIGEST_LENGTH)
    {
        return NXROMTicketFail(error, 2, @"The install ticket is malformed.");
    }
    
    NSData *publicKey = nil;
    for(NSDictionary *entry in NXTrustStoreTSSKeys())
    {
        if([entry[@"id"] isEqual:keyID])
        {
            publicKey = entry[@"publicKey"];
            break;
        }
    }
    if(publicKey == nil)
    {
        return NXROMTicketFail(error, 3, NXTrustStoreTSSKeys().count ? @"The install ticket is signed by a key the TrustStore doesn't trust." : @"The TrustStore has no TSS key: update it, then install the ROM again.");
    }
    
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    CC_SHA256_Update(&context, NXROMTicketDomain, sizeof(NXROMTicketDomain));
    CC_SHA256_Update(&context, payload.bytes, (CC_LONG)payload.length);
    CC_SHA256_Final(hash, &context);
    NSDictionary *attributes = @{(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom, (__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPublic, (__bridge id)kSecAttrKeySizeInBits:@256};
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)publicKey, (__bridge CFDictionaryRef)attributes, NULL);
    BOOL valid = key && SecKeyVerifySignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, (__bridge CFDataRef)[NSData dataWithBytes:hash length:sizeof(hash)], (__bridge CFDataRef)signature, NULL);
    if(key)
    {
        CFRelease(key);
    }
    if(!valid)
    {
        return NXROMTicketFail(error, 3, @"The install ticket's signature doesn't verify.");
    }
    
    id body = [NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:NULL error:NULL];
    if(![body isKindOfClass:NSDictionary.class] || ![body[@"format"] isEqual:@1] ||
       ![body[@"uniqueID"] isKindOfClass:NSString.class] || ![body[@"rom"] isKindOfClass:NSString.class] ||
       ![body[@"digest"] isKindOfClass:NSData.class] || ![body[@"nonce"] isKindOfClass:NSData.class] || [body[@"nonce"] length] != 32)
    {
        return NXROMTicketFail(error, 2, @"The install ticket's payload is malformed.");
    }
    NSString *uniqueID = NXDeviceUniqueID(NULL);
    if(uniqueID == nil || ![body[@"uniqueID"] isEqualToString:uniqueID])
    {
        return NXROMTicketFail(error, 4, @"The install ticket is for another device.");
    }
    if(![body[@"rom"] isEqualToString:rom] || ![body[@"digest"] isEqualToData:digest])
    {
        return NXROMTicketFail(error, 4, @"The install ticket is for another ROM release.");
    }
    if(nonce != nil && ![body[@"nonce"] isEqualToData:nonce])
    {
        return NXROMTicketFail(error, 4, @"The install ticket was made for another install (its nonce doesn't match).");
    }
    return body;
}

#endif /* NX_ROM_BOOTLOADER */
