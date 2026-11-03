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

#import "NXBootCertificate.h"
#import "NXBootLockdown.h"

#if NX_ROM_BOOTLOADER
#if __has_include(<OpenSSL/cms.h>)
#include <OpenSSL/cms.h>
#include <OpenSSL/pkcs12.h>
#include <OpenSSL/provider.h>
#else
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#endif /* NX_ROM_BOOTLOADER */

#import <CommonCrypto/CommonDigest.h>

NX_BOOT_ONLY static NSData *NXBootCertFail(NSError **error,
                                           NSString *message)
{
    if(error)
    {
        *error=[NSError errorWithDomain:@"org.emexlabs.nyxian.boot-signing" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    }
    return nil;
}

NX_BOOT_ONLY NSData *NXBootValidateSigningIdentity(NSData *pkcs12,
                                                   NSString *password,
                                                   NSData *profile,
                                                   NSString *bundleIdentifier,
                                                   NSDate *now,
                                                   NSError **error)
{
    if(!pkcs12.length || pkcs12.length > 16 * 1024 * 1024)
    {
        return NXBootCertFail(error, @"Import the .p12 or .pfx certificate used to sign Nyxian.");
    }
    
    if(!profile.length || profile.length > 16 * 1024 * 1024)
    {
        return NXBootCertFail(error, @"Nyxian has no valid embedded.mobileprovision. Reinstall Nyxian with a valid provisioning profile.");
    }
    
    static dispatch_once_t once;
    dispatch_once(&once,^{ OSSL_PROVIDER_load(NULL,"default"); OSSL_PROVIDER_load(NULL,"legacy"); });
    const unsigned char *p = pkcs12.bytes;
    PKCS12 *container = d2i_PKCS12(NULL,&p,(long)pkcs12.length);
    if(!container || p != (const unsigned char *)pkcs12.bytes + pkcs12.length)
    {
        PKCS12_free(container);
        return NXBootCertFail(error, @"The selected file is not a valid PKCS#12 certificate.");
    }
    
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    int imported = PKCS12_parse(container, (password ?: @"").UTF8String,&key,&certificate,NULL);
    PKCS12_free(container);
    if(imported != 1 || !key || !certificate || X509_check_private_key(certificate,key) != 1)
    {
        EVP_PKEY_free(key);
        X509_free(certificate);
        return NXBootCertFail(error, @"Could not unlock the certificate and matching private key. Check the certificate password.");
    }
    
    EVP_PKEY_free(key);
    time_t date = (time_t)now.timeIntervalSince1970;
    if(X509_cmp_time(X509_get0_notBefore(certificate), &date) >= 0 || X509_cmp_time(X509_get0_notAfter(certificate), &date) <= 0)
    {
        X509_free(certificate);
        return NXBootCertFail(error, @"The signing certificate is expired or not yet valid. Import a current certificate matching Nyxian's provisioning profile.");
    }
    
    ASN1_OBJECT *developmentOID = OBJ_txt2obj("1.2.840.113635.100.6.1.2", 1);
    BOOL development = developmentOID && X509_get_ext_by_OBJ(certificate, developmentOID, -1) >= 0;
    ASN1_OBJECT_free(developmentOID);
    if(!development)
    {
        X509_free(certificate);
        return NXBootCertFail(error, @"Only an Apple Development or iPhone Developer certificate can be used. Distribution and Developer ID certificates are not supported.");
    }
    
    int length = i2d_X509(certificate,NULL);
    NSMutableData *der = length>0 ? [NSMutableData dataWithLength:(NSUInteger)length] : nil;
    unsigned char *encoded = der.mutableBytes;
    BOOL encodedOK = der && i2d_X509(certificate, &encoded) == length;
    X509_free(certificate);
    if(!encodedOK)
    {
        return NXBootCertFail(error, @"Could not read the signing certificate.");
    }
    
    p = profile.bytes;
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &p, (long)profile.length);
    BIO *output = BIO_new(BIO_s_mem());
    BOOL cmsOK = cms && p == (const unsigned char *)profile.bytes+profile.length && output && CMS_verify(cms,NULL,NULL,NULL,output, CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) == 1;
    NSData *plist = nil;
    if(cmsOK)
    {
        BUF_MEM *memory = NULL; BIO_get_mem_ptr(output, &memory);
        if(memory && memory->length && memory->length <= 16 * 1024 * 1024)
        {
            plist=[NSData dataWithBytes:memory->data length:memory->length];
        }
    }
    
    BIO_free(output);
    CMS_ContentInfo_free(cms);
    id decoded = plist ? [NSPropertyListSerialization propertyListWithData:plist options:NSPropertyListImmutable format:NULL error:NULL] : nil;
    if(![decoded isKindOfClass:NSDictionary.class])
    {
        return NXBootCertFail(error, @"Nyxian's embedded provisioning profile has an invalid CMS signature or payload. Reinstall Nyxian with a valid profile.");
    }
    
    NSDictionary *body = decoded;
    id expires = body[@"ExpirationDate"], created = body[@"CreationDate"];
    if(![expires isKindOfClass:NSDate.class] || ![created isKindOfClass:NSDate.class] || [expires compare:now] != NSOrderedDescending || [created compare:now] == NSOrderedDescending)
    {
        return NXBootCertFail(error, @"Nyxian's provisioning profile is expired or not yet valid. Re-sign and reinstall Nyxian with a current profile.");
    }
    
    id debug = [body[@"Entitlements"] isKindOfClass:NSDictionary.class] ? body[@"Entitlements"][@"get-task-allow"] : nil;
    if(!debug || CFGetTypeID((__bridge CFTypeRef)debug) != CFBooleanGetTypeID() || ![debug boolValue])
    {
        return NXBootCertFail(error, @"Nyxian must use a development provisioning profile with get-task-allow enabled. Reinstall it using a development certificate/profile.");
    }
    
    NSArray *certificates = body[@"DeveloperCertificates"];
    BOOL matches = NO;
    if([certificates isKindOfClass:NSArray.class])
    {
        for(id allowed in certificates)
        {
            if([allowed isKindOfClass:NSData.class] && [allowed isEqual:der])
            {
                matches=YES; break;
            }
        }
    }
    
    if(!matches)
    {
        return NXBootCertFail(error, @"This certificate is not included in Nyxian's embedded provisioning profile. Import a matching certificate and private key.");
    }
    
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    static NSData *hostDigest;
    static dispatch_once_t hostOnce;
    dispatch_once(&hostOnce, ^{
        NSData *executable = [NSData dataWithContentsOfURL:NSBundle.mainBundle.executableURL options:NSDataReadingMappedIfSafe error:nil];
        if(!executable.length)
        {
            return;
        }
        unsigned char value[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(executable.bytes,(CC_LONG)executable.length,value);
        hostDigest = [NSData dataWithBytes:value length:sizeof(value)];
    });
    NSData *installation = [NSBundle.mainBundle.bundleURL.path dataUsingEncoding:NSUTF8StringEncoding];
    if(!hostDigest || !installation.length)
    {
        return NXBootCertFail(error, @"Could not identify the installed bootloader for ROM signing.");
    }
    const char domain[] = "NXROM-SIGNING-CONTEXT-v2";
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    CC_SHA256_Update(&hash, domain, sizeof(domain));
    CC_SHA256_Update(&hash, der.bytes, (CC_LONG)der.length);
    CC_SHA256_Update(&hash, profile.bytes, (CC_LONG)profile.length);
    CC_SHA256_Update(&hash, hostDigest.bytes,(CC_LONG)hostDigest.length);
    CC_SHA256_Update(&hash, installation.bytes, (CC_LONG)installation.length);
    CC_SHA256_Final(digest, &hash);
    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

#endif /* NX_ROM_BOOTLOADER */
