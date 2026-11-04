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

#import "NXROMDeviceTrust.h"
#import "NXBootLockdown.h"
#if NX_ROM_BOOTLOADER
#import "NXTrustStore.h"
#endif
#import <LindChain/ProcEnvironment/Surface/key.h>
#include <stdlib.h>
#include <string.h>

static NSMutableData *NXROMDeviceKey(void)
{
    uint8_t *priv = NULL, *pub = NULL;
    size_t privlen = 0, publen = 0;
    BOOL ok = get_static_kernel_key(&priv, &privlen, &pub, &publen);
    NSMutableData *key = ok && priv && privlen ? [NSMutableData dataWithBytes:priv length:privlen] : nil;
    if(priv)
    {
        volatile uint8_t *wipe = priv;
        for(size_t i = 0; i < privlen; i++)
        {
            wipe[i] = 0;
        }
        free(priv);
    }
    if(pub)
    {
        free(pub);
    }
    return key;
}

BOOL NXROMDeviceVerify(NSString *root,
                       BOOL requireVendor,
                       NSError **error)
{
    NSMutableData *key = NXROMDeviceKey();
    BOOL ok = NXROMVerifySeal(root, key ?: NSData.data, requireVendor, error);
    [key resetBytesInRange:NSMakeRange(0, key.length)];
    return ok;
}

static NSDictionary *NXROMDeviceIdentity(NSString *root,
                                         NSError **error)
{
    NSMutableData *key = NXROMDeviceKey();
    NSDictionary *identity = NXROMSealedReleaseIdentity(root, key ?: NSData.data, error);
    [key resetBytesInRange:NSMakeRange(0,key.length)];
    return identity;
}

BOOL NXROMDeviceCheckRollback(NSString *root,
                              BOOL allowUninitialized,
                              NSError **error)
{
    NSDictionary *identity = NXROMDeviceIdentity(root, error);
    return identity && NXROMRollbackCheckForIdentifier(identity[@"identifier"], [identity[@"securityVersion"] unsignedLongLongValue], identity[@"digest"], allowUninitialized, error);
}
NSDictionary *NXROMDeviceReleaseProof(NSString *root,
                                      NSError **error)
{
    NSMutableData *key = NXROMDeviceKey();
    NSDictionary *proof = NXROMSealedReleaseProof(root, key ?: NSData.data, error);
    [key resetBytesInRange:NSMakeRange(0, key.length)];
    return proof;
}

NSData *NXROMDeviceSigningContext(NSString *root,
                                  NSError **error)
{
    NSMutableData *key = NXROMDeviceKey();
    NSData *context = NXROMSealedSigningContext(root, key ?: NSData.data, error);
    [key resetBytesInRange:NSMakeRange(0, key.length)];
    return context;
}

BOOL NXROMDeviceVerifyOTAExecutable(NSString *root,
                                    NSString *path)
{
    NSString *expected = [root stringByAppendingPathComponent:@"binpack/usr/bin/otaupd"].stringByStandardizingPath.stringByResolvingSymlinksInPath;
    if(![path.stringByStandardizingPath.stringByResolvingSymlinksInPath isEqual:expected])
    {
        return NO;
    }
    
    NSMutableData *key = NXROMDeviceKey();
    BOOL ok = NXROMVerifySealedFile(root, @"binpack/usr/bin/otaupd", key ?: NSData.data, NULL);
    [key resetBytesInRange:NSMakeRange(0,key.length)];
    return ok;
}

#if NX_ROM_BOOTLOADER

NX_BOOT_ONLY BOOL NXROMDeviceManualCommitRollback(NSString *root,
                                                  NSError **error)
{
    if(!NXROMDeviceVerify(root, YES, error))
    {
        return NO;
    }
    
    NSDictionary *identity = NXROMDeviceIdentity(root, error);
    return identity && NXROMRollbackBootManualCommitForIdentifier(identity[@"identifier"], [identity[@"securityVersion"] unsignedLongLongValue], identity[@"digest"], error);
}

NX_BOOT_ONLY BOOL NXROMDeviceCommitRollback(NSString *root,
                                            NSError **error)
{
    NSDictionary *identity = NXROMDeviceIdentity(root, error);
    return identity && NXROMRollbackBootCommitForIdentifier(identity[@"identifier"], [identity[@"securityVersion"] unsignedLongLongValue], identity[@"digest"], error);
}

NX_BOOT_ONLY BOOL NXROMDeviceSeal(NSString *root,
                                  NSDictionary *proof,
                                  NSData *context,
                                  NSError **error)
{
    NSMutableData *key = NXROMDeviceKey();
    BOOL ok = NXROMWriteSealWithSigningContext(root, proof, key ?: NSData.data, context, error);
    [key resetBytesInRange:NSMakeRange(0, key.length)];
    return ok;
}

BOOL NXROMDeviceCheckRevocation(NSString *root,
                                NSError **error)
{
    NSDictionary *proof = NXROMDeviceReleaseProof(root, error);
    if(proof == nil)
    {
        return NO;
    }
    if(NXTrustStoreReleaseRevocation(proof[@"digest"]) == NXTrustStoreRevocationBoot)
    {
        if(error)
        {
            *error = [NSError errorWithDomain:@"org.emexlabs.rom.signature" code:2 userInfo:@{NSLocalizedDescriptionKey:@"This ROM release was revoked by its publisher and can't boot anymore. Install a newer release."}];
        }
        return NO;
    }
    return YES;
}

#endif /* NX_ROM_BOOTLOADER */
