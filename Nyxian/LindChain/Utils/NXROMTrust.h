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

#ifndef NXROMTRUST_H
#define NXROMTRUST_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NSDictionary * _Nullable NXROMArchiveProof(NSString *path, NSError **error);
NSDictionary * _Nullable NXROMArchiveProofForFD(int fd, NSError **error);
NSDictionary * _Nullable NXROMSealedReleaseProof(NSString *root, NSData *deviceKey, NSError **error);
NSData * _Nullable NXROMSealedSigningContext(NSString *root, NSData *deviceKey, NSError **error);
NSDictionary * _Nullable NXROMSealedReleaseIdentity(NSString *root, NSData *deviceKey, NSError **error);
BOOL NXROMVerifySeal(NSString *root, NSData *deviceKey, BOOL requireVendor, NSError **error);
BOOL NXROMVerifySealedFile(NSString *root, NSString *relativePath, NSData *deviceKey, NSError **error);

#if NX_ROM_BOOTLOADER

BOOL NXROMWriteSealWithSigningContext(NSString *root, NSDictionary *proof, NSData *deviceKey, NSData *context, NSError **error);
BOOL NXROMWriteSeal(NSString *root, NSDictionary * _Nullable proof, NSData *deviceKey, NSError **error);

#endif /* NX_ROM_BOOTLOADER */

NS_ASSUME_NONNULL_END

#endif /* NXROMTRUST_H */
