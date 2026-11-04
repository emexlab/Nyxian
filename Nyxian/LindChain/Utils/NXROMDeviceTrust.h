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

#ifndef NXROMDEVICETRUST_H
#define NXROMDEVICETRUST_H

#import "NXROMTrust.h"
#import "NXROMRollback.h"

NS_ASSUME_NONNULL_BEGIN

BOOL NXROMDeviceVerify(NSString *root, BOOL requireVendor, NSError **error);
BOOL NXROMDeviceCheckRollback(NSString *root, BOOL allowUninitialized, NSError **error);
NSDictionary * _Nullable NXROMDeviceReleaseProof(NSString *root, NSError **error);
NSData * _Nullable NXROMDeviceSigningContext(NSString *root, NSError **error);
BOOL NXROMDeviceVerifyOTAExecutable(NSString *root, NSString *path);

#if NX_ROM_BOOTLOADER

BOOL NXROMDeviceManualCommitRollback(NSString *root, NSError **error);
BOOL NXROMDeviceCommitRollback(NSString *root, NSError **error);
BOOL NXROMDeviceSeal(NSString *root, NSDictionary * _Nullable proof, NSData *context, NSError **error);
BOOL NXROMDeviceCheckRevocation(NSString *root, NSError **error);

#endif /* NX_ROM_BOOTLOADER */

NS_ASSUME_NONNULL_END

#endif /* NXROMDEVICETRUST_H */
