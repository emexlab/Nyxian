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

#ifndef NXROMROLLBACK_H
#define NXROMROLLBACK_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

BOOL NXROMIdentifierIsValid(id _Nullable identifier);
BOOL NXROMRollbackCheckForIdentifier(NSString *identifier, uint64_t version, NSData *digest, BOOL allowUninitialized, NSError **error);
NSNumber * _Nullable NXROMParseSecurityVersion(id _Nullable value);
BOOL NXROMRollbackCheck(uint64_t version, NSData *digest, BOOL allowUninitialized, NSError **error);

#if NX_ROM_BOOTLOADER
BOOL NXROMRollbackBootCommitForIdentifier(NSString *identifier, uint64_t version, NSData *digest, NSError **error);
BOOL NXROMRollbackBootManualCommitForIdentifier(NSString *identifier, uint64_t version, NSData *digest, NSError **error);
BOOL NXROMRollbackBootManualCommit(uint64_t version, NSData *digest, NSError **error);
BOOL NXROMRollbackBootCommit(uint64_t version, NSData *digest, NSError **error);
#endif /* NX_ROM_BOOTLOADER */

NS_ASSUME_NONNULL_END

#endif /* NXROMROLLBACK_H */
