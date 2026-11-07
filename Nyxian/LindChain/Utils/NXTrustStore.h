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

#ifndef NXTRUSTSTORE_H
#define NXTRUSTSTORE_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#if NX_ROM_BOOTLOADER

typedef NS_ENUM(NSInteger, NXTrustStoreRevocation) {
    NXTrustStoreRevocationNone = 0,
    NXTrustStoreRevocationInstall = 1,
    NXTrustStoreRevocationBoot = 2,
};

NXTrustStoreRevocation NXTrustStoreReleaseRevocation(NSData *digest);

NSArray<NSDictionary *> *NXTrustStoreTrustedKeys(void);
NSArray<NSDictionary *> *NXTrustStoreTSSKeys(void);
NSDictionary *NXTrustStoreStatus(void);
NSDictionary * _Nullable NXTrustStoreParse(NSData *data, NSError **error);
BOOL NXTrustStoreInstall(NSData *data, NSError **error);
BOOL NXTrustStoreCommitFloor(NSError **error);
NSString *NXTrustStoreDownloadedPath(void);
NSURL *NXTrustStoreUpdateURL(void);

#endif /* NX_ROM_BOOTLOADER */

NS_ASSUME_NONNULL_END

#endif /* NXTRUSTSTORE_H */
