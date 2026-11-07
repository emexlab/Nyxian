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

#ifndef NXROMTICKET_H
#define NXROMTICKET_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#if NX_ROM_BOOTLOADER

NSURL *NXROMTicketServerURL(void);

NSData * _Nullable NXROMTicketNewNonce(void);
NSData * _Nullable NXROMTicketRequestBody(NSString *rom, NSData *digest, NSData *nonce, NSError **error);
NSDictionary * _Nullable NXROMTicketVerify(NSData *ticket, NSString *rom, NSData *digest, NSData * _Nullable nonce, NSError **error);

#endif /* NX_ROM_BOOTLOADER */

NS_ASSUME_NONNULL_END

#endif /* NXROMTICKET_H */
