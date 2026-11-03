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

#import <Foundation/Foundation.h>

//! Project version number for LiveProcessLegacy.
FOUNDATION_EXPORT double LiveProcessLegacyVersionNumber;

//! Project version string for LiveProcessLegacy.
FOUNDATION_EXPORT const unsigned char LiveProcessLegacyVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <LiveProcessLegacy/PublicHeader.h>

#import <LiveProcessLegacy/LPLSyscall.h>
#import <LiveProcessLegacy/LPLUtils.h>
#import <LiveProcessLegacy/LPLVRoot.h>
#import <LiveProcessLegacy/LPLFileport.h>
#import <LiveProcessLegacy/LPLService.h>
#import <LiveProcessLegacy/LPLServiceProtocol.h>
#import <LiveProcessLegacy/LPLLSDyld.h>
#import <LiveProcessLegacy/LPLLSPatchcache.h>
