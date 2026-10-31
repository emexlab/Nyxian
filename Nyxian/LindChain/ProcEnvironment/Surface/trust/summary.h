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

#ifndef TRUST_SUMMARY_H
#define TRUST_SUMMARY_H

#import <Foundation/Foundation.h>
#import <LindChain/ProcEnvironment/Surface/trust/entitlement.h>

typedef NS_ENUM(NSUInteger, KSNXT2Section) {
    KSNXT2SectionIdentity = 0,
    KSNXT2SectionProcesses,
    KSNXT2SectionDebugging,
    KSNXT2SectionFilesystem,
    KSNXT2SectionServices,
    KSNXT2SectionManagement,
    KSNXT2SectionStealth,
    KSNXT2SectionTrust,
    KSNXT2SectionUnrecognized,
    KSNXT2SectionCount
};

static NSString *const kKSNXT2SectionTitles[KSNXT2SectionCount] = {
    @"Identity",
    @"Processes",
    @"Debugging",
    @"Filesystem",
    @"Services",
    @"System Management",
    @"Stealth",
    @"Trust",
    @"Unrecognized Entitlements",
};

typedef NS_ENUM(NSUInteger, KSNXT2Severity) {
    KSNXT2SeverityInfo = 0,
    KSNXT2SeverityNote,
    KSNXT2SeverityWarn,
    KSNXT2SeverityCrit,
};

typedef NS_ENUM(NSUInteger, KSNXT2ValueKind) {
    KSNXT2ValueBool = 0,
    KSNXT2ValueString,
    KSNXT2ValueInteger,
    KSNXT2ValueStringArray,
    KSNXT2ValuePathArray,
};

typedef struct {
    CFStringRef         identifier;
    KSNXT2Section       section;
    KSNXT2ValueKind     kind;
    KSNXT2Severity      severity;
    BOOL                restrictive;
    CFStringRef         summary;
} KSNXT2Descriptor;

typedef struct {
    BOOL            active;
    CFStringRef     required[4];
} KSNXT2RuleSet;

typedef struct {
    KSNXT2RuleSet   set[4];
    KSNXT2Section   section;
    KSNXT2Severity  severity;
    CFStringRef     summary;
} KSNXT2Rule;

NSAttributedString *KSurfaceNXT2CreateEntitlementSummary(NSDictionary *entitlements);

#endif /* TRUST_SUMMARY_H */
