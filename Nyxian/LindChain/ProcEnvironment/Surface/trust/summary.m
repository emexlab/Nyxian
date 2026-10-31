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

#import <LindChain/ProcEnvironment/Surface/trust/summary.h>
#import <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#import <UIKit/UIKit.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

static BOOL KSNXT2ValueIsAsserted(id value,
                                  KSNXT2ValueKind kind)
{
    switch(kind)
    {
        case KSNXT2ValueBool:
            return [value isKindOfClass:NSNumber.class] && ((NSNumber *)value).boolValue;
        case KSNXT2ValueString:
            return [value isKindOfClass:NSString.class] && ((NSString *)value).length > 0;
        case KSNXT2ValueInteger:
            return [value isKindOfClass:NSNumber.class] && CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID();
        case KSNXT2ValueStringArray:
        case KSNXT2ValuePathArray:
            return [value isKindOfClass:NSArray.class] && ((NSArray *)value).count > 0;
    }
    return NO;
}

static NSString *KSNXT2FormatPaths(NSArray *raw,
                                   KSNXT2Severity *severityInOut,
                                   KSNXT2Section section,
                                   NXT2Entitlement entitlement)
{
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    for(id entry in raw)
    {
        if(![entry isKindOfClass:NSString.class])
        {
            continue;
        }
        NSString *p = ((NSString *)entry).stringByStandardizingPath;
        if(p.length)
        {
            [paths addObject:p];
        }
    }
    
    [paths sortUsingSelector:@selector(compare:)];
    
    NSMutableArray<NSString *> *collapsed = [NSMutableArray array];
    for(NSString *p in paths)
    {
        if(section == KSNXT2SectionFilesystem)
        {
            NSString *prefix = collapsed.lastObject;
            BOOL covered = prefix && ([p isEqualToString:prefix] || [p hasPrefix:[prefix hasSuffix:@"/"] ? prefix : [prefix stringByAppendingString:@"/"]]);
            if(!covered)
            {
                [collapsed addObject:p];
            }
        }
        else if(section == KSNXT2SectionServices)
        {
            if([p hasPrefix:@"org.emexlabs."])
            {
                *severityInOut = [(__bridge NSString*)entitlement isEqualToString:(__bridge NSString*)kNXT2EntitlementLaunchServicesSetEndpointAllowList] ? KSNXT2SeverityCrit : KSNXT2SeverityWarn;
            }
            [collapsed addObject:p];
        }
    }
    
    if(section == KSNXT2SectionFilesystem)
    {
        *severityInOut = KSNXT2SeverityCrit;    /* any appended file system access shall be treated as ab critical entitlement */
    }
    
    return [NSListFormatter localizedStringByJoiningStrings:collapsed];
}

static NSString *KSNXT2FormatIdentity(NSNumber *value,
                                      KSNXT2Severity *severityInOut)
{
    if(value.longValue == 0)
    {
        *severityInOut = KSNXT2SeverityCrit;
    }
    return [NSString stringWithFormat:@"%@", value];
}

static NSDictionary *KSNXT2AttributesForSeverity(KSNXT2Severity severity)
{
    static NSMutableParagraphStyle *left;
    static UIColor *warn, *crit;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        left = [NSMutableParagraphStyle new];
        left.alignment = NSTextAlignmentLeft;
        warn = [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *tc) {
            return tc.userInterfaceStyle == UIUserInterfaceStyleDark ? UIColor.systemYellowColor : UIColor.systemOrangeColor;
        }];
        crit = [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *tc) {
            return tc.userInterfaceStyle == UIUserInterfaceStyleDark ? UIColor.systemOrangeColor : UIColor.systemRedColor;
        }];
    });
    
    NSMutableDictionary *attrs = [@{
        NSFontAttributeName: [UIFont systemFontOfSize:11.0],
        NSParagraphStyleAttributeName: left,
    } mutableCopy];
    
    if(severity == KSNXT2SeverityWarn)
    {
        attrs[NSForegroundColorAttributeName] = warn;
    }
    if(severity == KSNXT2SeverityCrit)
    {
        attrs[NSForegroundColorAttributeName] = crit;
    }
    return attrs;
}

static NSDictionary *KSNXT2HeaderAttributes(void)
{
    NSMutableParagraphStyle *left = [NSMutableParagraphStyle new];
    left.alignment = NSTextAlignmentLeft;
    return @{ NSFontAttributeName: [UIFont boldSystemFontOfSize:14.0], NSParagraphStyleAttributeName: left };
}

typedef struct {
    KSNXT2Severity severity;
    __unsafe_unretained NSString *text;
} KSNXT2Line;

LIBKERN_DEFINE_PATCHABLE(NSAttributedString*, KSurfaceNXT2CreateEntitlementSummary, (NSDictionary *entitlements))
{
    const KSNXT2Descriptor kKSNXT2Descriptors[] = {
        { kNXT2EntitlementPlatform, KSNXT2SectionIdentity, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Runs as a platform process and is exempt from some restrictions.") },
        { kNXT2EntitlementPlatformRoot, KSNXT2SectionIdentity, KSNXT2ValueBool, KSNXT2SeverityCrit, NO, CFSTR("Runs with root privileges.") },
        { kNXT2EntitlementPlatformUser, KSNXT2SectionIdentity, KSNXT2ValueInteger, KSNXT2SeverityNote, NO, CFSTR("Runs as user %@.") },
        { kNXT2EntitlementPlatformGroup, KSNXT2SectionIdentity, KSNXT2ValueInteger, KSNXT2SeverityNote, NO, CFSTR("Runs as group %@.") },
        { kNXT2EntitlementSUGID, KSNXT2SectionIdentity, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can change its own user and group identity while running.") },
        { kNXT2EntitlementProcessEnumeration, KSNXT2SectionProcesses, KSNXT2ValueBool, KSNXT2SeverityNote, NO, CFSTR("Can see every process running in Nyxian.") },
        { kNXT2EntitlementProcessKill, KSNXT2SectionProcesses, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can terminate and signal processes.") },
        { kNXT2EntitlementProcessSpawn, KSNXT2SectionProcesses, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can launch arbitrary executables.") },
        { kNXT2EntitlementProcessSpawnSignedOnly, KSNXT2SectionProcesses, KSNXT2ValueBool, KSNXT2SeverityInfo, YES, CFSTR("Executables it launches must be signed.") },
        { kNXT2EntitlementProcessSpawnInheriteEntitlements, KSNXT2SectionProcesses, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Executables it launches inherit some of its privileges.") },
        { kNXT2EntitlementGetTaskAllow, KSNXT2SectionDebugging, KSNXT2ValueBool, KSNXT2SeverityNote, NO, CFSTR("Permits other processes to inspect and modify its memory.") },
        { kNXT2EntitlementTaskForPid, KSNXT2SectionDebugging, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can inspect and modify the memory of other apps.") },
        { kNXT2EntitlementSystemTaskPorts, KSNXT2SectionDebugging, KSNXT2ValueBool, KSNXT2SeverityCrit, NO, CFSTR("Can obtain task ports for system processes.") },
        { kNXT2EntitlementSandboxNoContainer, KSNXT2SectionFilesystem, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Runs without a private container.") },
        { kNXT2EntitlementSandboxFileRead, KSNXT2SectionFilesystem, KSNXT2ValuePathArray, KSNXT2SeverityNote, NO, CFSTR("Can read: %@") },
        { kNXT2EntitlementSandboxFileReadWrite, KSNXT2SectionFilesystem, KSNXT2ValuePathArray, KSNXT2SeverityWarn, NO, CFSTR("Can read and modify: %@") },
        { kNXT2EntitlementLaunchServicesStart, KSNXT2SectionServices, KSNXT2ValueBool, KSNXT2SeverityNote, NO, CFSTR("Can start system services.") },
        { kNXT2EntitlementLaunchServicesStop, KSNXT2SectionServices, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can stop system services.") },
        { kNXT2EntitlementLaunchServicesToggle, KSNXT2SectionServices, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can enable and disable system services.") },
        { kNXT2EntitlementLaunchServicesGetEndpoint, KSNXT2SectionServices, KSNXT2ValueBool, KSNXT2SeverityCrit, NO, CFSTR("Can look up the endpoint of arbitary service running in Nyxian.") },
        { kNXT2EntitlementLaunchServicesSetEndpoint, KSNXT2SectionServices, KSNXT2ValueBool, KSNXT2SeverityCrit, NO, CFSTR("Can redirect service endpoints of some 3rd party services to code of its own.") },
        { kNXT2EntitlementManagementHost, KSNXT2SectionManagement, KSNXT2ValueBool, KSNXT2SeverityWarn, NO, CFSTR("Can overwrite the hostname (as of now).") },
        { kNXT2EntitlementLaunchServicesGetEndpointAllowList, KSNXT2SectionServices, KSNXT2ValuePathArray, KSNXT2SeverityNote, NO, CFSTR("Can look up service endpoints: %@") },
        { kNXT2EntitlementLaunchServicesSetEndpointAllowList, KSNXT2SectionServices, KSNXT2ValuePathArray, KSNXT2SeverityWarn, NO, CFSTR("Can redirect service service endpoints: %@") },
        { kNXT2EntitlementKsurfaceKEXTLoading, KSNXT2SectionTrust, KSNXT2ValueBool, KSNXT2SeverityCrit, NO, CFSTR("Can run code in Nyxians address space and can pose a huge security risk and threat to your data as well as primitives of other apps you use, use this app only if you truly know what it does and what you do.") },
        { kNXT2EntitlementSandboxHost, KSNXT2SectionFilesystem, KSNXT2ValueBool, KSNXT2SeverityCrit, NO, CFSTR("Can read and write everything ksurface can, this is a SERIOUS ENTITLEMENT cause it means nothing holds it in place, not even the vmount's.") },
    };

    static const size_t kKSNXT2DescriptorCount = sizeof(kKSNXT2Descriptors) / sizeof(kKSNXT2Descriptors[0]);
    
    const KSNXT2Rule kKSNXT2Rules[] = {
        {
            {
                {
                    .active = YES,
                    { kNXT2EntitlementPlatform, kNXT2EntitlementPlatformRoot, kNXT2EntitlementProcessSpawn, kNXT2EntitlementProcessSpawnInheriteEntitlements },
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
            },
            KSNXT2SectionProcesses, KSNXT2SeverityCrit,
            CFSTR("Can run any code it wants as root, with most privileges listed here."),
        },
        {
            {
                {
                    .active = YES,
                    { kNXT2EntitlementSUGID, kNXT2EntitlementProcessSpawn, NULL },
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
            },
            KSNXT2SectionProcesses, KSNXT2SeverityCrit,
            CFSTR("Can launch executables under any identity, including root."),
        },
        {
            {
                {
                    .active = YES,
                    { kNXT2EntitlementProcessSpawnSignedOnly, NULL },
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
            },
            KSNXT2SectionProcesses, KSNXT2SeverityWarn,
            CFSTR("Can launch executables, but only signed ones."),
        },
        {
            {
                {
                    .active = YES,
                    { kNXT2EntitlementTaskForPid, kNXT2EntitlementSystemTaskPorts, NULL },
                },
                {
                    .active = YES,
                    { kNXT2EntitlementTaskForPid, kNXT2EntitlementPlatform, kNXT2EntitlementPlatformRoot, NULL },
                },
                {
                    .active = YES,
                    { kNXT2EntitlementTaskForPid, kNXT2EntitlementPlatform, kNXT2EntitlementSUGID, NULL },
                },
                {
                    .active = NO,
                },
            },
            KSNXT2SectionDebugging, KSNXT2SeverityCrit,
            CFSTR("Can read and modify the memory and state of any process running in Nyxian, including Nyxian's daemons and services."),
        },
        {
            {
                {
                    .active = YES,
                    { kNXT2EntitlementTaskForPid, kNXT2EntitlementSUGID, NULL },
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
                {
                    .active = NO,
                },
            },
            KSNXT2SectionDebugging, KSNXT2SeverityCrit,
            CFSTR("Can read and modify the memory and state of any process running in Nyxian"),
        },
    };

    static const size_t kKSNXT2RuleCount = sizeof(kKSNXT2Rules) / sizeof(kKSNXT2Rules[0]);
    
    NSMutableArray<NSMutableArray *> *lines = [NSMutableArray array];
    for(NSUInteger i = 0; i < KSNXT2SectionCount; i++)
    {
        [lines addObject:[NSMutableArray array]];
    }
    
    NSMutableSet<NSString *> *asserted = [NSMutableSet set];
    NSMutableSet<NSString *> *known = [NSMutableSet set];
    for(size_t i = 0; i < kKSNXT2DescriptorCount; i++)
    {
        NSString *ident = (__bridge NSString *)kKSNXT2Descriptors[i].identifier;
        [known addObject:ident];
        if(KSNXT2ValueIsAsserted(entitlements[ident], kKSNXT2Descriptors[i].kind))
        {
            [asserted addObject:ident];
        }
    }
    
    NSMutableSet<NSString *> *consumed = [NSMutableSet set];
    for(size_t r = 0; r < kKSNXT2RuleCount; r++)
    {
        const KSNXT2Rule *rule = &kKSNXT2Rules[r];
        BOOL matches = YES;
        for(int i = 0; i < 4 && rule->set[i].active && matches; i++)
        {
            for(int j = 0; j < 4 && rule->set[i].required[j] && matches; j++)
            {
                NSString *ident = (__bridge NSString *)rule->set[i].required[j];
                if(![asserted containsObject:ident] || [consumed containsObject:ident])
                {
                    matches = NO;
                }
            }
            if(matches)
            {
                for(int j = 0; j < 4 && rule->set[i].required[j] && matches; j++)
                {
                    NSString *ident = (__bridge NSString *)rule->set[i].required[j];
                    [consumed addObject:ident];
                }
                break;
            }
        }
        if(!matches)
        {
            continue;
        }
        [lines[rule->section] addObject:@[ @(rule->severity), (__bridge NSString *)rule->summary ]];
    }
    
    for(size_t i = 0; i < kKSNXT2DescriptorCount; i++)
    {
        const KSNXT2Descriptor *desc = &kKSNXT2Descriptors[i];
        NSString *ident = (__bridge NSString *)desc->identifier;
        if(![asserted containsObject:ident] || [consumed containsObject:ident])
        {
            continue;
        }
        if(desc->restrictive)
        {
            continue;
        }
        
        KSNXT2Severity severity = desc->severity;
        NSString *format = (__bridge NSString *)desc->summary;
        NSString *text;
        
        switch(desc->kind)
        {
            case KSNXT2ValuePathArray:
                text = [NSString stringWithFormat:format, KSNXT2FormatPaths(entitlements[ident], &severity, desc->section, desc->identifier)];
                break;
            case KSNXT2ValueStringArray:
                text = [NSString stringWithFormat:format, [NSListFormatter localizedStringByJoiningStrings:entitlements[ident]]];
                break;
            case KSNXT2ValueInteger:
                text = [NSString stringWithFormat:format, KSNXT2FormatIdentity(entitlements[ident], &severity)];
                break;
            case KSNXT2ValueBool:
                text = format;
                break;
        }
        [lines[desc->section] addObject:@[ @(severity), text ]];
    }
    
    for(NSString *ident in entitlements)
    {
        if([known containsObject:ident])
        {
            continue;
        }
        [lines[KSNXT2SectionUnrecognized] addObject:@[ @(KSNXT2SeverityCrit), [NSString stringWithFormat:@"%@, not recognised by this version.", ident] ]];
    }
    
    NSMutableAttributedString *attributedString = [NSMutableAttributedString new];
    BOOL first = YES;
    for(NSUInteger s = 0; s < KSNXT2SectionCount; s++)
    {
        NSArray *sectionLines = lines[s];
        if(!sectionLines.count)
        {
            continue;
        }
        
        sectionLines = [sectionLines sortedArrayUsingComparator:^NSComparisonResult(NSArray *a, NSArray *b) {
            return [b[0] compare:a[0]];
        }];
        
        [attributedString appendAttributedString:[[NSAttributedString alloc] initWithString:(first ? kKSNXT2SectionTitles[s] : [@"\n\n" stringByAppendingString:kKSNXT2SectionTitles[s]]) attributes:KSNXT2HeaderAttributes()]];
        first = NO;
        
        for(NSArray *line in sectionLines)
        {
            [attributedString appendAttributedString:[[NSAttributedString alloc] initWithString:[@"\n" stringByAppendingString:line[1]] attributes:KSNXT2AttributesForSeverity((KSNXT2Severity)[line[0] unsignedIntegerValue])]];
        }
    }
    
    if(attributedString.length == 0)
    {
        [attributedString appendAttributedString:[[NSAttributedString alloc] initWithString:@"This app requests no special privileges." attributes:KSNXT2AttributesForSeverity(KSNXT2SeverityInfo)]];
    }
    
    return [attributedString copy];
}
