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
#import <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#import <LindChain/ProcEnvironment/Surface/trust/presets.h>

CFDictionaryRef kPEEntitlementsNXT2PresetsKernel;
CFDictionaryRef kPEEntitlementsNXT2PresetsDaemonBootstrap;
CFDictionaryRef kPEEntitlementsNXT2PresetsDaemonCompiler;

__attribute__((constructor))
static void TrustPresetsInit(void)
{
    kPEEntitlementsNXT2PresetsKernel = (__bridge_retained CFDictionaryRef)@{
        /* platformization */
        (__bridge NSString*)kNXT2EntitlementPlatform: @(YES),   /* needed so trust layer allows creation of other platform identities */
        
        /* debugging */
        (__bridge NSString*)kNXT2EntitlementGetTaskAllow: @(NO),
    };
    
    kPEEntitlementsNXT2PresetsDaemonBootstrap = (__bridge_retained CFDictionaryRef)@{
        /* platformization */
        (__bridge NSString*)kNXT2EntitlementPlatform: @(YES),
        (__bridge NSString*)kNXT2EntitlementPlatformRoot: @(YES),
        
        /* debugging */
        (__bridge NSString*)kNXT2EntitlementGetTaskAllow: @(NO),
        
        /* management */
        (__bridge NSString*)kNXT2EntitlementManagementProcEnvironment: @(YES),  /* needed to open apps for other processes that issue a request */
        
        /* launch services */
        (__bridge NSString*)kNXT2EntitlementLaunchServicesSetEndpointAllowList: @[
            @"org.emexlabs.bootstrapd",
        ],
        
        /* sandbox */
        (__bridge NSString*)kNXT2EntitlementSandboxFileReadWrite: @[
            @"$(NXROOT)/usr/bin",               /* needs access to fastpath binaries */
            @"$(NXROOT)/var/containers",        /* needs access to application bundles */
            @"$(NXROOT)/var/mobile/Containers", /* needs access to application data containers */
            @"$(NXROOT)/var/mobile/tmp",        /* needs access to tmp of root home */
        ],
    };
    
    kPEEntitlementsNXT2PresetsDaemonCompiler = (__bridge_retained CFDictionaryRef)@{
        /* platformization */
        (__bridge NSString*)kNXT2EntitlementPlatform: @(YES),
        (__bridge NSString*)kNXT2EntitlementPlatformRoot: @(YES),
        
        /* debugging */
        (__bridge NSString*)kNXT2EntitlementGetTaskAllow: @(NO),
        
        /* launch services */
        (__bridge NSString*)kNXT2EntitlementLaunchServicesSetEndpoint: @(YES),  /* needed so it can set the unique service */
        
        /* sandbox */
        (__bridge NSString*)kNXT2EntitlementSandboxHost: @(YES),                /* allows file access to all of Nyxian, EXTREMELY POWERFUL */
    };
}
