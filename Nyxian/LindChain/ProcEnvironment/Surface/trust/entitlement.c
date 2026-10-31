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

/* ----------------------------------------------------------------------
 *  System Headers
 * -------------------------------------------------------------------- */
#include <assert.h>

/* ----------------------------------------------------------------------
 *  Project Headers
 * -------------------------------------------------------------------- */
#include <LindChain/ProcEnvironment/Surface/trust/entitlement.h>
#include <LindChain/ProcEnvironment/Surface/proc/proc.h>
#include <LindChain/ProcEnvironment/Surface/key.h>
#include <LindChain/ProcEnvironment/Surface/trust/trust.h>
#include <OpenSSL/evp.h>
#include <OpenSSL/err.h>
#include <OpenSSL/ec.h>
#include <OpenSSL/pem.h>
#include <ksurface_config.h>

/* ----------------------------------------------------------------------
 *  Constants
 * -------------------------------------------------------------------- */

/* foundational */
NXT2Entitlement const kNXT2EntitlementPlatform = CFSTR("org.emexlabs.nyxian.platform");
NXT2Entitlement const kNXT2EntitlementPlatformRoot = CFSTR("org.emexlabs.nyxian.platform-root");
NXT2Entitlement const kNXT2EntitlementPlatformUser = CFSTR("org.emexlabs.nyxian.platform.user");
NXT2Entitlement const kNXT2EntitlementPlatformGroup = CFSTR("org.emexlabs.nyxian.platform.group");
NXT2Entitlement const kNXT2EntitlementGetTaskAllow = CFSTR("org.emexlabs.nyxian.get-task-allow");
NXT2Entitlement const kNXT2EntitlementTaskForPid = CFSTR("org.emexlabs.nyxian.task-for-pid");
NXT2Entitlement const kNXT2EntitlementSUGID = CFSTR("org.emexlabs.nyxian.sugid");
NXT2Entitlement const kNXT2EntitlementSystemTaskPorts = CFSTR("org.emexlabs.nyxian.system-task-ports");

/* process */
NXT2Entitlement const kNXT2EntitlementProcessEnumeration = CFSTR("org.emexlabs.nyxian.process.enumeration");
NXT2Entitlement const kNXT2EntitlementProcessKill = CFSTR("org.emexlabs.nyxian.process.kill");
NXT2Entitlement const kNXT2EntitlementProcessSpawn = CFSTR("org.emexlabs.nyxian.process.spawn");
NXT2Entitlement const kNXT2EntitlementProcessSpawnSignedOnly = CFSTR("org.emexlabs.nyxian.process.spawn.signed-only");
NXT2Entitlement const kNXT2EntitlementProcessSpawnInheriteEntitlements = CFSTR("org.emexlabs.nyxian.process.spawn.inherite-entitlements");

/* management */
NXT2Entitlement const kNXT2EntitlementManagementHost = CFSTR("org.emexlabs.nyxian.management.host");
NXT2Entitlement const kNXT2EntitlementManagementProcEnvironment = CFSTR("org.emexlabs.nyxian.management.proc-environment");

/* launch services */
NXT2Entitlement const kNXT2EntitlementLaunchServicesStart = CFSTR("org.emexlabs.nyxian.launch-services.start");
NXT2Entitlement const kNXT2EntitlementLaunchServicesStop = CFSTR("org.emexlabs.nyxian.launch-services.stop");
NXT2Entitlement const kNXT2EntitlementLaunchServicesToggle = CFSTR("org.emexlabs.nyxian.launch-services.toggle");
NXT2Entitlement const kNXT2EntitlementLaunchServicesGetEndpoint = CFSTR("org.emexlabs.nyxian.launch-services.get-endpoint");
NXT2Entitlement const kNXT2EntitlementLaunchServicesSetEndpoint = CFSTR("org.emexlabs.nyxian.launch-services.set-endpoint");
NXT2Entitlement const kNXT2EntitlementLaunchServicesGetEndpointAllowList = CFSTR("org.emexlabs.nyxian.launch-services.get-endpoint.allow-list");
NXT2Entitlement const kNXT2EntitlementLaunchServicesSetEndpointAllowList = CFSTR("org.emexlabs.nyxian.launch-services.set-endpoint.allow-list");

/* sandbox */
NXT2Entitlement const kNXT2EntitlementSandboxFileRead = CFSTR("org.emexlabs.nyxian.sandbox.file.read");
NXT2Entitlement const kNXT2EntitlementSandboxFileReadWrite = CFSTR("org.emexlabs.nyxian.sandbox.file.read-write");
NXT2Entitlement const kNXT2EntitlementSandboxNoContainer = CFSTR("org.emexlabs.nyxian.sandbox.no-container");
NXT2Entitlement const kNXT2EntitlementSandboxHost = CFSTR("org.emexlabs.nyxian.sandbox.host");

/* ksurface */
NXT2Entitlement const kNXT2EntitlementKsurfaceKEXTLoading = CFSTR("org.emexlabs.nyxian.ksurface.kernelextension.loading");

/* ----------------------------------------------------------------------
 *  Functions
 * -------------------------------------------------------------------- */

PEEntitlementFlags entitlement_sanitize(PEEntitlementFlags base)
{
#if KSURFACE_CS_SANITIZE_ENTITLEMENTS
    base &= kPEEntitlementFlagAll;  /* making sure no unused bit fields are enabled */
    
    /* can it see a other process ever? */
    if(!entitlement_got_entitlement(base, kPEEntitlementFlagProcessSpawn) &&
       !entitlement_got_entitlement(base, kPEEntitlementFlagProcessSpawnSignedOnly) &&
       !entitlement_got_entitlement(base, kPEEntitlementFlagProcessEnumeration))
    {
        /* you cannot do much when you cannot see the target */
        entitlement_strip(base, kPEEntitlementFlagTaskForPid | kPEEntitlementFlagProcessKill);
    }
    
    /* can it spawn a other process ever? */
    if(!entitlement_got_entitlement(base, kPEEntitlementFlagProcessSpawn) &&
       !entitlement_got_entitlement(base, kPEEntitlementFlagProcessSpawnSignedOnly))
    {
        entitlement_strip(base, kPEEntitlementFlagProcessSpawnInheriteEntitlements);
    }
    
    /* can it be platform root? */
    if(entitlement_got_entitlement(base, kPEEntitlementFlagPlatformRoot) &&
       !entitlement_got_entitlement(base, kPEEntitlementFlagPlatform))
    {
        /* you cannot be platformized as root user if you're not platform */
        entitlement_strip(base, kPEEntitlementFlagPlatformRoot);
    }
#endif /* KSURFACE_CS_SANITIZE_ENTITLEMENTS */
    return base;
}
