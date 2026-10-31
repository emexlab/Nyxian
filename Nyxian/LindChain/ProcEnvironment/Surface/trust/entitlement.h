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

#ifndef TRUST_ENTITLEMENT_H
#define TRUST_ENTITLEMENT_H

/* ----------------------------------------------------------------------
 *  System Headers
 * -------------------------------------------------------------------- */
#include <CoreFoundation/CoreFoundation.h>
#include <mach/kern_return.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>

/* ----------------------------------------------------------------------
 *  Constants
 * -------------------------------------------------------------------- */
/*!
 @enum PEEntitlement
 @abstract Entitlements which are responsible for the primitives of the environment
 */
typedef CF_OPTIONS(uint64_t, PEEntitlementFlags) {
    /*! No entitlements at all */
    kPEEntitlementFlagNone                          = 0,
    
    /*! Grants other processes with appropriate permitives to get task port of process .*/
    kPEEntitlementFlagGetTaskAllowed                = 1ull << 0,
    
    /*! Grants process to get task port of processes. */
    kPEEntitlementFlagTaskForPid                    = 1ull << 1,
    
    /*! Grants process to enumerate processes. */
    kPEEntitlementFlagProcessEnumeration            = 1ull << 3,
    
    /*! Grants process to kill other processes. */
    kPEEntitlementFlagProcessKill                   = 1ull << 5,
    
    /*! Grants process to spawn other processes. */
    kPEEntitlementFlagProcessSpawn                  = 1ull << 6,
    
    /*! Grants process to spawn other processes, under the condition that the binary must be signed. */
    kPEEntitlementFlagProcessSpawnSignedOnly        = 1ull << 7,
    
    /*! Grants process to elevate permitive. */
    kPEEntitlementFlagProcessElevate                = 1ull << 8,
    
    /*! Grants process to manage host. */
    kPEEntitlementFlagHostManager                   = 1ull << 9,
    
    /*! Grants process to manage credentials. */
    kPEEntitlementFlagCredentialsManager            = 1ull << 10,
    
    /*! Grants process to start launch services. */
    kPEEntitlementFlagLaunchServicesStart           = 1ull << 11,
    
    /*! Grants process to stop launch services. */
    kPEEntitlementFlagLaunchServicesStop            = 1ull << 12,
    
    /*! Grants process to manage launch services. */
    kPEEntitlementFlagLaunchServicesToggle          = 1ull << 13,
    
    /*! Grants process to get endpoint of launch services. */
    kPEEntitlementFlagLaunchServicesGetEndpoint     = 1ull << 14,
    
    /*! Grants process to set endpoint of launch services. */
    kPEEntitlementFlagLaunchServicesSetEndpoint     = 1ull << 15,
    
    /*! Makes a process retain entitlements across processes, made for sandboxed applications and such. Its a security feature. */
    kPEEntitlementFlagProcessSpawnInheriteEntitlements  = 1ull << 19,
    
    /*! Security feature for daemons and such */
    kPEEntitlementFlagPlatform                      = 1ull << 20,
    
    /*! Security feature for daemons to start as root process, requires `PEEntitlementPlatform` to be present */
    kPEEntitlementFlagPlatformRoot                  = 1ull << 21,
    
    /*! Grants process to get task port of any process. */
    kPEEntitlementFlagSystemTaskPorts               = 1ull << 22,
    
    /*! Grants a process to load a kernel extension */
    kPEEntitlementFlagLoadKEXT                      = 1ull << 23,
    
    kPEEntitlementFlagAll                           = kPEEntitlementFlagGetTaskAllowed | kPEEntitlementFlagTaskForPid | kPEEntitlementFlagProcessEnumeration | kPEEntitlementFlagProcessKill | kPEEntitlementFlagProcessSpawn | kPEEntitlementFlagProcessSpawnSignedOnly | kPEEntitlementFlagProcessElevate | kPEEntitlementFlagHostManager | kPEEntitlementFlagCredentialsManager | kPEEntitlementFlagLaunchServicesStart | kPEEntitlementFlagLaunchServicesStop | kPEEntitlementFlagLaunchServicesToggle | kPEEntitlementFlagLaunchServicesGetEndpoint | kPEEntitlementFlagLaunchServicesSetEndpoint | kPEEntitlementFlagProcessSpawnInheriteEntitlements | kPEEntitlementFlagPlatform | kPEEntitlementFlagPlatformRoot | kPEEntitlementFlagSystemTaskPorts,
};

/* new NXT2 entitlements */
typedef CFStringRef NXT2Entitlement CF_TYPED_ENUM;

/* foundational */
extern NXT2Entitlement const kNXT2EntitlementPlatform;
extern NXT2Entitlement const kNXT2EntitlementPlatformRoot;
extern NXT2Entitlement const kNXT2EntitlementPlatformUser;
extern NXT2Entitlement const kNXT2EntitlementPlatformGroup;
extern NXT2Entitlement const kNXT2EntitlementGetTaskAllow;
extern NXT2Entitlement const kNXT2EntitlementTaskForPid;
extern NXT2Entitlement const kNXT2EntitlementSUGID;
extern NXT2Entitlement const kNXT2EntitlementSystemTaskPorts;

/* process */
extern NXT2Entitlement const kNXT2EntitlementProcessEnumeration;
extern NXT2Entitlement const kNXT2EntitlementProcessKill;
extern NXT2Entitlement const kNXT2EntitlementProcessSpawn;
extern NXT2Entitlement const kNXT2EntitlementProcessSpawnSignedOnly;
extern NXT2Entitlement const kNXT2EntitlementProcessSpawnInheriteEntitlements;

/* management */
extern NXT2Entitlement const kNXT2EntitlementManagementHost;
extern NXT2Entitlement const kNXT2EntitlementManagementProcEnvironment;

/* launch services */
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesStart;                   /* unimplemented */
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesStop;                    /* unimplemented */
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesToggle;                  /* unimplemented */
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesGetEndpoint;
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesSetEndpoint;
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesGetEndpointAllowList;    /* has to be CFArray filled with CFString */
extern NXT2Entitlement const kNXT2EntitlementLaunchServicesSetEndpointAllowList;    /* has to be CFArray filled with CFString */

/* sandbox */
extern NXT2Entitlement const kNXT2EntitlementSandboxFileRead;                       /* has to be CFArray filled with CFString */
extern NXT2Entitlement const kNXT2EntitlementSandboxFileReadWrite;                  /* has to be CFArray filled with CFString */
extern NXT2Entitlement const kNXT2EntitlementSandboxNoContainer;                    /* unfinished, container path here needs to default to $(ROOTFS)/var/mobile */
extern NXT2Entitlement const kNXT2EntitlementSandboxHost;                           /* EXTREMELY POWERFUL ENTITLEMENT, GIVES CHILD AS MUCH FILE ACCESS AS HOST */

/* ksurface */
extern NXT2Entitlement const kNXT2EntitlementKsurfaceKEXTLoading;

/* ----------------------------------------------------------------------
 *  Types
 * -------------------------------------------------------------------- */
typedef struct ksurface_proc ksurface_proc_t;
typedef struct ksurface_nxt2_blob_header ksurface_nxt2_blob_header_t;
typedef struct ksurface_nxt2_blob_footer ksurface_nxt2_blob_footer_t;
typedef struct ksurface_nxt2 ksurface_nxt2_t;

/* header contains everything signed  */
struct __attribute__((packed)) ksurface_nxt2_blob_header {
    char cdhash[USER_FSIGNATURES_CDHASH_LEN];
    uint64_t nonce;
    size_t plist_len;
    const char plist_data[];
};

/* footer remains unsigned, it contains the signing identity */
struct __attribute__((packed))ksurface_nxt2_blob_footer {
    size_t mac_len;
    uint8_t mac[72];
};

struct ksurface_nxt2 {
    bool isValid;       /* unlike in nxtr a valid blob in nxt2 means it passes sanity checks! */
    bool isSigned;      /* means the blob is signed */
    bool isCdHashValid;
    bool needsResign;   /* trust will resign the executable entirely when set */
    char cdhash[USER_FSIGNATURES_CDHASH_LEN];
    CFDictionaryRef entitlements;
};

/* ----------------------------------------------------------------------
 *  Macros
 * -------------------------------------------------------------------- */
#define entitlement_got_entitlement(present,needed) (((present) & (needed)) == (needed))
#define entitlement_strip(present,strip) (present) &= ~(strip)

/* ----------------------------------------------------------------------
 *  Function Prototypes
 * -------------------------------------------------------------------- */

PEEntitlementFlags entitlement_sanitize(PEEntitlementFlags base);

#endif /* TRUST_ENTITLEMENT_H */
