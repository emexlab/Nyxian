/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab
 Copyright (C) 2026 semvis123

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

#ifndef TRUST_TRUST_H
#define TRUST_TRUST_H

/* ----------------------------------------------------------------------
 *  System Headers
 * -------------------------------------------------------------------- */
#include <CoreFoundation/CoreFoundation.h>
#include <sys/param.h>

/* ----------------------------------------------------------------------
 *  Project Headers
 * -------------------------------------------------------------------- */
#include <LindChain/ProcEnvironment/Surface/trust/apple.h>
#include <LindChain/ProcEnvironment/Surface/trust/cdhash.h>
#include <LindChain/ProcEnvironment/Surface/trust/entitlement.h>
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>
#include <LindChain/ProcEnvironment/Surface/trust/presets.h>
#include <LindChain/ProcEnvironment/Surface/trust/keychain.h>
#if __OBJC__
#import <LindChain/ProcEnvironment/Surface/trust/summary.h>
#endif /* __OBJC__ */

/* ----------------------------------------------------------------------
 *  Types
 * -------------------------------------------------------------------- */
typedef enum: UInt8 {
    kPETrustLevelFallback = 0,  /* no trust */
    kPETrustLevelSignature = 1, /* signature trust */
    kPETrustLevelTrusted = 2,   /* system trust */
} PETrustLevel;

typedef CF_ENUM(UInt32, PEEnforcementMode) {
    kPEEnforcementModeEnforcing = 0,
    kPEEnforcementModePermissive = 1,
    kPEEnforcementModeDisabled = 2,
};

typedef struct {
    char path[MAXPATHLEN];
    char cdhash[USER_FSIGNATURES_CDHASH_LEN];
    CFDictionaryRef entitlements;
    CFArrayRef filePermissions;
    PETrustLevel trustLevel;
} ksurface_trust_identity_t;

/* ----------------------------------------------------------------------
 *  Function Prototype
 * -------------------------------------------------------------------- */
bool trust_enforcement_set_mode(PEEnforcementMode mode);
PEEnforcementMode trust_enforcement_mode(void);
bool trust_enforcement_should_deny(pid_t pid, PEEntitlementFlags missing, const char *operation);
bool trust_enforcement_overrides(pid_t pid, PEEntitlementFlags missing, const char *operation);

ksurface_trust_identity_t *trust_identity_get_kernel(void);

/* they are immutable, except for maxLegacyEntitlements! */
ksurface_trust_identity_t *trust_identity_create_from_path(const char *path);
ksurface_trust_identity_t *trust_identity_create_from_path_with_parent_identity(const char *path, ksurface_trust_identity_t *parentIdentity);

void trust_identity_destroy(ksurface_trust_identity_t *identity);

PEEntitlementFlags trust_identity_entitlement_flags_from_entitlements(CFDictionaryRef entitlements);

#endif /* TRUST_TRUST_H */
