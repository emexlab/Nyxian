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

#ifndef KSURFACE_ABI_H
#define KSURFACE_ABI_H

/* ----------------------------------------------------------------------
 *  Apple API Headers
 * -------------------------------------------------------------------- */
#include <CoreFoundation/CoreFoundation.h>
#include <sys/syscall.h>

/* ----------------------------------------------------------------------
 *  Macros
 * -------------------------------------------------------------------- */

/* additional nyxian syscalls for now */
#define SYS_proctb          750     /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_getent          751     /* MARK: deprecated, use SYS_pectl instead */
#define SYS_gethostname     752     /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_sethostname     753     /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_task_for_pid    754     /* gets task port */
#define SYS_procpath        755     /* MARK: deprecated, use SYS_proc_info instead */
#define SYS_procbsd         756     /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_handoffep       757     /* handoff exception port to kvirt */
#define SYS_setent          758     /* MARK: deprecated, use SYS_pectl instead */
#define SYS_waittask        759     /* waits till task port of a task is available */
#define SYS_pectl           760     /* utility for many proc environment operations */
#define SYS_sign            761     /* this is to be able to sign the binary */
#define SYS_openpty         762     /* opens new pseudo terminal */
#define SYS_loginctl        763     /* process login-name control */
#define SYS_groupctl        764     /* supplementary group control */
#define SYS_vroot           765     /* gives the virtual root path of the environment */
#define SYS_spawn           766     /* posix_spawn without NSXPC, see ksurface_spawn_request_t */
#define SYS_spawn_bootstrap 767     /* claim this child's pending bootstrap override before guest initializers */

#define KSURFACE_SPAWN_REQUEST_VERSION  1
#define KSURFACE_SPAWN_REQUEST_MAX      (1024 * 1024)

typedef struct {
    uint32_t version;
    uint32_t argc;
    uint32_t envc;
    uint32_t fd_count;
    int32_t  flags;
    int32_t  pgroup;
} ksurface_spawn_request_t;

#define KSURFACE_SPAWN_REQUEST_VERSION_2    2
#define KSURFACE_SPAWN_BOOTSTRAP            (1u << 0)
#define KSURFACE_SPAWN_BOOTSTRAP_NULL       (1u << 1)
#define KSURFACE_SPAWN_PERSONA_UID          (1u << 2)
#define KSURFACE_SPAWN_PERSONA_GID          (1u << 3)
#define KSURFACE_BOOTSTRAP_SET 1
#define KSURFACE_BOOTSTRAP_CLEAR 2

typedef struct {
    ksurface_spawn_request_t base;
    uint32_t attributes;
    uint32_t persona_uid;
    uint32_t persona_gid;
    uint32_t reserved;
} ksurface_spawn_request_v2_t;

/* procursus jailed syscall */
#define SYS_sign2           1000

typedef CF_ENUM(UInt16, PELoginCTLAction) {
    kPELoginCTLGetLength = 0,
    kPELoginCTLGetWord = 1,
    kPELoginCTLSetWord = 2,
    kPELoginCTLCommit = 3,
    kPELoginCTLClear = 4,
};

typedef CF_ENUM(UInt16, PEGroupCTLAction) {
    kPEGroupCTLGetCount = 0,
    kPEGroupCTLGetAt = 1,
    kPEGroupCTLSetAt = 2,
    kPEGroupCTLCommit = 3,
    kPEGroupCTLClear = 4,
};

/* proc environment control mappings */
/* categories */
typedef CF_ENUM(UInt16, PECTLCategory) {
    kPECTLCategoryLaunchService = 0,
    kPECTLCategoryCodeSigning = 1,
    kPECTLCategoryUserInterface = 2,
    kPECTLCategoryUserspace = 3,
    kPECTLCategoryMisceleanous = 4,
};

/* sub categories */
typedef CF_ENUM(UInt16, PECTLLaunchService) {
    kPECTLLaunchServiceGetEndpoint = 0,
    kPECTLLaunchServiceSetEndpoint = 1,
    kPECTLLaunchServiceLoad = 2,
    kPECTLLaunchServiceUnload = 3,
    kPECTLLaunchServiceRegisterEndpoint = 4,
};

/* flags for kPECTLLaunchServiceLoad / kPECTLLaunchServiceUnload (args[2]) */
typedef CF_OPTIONS(UInt64, PECTLLaunchServiceFlags) {
    kPECTLLaunchServiceFlagNone = 0,
    kPECTLLaunchServiceFlagEnable = 1 << 0,
    kPECTLLaunchServiceFlagForce = 1 << 1,
};

typedef CF_ENUM(UInt16, PECTLCodeSigning) {
    kPECTLCodeSigningGetPublicKey = 0,
    kPECTLCodeSigningGetPrivateKey = 1,
    
    kPECTLCodeSigningSignPath = 2,
    kPECTLCodeSigningGetCDHash = 3,
    
    kPECTLCodeSigningAllEntitlements = 4,
    kPECTLCodeSigningGetEntitlements = 5,
    kPECTLCodeSigningSetEntitlements = 6,
    kPECTLCodeSigningDropAllEntitlements = 7,
    
    /* heavily guarded kernel development utilities */
    kPECTLCodeSigningLoadKernelExtension = 8,
    kPECTLCodeSigningUnloadKernelExtension = 9,
};

typedef CF_ENUM(UInt16, PECTLUserInterface) {
    kPECTLUserInterfaceInit = 0,
    kPECTLUserInterfaceOpenBundleIdentifier = 1,
    kPECTLUserInterfaceRespring = 2,
    kPECTLUserInterfaceOpenURL = 3,
    kPECTLUserInterfaceTakeOpenURL = 4,
    kPECTLUserInterfaceOpenURLInApplication = 5,
    kPECTLUserInterfaceSetStatusBarStyle = 6,
};

typedef CF_ENUM(UInt16, PECTLUserspace) {
    kPECTLUserspaceReboot = 0,
    kPECTLUserspaceGetMode = 1,
};

typedef CF_ENUM(UInt16, PECTLMisceleanous) {
    kPECTLMisceleanousGetBuildType = 0,
    
    kPECTLMisceleanousReboot = 2,
    kPECTLMisceleanousROMOTAPathSet = 3,
    kPECTLMisceleanousManageBootstrap = 4,
};

typedef CF_ENUM(UInt16, PEBuildType) {
    kPEBuildTypeRelease = 0,
    kPEBuildTypeDebug = 1,
};

#endif /* KSURFACE_ABI_H */
