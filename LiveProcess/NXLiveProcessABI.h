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

#ifndef NXLIVEPROCESSABI_H
#define NXLIVEPROCESSABI_H

#include <stddef.h>
#include <stdint.h>

#define NX_LIVEPROCESS_ABI_VERSION 1u
#define NX_LIVEPROCESS_LIBSYSTEM_MODE "libsystem-v1"
#define NX_LIVEPROCESS_MODE_ENV "NYXIAN_LIVEPROCESS_MODE"
#define NX_LIVEPROCESS_ABI_ENV "NYXIAN_LIVEPROCESS_ABI"
#define NX_LIVEPROCESS_MODULE_ENV "NYXIAN_SIMULATOR_MODULE"
#define NX_LIVEPROCESS_HASH_ENV "NYXIAN_SIMULATOR_MODULE_SHA256"
#define NX_LIVEPROCESS_TOKEN_ENV "NYXIAN_SIMULATOR_MODULE_TOKEN"
#define NX_LIVEPROCESS_MODULE_SYMBOL "NXLiveProcessSimulatorModuleV1"
#define NX_LIVEPROCESS_MODULE_OWNS_RUNTIME (1u << 0)

#ifdef __cplusplus
extern "C" {
#endif

/* All pointers are process-local native pointers, not an IPC wire representation. No ObjC objects cross this ABI. */
typedef struct NXLiveProcessStartV1 {
    uint32_t version, size;
    int32_t argc;
    uint32_t flags; /* Must be zero in v1. */
    const char *const *argv;
    const char *const *envp;
    const char *const *apple;
    const char *modulePath; /* Canonical physical path; valid until module main returns. */
} NXLiveProcessStartV1;

typedef struct NXLiveProcessSimulatorModuleDescriptorV1 {
    uint32_t version, size;
    uint64_t flags; /* v1 requires exactly NX_LIVEPROCESS_MODULE_OWNS_RUNTIME. */
    int (*main)(const NXLiveProcessStartV1 *start);
} NXLiveProcessSimulatorModuleDescriptorV1;

/* The query and main must both be defined by the supplied module itself. They must not initialize UIKit/ObjC before handoff. */
typedef const NXLiveProcessSimulatorModuleDescriptorV1 *(*NXLiveProcessSimulatorModuleQueryV1)(uint32_t version, uint32_t startSize);

typedef struct NXLiveProcessLaunchV1 {
    uint32_t version, size;
    char modulePath[1024];
    char moduleSHA256[65];
    char readOnlySandboxToken[4096]; /* Capability: do not log or persist. */
    char extensionIdentifier[256];
    uint8_t reserved[7];
} NXLiveProcessLaunchV1;

/* Host exports. ROMs resolve these symbols from Nyxian using dlsym(RTLD_DEFAULT, ...). */
uint32_t NXLiveProcessGetHostABIVersion(void);
uint32_t NXLiveProcessGetBootstrapVersion(void);
int NXLiveProcessPrepareSimulatorLaunchV1(const char *sealedSlot, const char *moduleRelativePath,
                                        NXLiveProcessLaunchV1 *output, uint32_t outputSize);

/* Pure-C protocol validation, shared with tests. Returns 0 for legacy, 1 for Simulator, or negative errno. */
int NXLiveProcessSelectPathV1(const char *mode, const char *version);
int NXLiveProcessValidateModuleV1(const NXLiveProcessSimulatorModuleDescriptorV1 *module);
int NXLiveProcessRunLibSystemV1(const char *path, const char *sha256, const NXLiveProcessStartV1 *start, int *moduleStatus);

#ifdef __cplusplus
}
#endif
#if defined(__LP64__)
#if defined(__cplusplus)
static_assert(sizeof(NXLiveProcessStartV1) == 48 && sizeof(NXLiveProcessSimulatorModuleDescriptorV1) == 24 && sizeof(NXLiveProcessLaunchV1) == 5456, "LiveProcess ABI v1 layout changed");
#else
_Static_assert(sizeof(NXLiveProcessStartV1) == 48 && sizeof(NXLiveProcessSimulatorModuleDescriptorV1) == 24 && sizeof(NXLiveProcessLaunchV1) == 5456, "LiveProcess ABI v1 layout changed");
#endif
#endif /* defined(__LP64__) */

#endif /* NXLIVEPROCESSABI_H */
