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

#ifndef KSURFACE_CONFIG_H
#define KSURFACE_CONFIG_H

/* ----------------------------------------------------------------------
 *  Macros
 * -------------------------------------------------------------------- */

/* kernel process configuration */
#define KSURFACE_EMIT_KERNEL_TASK               0   /* adds kernel task entry, instead of Nyxian entry MARK: unsupported currently */

/* syscalling coverage configuration */
#define KSURFACE_SYS_IOCTL_ENABLED              1
#define KSURFACE_SYS_SYSCTL_ENABLED             1
#define KSURFACE_SYS_TASK_ENABLED               1
#define KSURFACE_SYS_UCRED_ENABLED              1
#define KSURFACE_SYS_PROC_ENABLED               1

/* codesigning feature configuration */
#define KSURFACE_CS_SANITIZE_ENTITLEMENTS       1   /* strips unecessary entitlements at launch time */
#define KSURFACE_CS_ALLOW_NXT2                  1   /* enables compatibility with the new code signature format NXT2 (in case we have to disable this some day) */

/* dyld feature configuration */
#define KSURFACE_DYLD_HOOK_LOGGING_ENABLED      0   /* enables logging from the hooks */
#define KSURFACE_DYLD_HARDENED_CDHASH_VERIFIER  1   /* hardlocks open on failed cdhash verification (recommended to be enabled as it closes a huge security risk otherwise) */

/* logging features */
#define KSURFACE_KLOG_ENABLE_DAEMONS            0
#define KSURFACE_KLOG_ENABLE_PROCESSES          0

/* kernel extension features */
#define KSURFACE_KEXT_HARDENED_LOADING          0   /* crash on failed loads */
#define KSURFACE_KEXT_ALLOW_CONSTRUCTORS        0   /* allows that kext link editor runs __attribute__((constructor)) in kexts */

/* in releases these features shall be disabled */
#if !DEBUG
#undef KSURFACE_DYLD_HOOK_LOGGING_ENABLED
#undef KSURFACE_KLOG_ENABLE_DAEMONS
#undef KSURFACE_KLOG_ENABLE_PROCESSES
#define KSURFACE_DYLD_HOOK_LOGGING_ENABLED      0
#define KSURFACE_KLOG_ENABLE_DAEMONS            0
#define KSURFACE_KLOG_ENABLE_PROCESSES          0
#endif /* !DEBUG */

#endif /* KSURFACE_CONFIG_H */
