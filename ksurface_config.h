/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
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
