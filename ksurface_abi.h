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

/*
 * all of this is contract information, never reorder one of
 * those, if you change them you will break it, those definitions
 * are strictly append-only. Syscalls which are deprecated keep
 * their number, never reuse them.
 */

/* additional nyxian syscalls for now */
#define SYS_proctb          750 /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_getent          751 /* MARK: deprecated, use SYS_pectl instead */
#define SYS_gethostname     752 /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_sethostname     753 /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_task_for_pid    754 /* gets task port */
#define SYS_procpath        755 /* MARK: deprecated, use SYS_proc_info instead */
#define SYS_procbsd         756 /* MARK: deprecated, use SYS_sysctl instead */
#define SYS_handoffep       757 /* handoff exception port to kvirt */
#define SYS_setent          758 /* MARK: deprecated, use SYS_pectl instead */
#define SYS_waittask        759 /* waits till task port of a task is available */
#define SYS_pectl           760 /* utility for many proc environment operations */
#define SYS_sign            761 /* this is to be able to sign the binary */
#define SYS_openpty         762 /* opens new pseudo terminal */
#define SYS_loginctl        763 /* process login-name control */
#define SYS_groupctl        764 /* supplementary group control */
#define SYS_vroot           765 /* tells guests where Nyxian's root lives at */

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
};

typedef CF_ENUM(UInt16, PECTLUserspace) {
    kPECTLUserspaceReboot = 0,
    kPECTLUserspaceGetMode = 1,
};

typedef CF_ENUM(UInt16, PECTLMisceleanous) {
    kPECTLMisceleanousGetBuildType = 0,
};

typedef CF_ENUM(UInt16, PEBuildType) {
    kPEBuildTypeRelease = 0,
    kPEBuildTypeDebug = 1,
};

#endif /* KSURFACE_ABI_H */
