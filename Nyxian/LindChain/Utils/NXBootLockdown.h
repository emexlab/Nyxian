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

#ifndef NXBOOTLOCKDOWN_H
#define NXBOOTLOCKDOWN_H

#if NX_ROM_BOOTLOADER
#if __has_attribute(nouwtable)
#define NX_BOOT_ONLY __attribute__((section("__BOOTONLY,__boot_text,regular,pure_instructions"), noinline, nothrow, nouwtable))
#else
#error "NX_BOOT_ONLY needs clang's nouwtable attribute (Xcode 15 or newer)"
#endif
#else
#define NX_BOOT_ONLY
#endif

#if NX_ROM_BOOTLOADER

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * meant to harden against kexploit's that grant a attacker
 * read,write or even calling primitives
 */
bool NXBootLockdown(void);
bool NXBootLockdownActive(void);

#ifdef __cplusplus
}
#endif

#endif /* NX_ROM_BOOTLOADER */

#endif /* NXBOOTLOCKDOWN_H */
