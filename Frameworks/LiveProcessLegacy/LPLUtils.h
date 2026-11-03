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

/* TODO: this needs a better place */

#ifndef LPLUTILS_H
#define LPLUTILS_H

#include <stdlib.h>
#include <mach/mach.h>

/* https://github.com/opa334/opainject/blob/849bb296ea8bc0643a2966485ea3c3c96ebdcd5b/thread_utils.h#L27 */
struct arm64_thread_full_state {
    arm_thread_state64_t    thread;
    arm_exception_state64_t exception;
    arm_neon_state64_t      neon;
    arm_debug_state64_t     debug;
    uint32_t                thread_valid:1,
                            exception_valid:1,
                            neon_valid:1,
                            debug_valid:1,
                            cpmu_valid:1;
};

/* https://github.com/opa334/opainject/blob/849bb296ea8bc0643a2966485ea3c3c96ebdcd5b/thread_utils.h#L39 */
struct arm64_thread_full_state* thread_save_state_arm64(thread_act_t thread);
bool thread_restore_state_arm64(thread_act_t thread, struct arm64_thread_full_state* state);

#endif /* LPLUTILS_H */
