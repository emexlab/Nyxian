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

#include <LiveProcessLegacy/LPLUtils.h>

/* https://github.com/opa334/opainject/blob/849bb296ea8bc0643a2966485ea3c3c96ebdcd5b/thread_utils.m#L14 */
struct arm64_thread_full_state* thread_save_state_arm64(thread_act_t thread)
{
    struct arm64_thread_full_state* s = malloc(sizeof(struct arm64_thread_full_state));
    mach_msg_type_number_t count;
    kern_return_t kr;
    
    count = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &s->thread, &count);
    s->thread_valid = (kr == KERN_SUCCESS);
    if(kr != KERN_SUCCESS)
    {
        free(s);
        return NULL;
    }
    
    count = ARM_EXCEPTION_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t) &s->exception, &count);
    s->exception_valid = (kr == KERN_SUCCESS);
    
    count = ARM_NEON_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t) &s->neon, &count);
    s->neon_valid = (kr == KERN_SUCCESS);
    
    count = ARM_DEBUG_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t) &s->debug, &count);
    s->debug_valid = (kr == KERN_SUCCESS);
    
    return s;
}

/* https://github.com/opa334/opainject/blob/849bb296ea8bc0643a2966485ea3c3c96ebdcd5b/thread_utils.m#L55 */
bool thread_restore_state_arm64(thread_act_t thread, struct arm64_thread_full_state* state)
{
    struct arm64_thread_full_state *s = (void *) state;
    kern_return_t kr;
    bool success = true;
    
    if(s->thread_valid)
    {
        kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t) &s->thread, ARM_THREAD_STATE64_COUNT);
    }
    
    if(s->exception_valid)
    {
        kr = thread_set_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t) &s->exception, ARM_EXCEPTION_STATE64_COUNT);
    }
    
    if(s->neon_valid)
    {
        kr = thread_set_state(thread, ARM_NEON_STATE64, (thread_state_t) &s->neon, ARM_NEON_STATE64_COUNT);
    }
    
    if(s->debug_valid)
    {
        kr = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t) &s->debug, ARM_DEBUG_STATE64_COUNT);
    }
    
    free(s);
    return success;
}
