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

#import "NXBootPolicy.h"
#import "NXBootLockdown.h"
#include <mach/mach.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    uint32_t magic;
    uint8_t trustStoreValidation;
    uint8_t tssValidation;
} NXBootPolicyValues;

#define NXBOOTPOLICY_MAGIC 0x4e584250u

static const NXBootPolicyValues *NXBootPolicyCurrent = NULL;

#if NX_ROM_BOOTLOADER

static BOOL NXBootPolicyIsFalse(id value)
{
    return value != nil && CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() && ![value boolValue];
}

NX_BOOT_ONLY __attribute__((constructor)) static void NXBootPolicyLoad(void)
{
    @autoreleasepool
    {
        NXBootPolicyValues values = { NXBOOTPOLICY_MAGIC, 1, 1 };
        NSString *path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"NXBootPolicy.plist"];
        int fd = path ? open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
        if(fd >= 0)
        {
            struct stat st;
            if(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= 4096)
            {
                NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
                if(pread(fd, data.mutableBytes, (size_t)st.st_size, 0) == st.st_size)
                {
                    id policy = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
                    if([policy isKindOfClass:NSDictionary.class])
                    {
                        values.trustStoreValidation = NXBootPolicyIsFalse(policy[@"NXTrustStoreValidation"]) ? 0 : 1;
                        values.tssValidation = NXBootPolicyIsFalse(policy[@"NXTSSValidation"]) ? 0 : 1;
                    }
                }
            }
            close(fd);
        }
        
        vm_address_t page = 0;
        if(vm_allocate(mach_task_self(), &page, vm_page_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        {
            return;
        }
        memcpy((void *)page, &values, sizeof(values));
        if(vm_protect(mach_task_self(), page, vm_page_size, FALSE, VM_PROT_READ) != KERN_SUCCESS
           || vm_protect(mach_task_self(), page, vm_page_size, TRUE, VM_PROT_READ) != KERN_SUCCESS)
        {
            vm_deallocate(mach_task_self(), page, vm_page_size);
            return;
        }
        NXBootPolicyCurrent = (const NXBootPolicyValues *)page;
    }
}

#endif /* NX_ROM_BOOTLOADER */

BOOL NXBootPolicyTrustStoreValidation(void)
{
    const NXBootPolicyValues *values = NXBootPolicyCurrent;
    return values == NULL || values->magic != NXBOOTPOLICY_MAGIC || values->trustStoreValidation != 0;
}

BOOL NXBootPolicyTSSValidation(void)
{
    const NXBootPolicyValues *values = NXBootPolicyCurrent;
    return values == NULL || values->magic != NXBOOTPOLICY_MAGIC || values->tssValidation != 0;
}
