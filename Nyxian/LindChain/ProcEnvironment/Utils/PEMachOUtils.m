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

#import <LindChain/ProcEnvironment/Utils/PEMachOUtils.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <mach-o/loader.h>
#import <mach-o/ldsyms.h>
#import <assert.h>

extern const struct mach_header *_dyld_get_dlopen_image_header(void *handle);

void *PEGetMachOEntryPointOfHeader(void *handle)
{
    const struct mach_header_64 *header = (struct mach_header_64 *)_dyld_get_dlopen_image_header(handle);
    const struct load_command *cmd = (const struct load_command *) ((uintptr_t)header + sizeof(struct mach_header_64));

    for(uint32_t i = 0; i < header->ncmds; i++)
    {
        if(__builtin_expect(cmd->cmd == LC_MAIN, 0))
        {
            const struct entry_point_command *ec = (const struct entry_point_command *)cmd;
            assert(ec->entryoff > 0);
            return (void *)((uintptr_t)header + ec->entryoff);
        }
        cmd = (const struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
    }

    return NULL;
}
