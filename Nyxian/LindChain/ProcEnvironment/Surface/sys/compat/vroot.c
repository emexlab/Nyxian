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

#include <LindChain/ProcEnvironment/Surface/sys/compat/vroot.h>
#include <CoreFoundation/CoreFoundation.h>

DEFINE_SYSCALL_HANDLER(vroot)
{
    /* parsing arguments */
    userspace_pointer_t u_path_buf = (userspace_pointer_t)args[0];
    if(u_path_buf == NULL)
    {
        /* size query */
        return (int64_t)(size_t)PATH_MAX;
    }
    
    /* create vroot path */
    static char path[PATH_MAX];
    static size_t size = 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        /* we gotta get the home path */
        const char *home = getenv("HOME");
        if(home == NULL)
        {
            return;
        }
        
        /* and construct the vroot path */
        size = snprintf(path, PATH_MAX, "%s/Documents/rootfs", home) + 1;
    });
    
    /* copy the string out */
    if(size == 0 || !syscall_copy_out(sys_task_, size, path, u_path_buf))
    {
        sys_return_failure_with_errno(EFAULT);
    }
    
    sys_return;
}
