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

#ifndef SURFACE_SYS_SYSCALL_H
#define SURFACE_SYS_SYSCALL_H

/* system headers */
#include <sys/syscall.h>

/* headers to all syscall handlers */
#include <LindChain/ProcEnvironment/Surface/sys/host/ioctl.h>
#include <LindChain/ProcEnvironment/Surface/sys/host/sysctl.h>
#include <LindChain/ProcEnvironment/Surface/sys/host/openpty.h>
#include <LindChain/ProcEnvironment/Surface/sys/compat/task_for_pid.h>
#include <LindChain/ProcEnvironment/Surface/sys/compat/handoffep.h>
#include <LindChain/ProcEnvironment/Surface/sys/compat/waittask.h>
#include <LindChain/ProcEnvironment/Surface/sys/compat/pectl.h>
#include <LindChain/ProcEnvironment/Surface/sys/compat/sign.h>
#include <LindChain/ProcEnvironment/Surface/sys/compat/vroot.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/setuid.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/setgid.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/getppid.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/getuid.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/getgid.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/loginctl.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/groupctl.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/getsid.h>
#include <LindChain/ProcEnvironment/Surface/sys/cred/setsid.h>
#include <LindChain/ProcEnvironment/Surface/sys/proc/kill.h>
#include <LindChain/ProcEnvironment/Surface/sys/proc/wait4.h>
#include <LindChain/ProcEnvironment/Surface/sys/proc/proc_info.h>

typedef struct {
    const char *name;
    uint32_t sysnum;
    syscall_handler_t hndl;
} syscall_list_item_t;

#endif /* SURFACE_SYS_SYSCALL_H */
