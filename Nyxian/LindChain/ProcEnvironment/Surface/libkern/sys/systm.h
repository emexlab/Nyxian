/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab
 Copyright (C) 2026 semvis123

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

#ifndef SYS_PAYLOAD_H
#define SYS_PAYLOAD_H

#include <mach/mach.h>
#include <stdlib.h>
#include <stdbool.h>

typedef void* userspace_pointer_t;
typedef void* kernelspace_pointer_t;

kern_return_t syscall_payload_create(void *ptr, size_t size, mach_vm_address_t *mach_vm_address);

bool syscall_copy_in(task_t task, size_t size, kernelspace_pointer_t kptr, userspace_pointer_t src);
kernelspace_pointer_t syscall_alloc_in(task_t task, size_t size, userspace_pointer_t src);
bool syscall_copy_out(task_t task, size_t size, kernelspace_pointer_t kptr, userspace_pointer_t dst);
char *syscall_copy_str_in(task_t task, userspace_pointer_t src, size_t len);

#endif /* SYS_PAYLOAD_H */
