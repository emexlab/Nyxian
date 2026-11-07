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

#ifndef LIBKERN_VERSION_H
#define LIBKERN_VERSION_H

#include <stddef.h>
#include <stdint.h>
#include <mach/kern_return.h>

int ksurface_version_get_length(void);
const char *ksurface_version_get_string(void);
kern_return_t ksurface_version_get_buffer(int *buffer, size_t *size);

#endif /* LIBKERN_VERSION_H */
