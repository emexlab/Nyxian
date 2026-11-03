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

#ifndef PE_SPAWN_BOOTSTRAP_H
#define PE_SPAWN_BOOTSTRAP_H

#include <mach/mach.h>
#include <spawn.h>
#include <stdbool.h>

int pe_spawn_bootstrap_copy(const posix_spawnattr_t *attributes, bool *present, mach_port_t *port);
int pe_spawn_bootstrap_initialize(void);

#endif /* PE_SPAWN_BOOTSTRAP_H */
