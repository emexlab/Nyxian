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

#ifndef LPLLSPATCHCACHE_H
#define LPLLSPATCHCACHE_H

#include <stdint.h>
#include <stdbool.h>

extern uint64_t *patchcache;
extern uint64_t *epatchcache;
extern size_t epatchcache_count;
extern uint32_t epatchcache_schema, epatchcache_abi;

bool ksurface_user_patchcache_load(void);

#endif /* LPLLSPATCHCACHE_H */
