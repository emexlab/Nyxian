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

#ifndef SURFACE_KEY_H
#define SURFACE_KEY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define KEY_LEN 32

bool get_kernel_ec_key(uint8_t **priv_bytes, size_t *priv_len, uint8_t **pub_bytes, size_t *pub_len);
int store_kernel_key(uint8_t *priv_bytes, size_t priv_len, uint8_t *pub_bytes, size_t pub_len);
bool get_static_kernel_key(uint8_t **priv_bytes, size_t *priv_len, uint8_t **pub_bytes, size_t *pub_len);

#endif /* SURFACE_KEY_H */
