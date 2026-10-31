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

#ifndef TRUST_KEYCHAIN_H
#define TRUST_KEYCHAIN_H

/* I love shiney keysss >~< */
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>

kern_return_t ksurface_keychain_update(void);

kern_return_t ksurface_keychain_match(ksurface_nxt2_blob_footer_t *footer, ksurface_nxt2_blob_header_t *header);

#endif /* TRUST_KEYCHAIN_H */
