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

#ifndef TRUST_SIGNING_H
#define TRUST_SIGNING_H

#if NX_ROM_BOOTLOADER
#define trust_nxt2_sign     NXROMBootNXT2Sign
#define trust_nxt2_sign_fd  NXROMBootNXT2SignFD
#endif

/* ----------------------------------------------------------------------
 *  System Headers
 * -------------------------------------------------------------------- */
#include <CoreFoundation/CoreFoundation.h>
#include <mach/kern_return.h>

/* ----------------------------------------------------------------------
 *  Project Headers
 * -------------------------------------------------------------------- */
#include <LindChain/ProcEnvironment/Surface/trust/entitlement.h>

/* ----------------------------------------------------------------------
 *  Constants
 * -------------------------------------------------------------------- */
#define APPEND_TAG_NXTR "NXTR"
#define APPEND_TAG_NXT2 "NXT2"

#define NXT2_PUBKEY_MAGIC       0x4E32504B
#define NXT2_PUBKEY_VERSION     1
#define NXT2_VENDOR_NAME_MAX    255

/* ----------------------------------------------------------------------
 *  Types
 * -------------------------------------------------------------------- */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t name_len;
    uint32_t key_len;
} nxt2_pubkey_header_t;

typedef struct {
    char *vendor_name;
    uint8_t *public_key;
    size_t public_key_len;
} nxt2_vendor_key_t;

/* ----------------------------------------------------------------------
 *  Function Prototypes
 * -------------------------------------------------------------------- */
kern_return_t trust_remove_blob(const char *path);
kern_return_t trust_remove_blob_fd(int fd);

kern_return_t trust_nxt2_sign(const char *path, CFDictionaryRef entitlements, bool signBlob, const char *priv_der_path);
kern_return_t trust_nxt2_sign_fd(int fd, CFDictionaryRef entitlements, bool signBlob, const char *priv_der_path);
kern_return_t trust_nxt2_read(const char *path, ksurface_nxt2_t *result);
kern_return_t trust_nxt2_read_fd(int fd, ksurface_nxt2_t *result);

kern_return_t trust_nxt2_generate_rootca_keypair(const char *vendor_name, const char *public_key_path, const char *private_key_path);
kern_return_t trust_nxt2_public_key_read(const char *path, nxt2_vendor_key_t *result);

#endif /* TRUST_SIGNING_H */
