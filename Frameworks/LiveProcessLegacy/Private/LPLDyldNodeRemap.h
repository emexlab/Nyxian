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

#ifndef LPLDYLDNODEREMAP_H
#define LPLDYLDNODEREMAP_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <stdbool.h>
#include <stdint.h>

#define INODE_BANK_CAPACITY 1024
#define INODE_INVALID       0x0

typedef struct {
    ino_t ino;
    char real_path[PATH_MAX];
    char redirect_path[PATH_MAX];
    bool in_use;
} DyldInodeEntry;

ino_t inode_for_fd(int fd);
void inode_bank_init(void);
void inode_bank_put(ino_t ino, const char *real_path);
void inode_bank_set_redirect(ino_t ino, const char *redirect_path);
bool inode_bank_get_path(ino_t ino, char *out_path, size_t max_len);
bool inode_bank_get_real_path(ino_t ino, char *out_path, size_t max_len);
bool inode_bank_get_ino_by_path(const char *path, ino_t *out_ino);
void inode_bank_unlink_all(const char *tmp_root);

ino_t fake_inode_for_path(const char *path);

#endif /* LPLDYLDNODEREMAP_H */
