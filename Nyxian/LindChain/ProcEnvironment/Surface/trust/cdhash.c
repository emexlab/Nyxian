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

/* ----------------------------------------------------------------------
 *  System Headers
 * -------------------------------------------------------------------- */
#import <CommonCrypto/CommonCrypto.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

/* ----------------------------------------------------------------------
 *  Constants
 * -------------------------------------------------------------------- */

#define CSMAGIC_EMBEDDED_SIGNATURE              0xfade0cc0
#define CSMAGIC_CODEDIRECTORY                   0xfade0c02

#define CSSLOT_CODEDIRECTORY                    0
#define CSSLOT_ALTERNATE_CODEDIRECTORIES        0x1000
#define CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT    0x1005

#define CS_HASHTYPE_SHA1                        1
#define CS_HASHTYPE_SHA256                      2
#define CS_HASHTYPE_SHA256_TRUNCATED            3
#define CS_HASHTYPE_SHA384                      4

/* ----------------------------------------------------------------------
 *  Types
 * -------------------------------------------------------------------- */
typedef struct {
    uint32_t type;
    uint32_t offset;
} CS_BlobIndex;

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
} CS_CodeDirectoryPrefix;

/* ----------------------------------------------------------------------
 *  Functions
 * -------------------------------------------------------------------- */
/* TODO: melt verifier and getter */
static bool __range_valid(size_t offset, size_t length, size_t total)
{
    return offset <= total && length <= total - offset;
}

static bool __is_code_directory_slot(uint32_t slot)
{
    if(slot == CSSLOT_CODEDIRECTORY)
    {
        return true;
    }
    
    if(slot >= CSSLOT_ALTERNATE_CODEDIRECTORIES &&
       slot < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)
    {
        return true;
    }
    
    return false;
}

static bool __cdhash_for_code_directory(const uint8_t *cd_bytes,
                                        size_t available,
                                        uint8_t result[USER_FSIGNATURES_CDHASH_LEN])
{
    if(cd_bytes == NULL ||
       result == NULL ||
       available < sizeof(CS_CodeDirectoryPrefix))
    {
        return false;
    }
    
    CS_CodeDirectoryPrefix cd;
    memcpy(&cd, cd_bytes, sizeof(cd));
    if(OSSwapBigToHostInt32(cd.magic) != CSMAGIC_CODEDIRECTORY)
    {
        return false;
    }
    
    uint32_t length = OSSwapBigToHostInt32(cd.length);
    if(length < sizeof(CS_CodeDirectoryPrefix) || length > available)
    {
        return false;
    }
    
    switch(cd.hashType)
    {
        case CS_HASHTYPE_SHA1:
        {
            uint8_t digest[CC_SHA1_DIGEST_LENGTH];
            CC_SHA1(cd_bytes, (CC_LONG)length, digest);
            memcpy(result, digest, USER_FSIGNATURES_CDHASH_LEN);
            return true;
        }
        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED:
        {
            uint8_t digest[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(cd_bytes, (CC_LONG)length, digest);
            memcpy(result, digest, USER_FSIGNATURES_CDHASH_LEN);
            return true;
        }
        case CS_HASHTYPE_SHA384:
        {
            uint8_t digest[CC_SHA384_DIGEST_LENGTH];
            CC_SHA384(cd_bytes, (CC_LONG)length, digest);
            memcpy(result, digest, USER_FSIGNATURES_CDHASH_LEN);
            return true;
        }
        default:
        {
            return false;
        }
    }
}

static bool superblob_get_cdhash(const uint8_t *signature,
                                 size_t signature_size,
                                 uint8_t out[USER_FSIGNATURES_CDHASH_LEN])
{
    if(signature == NULL || out == NULL || signature_size < offsetof(CS_SuperBlob, index))
    {
        return false;
    }
    
    CS_SuperBlob header;
    memcpy(&header, signature, offsetof(CS_SuperBlob, index));
    
    if(OSSwapBigToHostInt32(header.magic) != CSMAGIC_EMBEDDED_SIGNATURE)
    {
        return false;
    }
    
    uint32_t blob_length =
    OSSwapBigToHostInt32(header.length);
    
    uint32_t count =
    OSSwapBigToHostInt32(header.count);
    
    size_t fixed =
    offsetof(CS_SuperBlob, index);
    
    if(blob_length > signature_size || blob_length < fixed)
    {
        return false;
    }
    
    if(count > (blob_length - fixed) / sizeof(CS_BlobIndex))
    {
        return false;
    }
    
    const uint8_t *best_cd = NULL;
    size_t best_available = 0;
    unsigned best_rank = 0;
    
    for(uint32_t i = 0; i < count; i++)
    {
        CS_BlobIndex entry;
        
        memcpy(&entry, signature + fixed + ((size_t)i * sizeof(entry)), sizeof(entry));
        uint32_t type =
        OSSwapBigToHostInt32(entry.type);
        
        uint32_t offset =
        OSSwapBigToHostInt32(entry.offset);
        
        if(!__is_code_directory_slot(type))
        {
            continue;
        }
        
        if(offset >= blob_length)
        {
            return false;
        }
        
        size_t available =
        blob_length - offset;
        
        if(available < sizeof(CS_CodeDirectoryPrefix))
        {
            return false;
        }
        
        CS_CodeDirectoryPrefix cd;
        
        memcpy(&cd, signature + offset, sizeof(cd));
        if(OSSwapBigToHostInt32(cd.magic) != CSMAGIC_CODEDIRECTORY)
        {
            return false;
        }
        
        uint32_t cd_length = OSSwapBigToHostInt32(cd.length);
        if(cd_length < sizeof(CS_CodeDirectoryPrefix) || cd_length > available)
        {
            return false;
        }
        
        /* thanks XNU :3 */
        unsigned rank;
        switch(cd.hashType)
        {
            case CS_HASHTYPE_SHA1:
                rank = 1;
                break;
            case CS_HASHTYPE_SHA256_TRUNCATED:
                rank = 2;
                break;
            case CS_HASHTYPE_SHA256:
                rank = 3;
                break;
            case CS_HASHTYPE_SHA384:
                rank = 4;
                break;
            default:
            {
                return false;
            }
        }
        
        if(best_cd != NULL && rank == best_rank)
        {
            return false;
        }
        
        if(best_cd == NULL || rank > best_rank)
        {
            best_cd = signature + offset;
            best_available = available;
            best_rank = rank;
        }
    }
    
    if(best_cd == NULL)
    {
        return false;
    }
    
    return __cdhash_for_code_directory(best_cd, best_available, out);
}

static bool thin_macho_get_cdhash(const uint8_t *base,
                                  size_t size,
                                  uint8_t out[USER_FSIGNATURES_CDHASH_LEN])
{
    if(base == NULL || out == NULL || size < sizeof(uint32_t))
    {
        return false;
    }
    
    uint32_t magic;
    memcpy(&magic, base, sizeof(magic));
    
    size_t header_size;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    
    if(magic == MH_MAGIC_64)
    {
        if(size < sizeof(struct mach_header_64))
        {
            return false;
        }
        
        struct mach_header_64 hdr;
        memcpy(&hdr, base, sizeof(hdr));
        
        if(hdr.cputype != CPU_TYPE_ARM64)
        {
            return false;
        }
        
        header_size = sizeof(hdr);
        ncmds = hdr.ncmds;
        sizeofcmds = hdr.sizeofcmds;
    }
    else
    {
        return false;
    }
    
    if(!__range_valid(header_size,
                      sizeofcmds,
                      size))
    {
        return false;
    }
    
    size_t command_offset = header_size;
    size_t command_end =
    header_size + sizeofcmds;
    
    unsigned code_sig_count = 0;
    struct linkedit_data_command sig = {0};
    
    for(uint32_t i = 0; i < ncmds; i++)
    {
        if(!__range_valid(command_offset, sizeof(struct load_command), command_end))
        {
            return false;
        }
        
        struct load_command lc;
        
        memcpy(&lc, base + command_offset, sizeof(lc));
        if(lc.cmdsize < sizeof(struct load_command))
        {
            return false;
        }
        
        if(!__range_valid(command_offset, lc.cmdsize, command_end))
        {
            return false;
        }
        
        if(lc.cmd == LC_CODE_SIGNATURE)
        {
            if(lc.cmdsize < sizeof(struct linkedit_data_command))
            {
                return false;
            }
            
            if(++code_sig_count > 1)
            {
                return false;
            }
            
            memcpy(&sig, base + command_offset, sizeof(sig));
        }
        
        command_offset += lc.cmdsize;
    }
    
    if(code_sig_count != 1)
    {
        return false;
    }
    
    if(!__range_valid(sig.dataoff, sig.datasize, size))
    {
        return false;
    }
    
    return superblob_get_cdhash(base + sig.dataoff, sig.datasize, out);
}

bool CDHashOfMachO(const uint8_t *base,
                   size_t size,
                   uint8_t out[USER_FSIGNATURES_CDHASH_LEN])
{
    if(base == NULL || out == NULL || size < sizeof(uint32_t))
    {
        return false;
    }
    
    uint32_t magic;
    memcpy(&magic, base, sizeof(magic));
    if(magic == MH_MAGIC_64)
    {
        return thin_macho_get_cdhash(base, size, out);
    }
    
    bool fat64;
    if(magic == FAT_CIGAM)
    {
        fat64 = false;
    }
    else if(magic == FAT_CIGAM_64)
    {
        fat64 = true;
    }
    else
    {
        return false;
    }
    
    if(size < sizeof(struct fat_header))
    {
        return false;
    }
    
    struct fat_header fat;
    memcpy(&fat, base, sizeof(fat));
    
    uint32_t count = OSSwapBigToHostInt32(fat.nfat_arch);
    size_t arch_size = fat64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
    
    if(count > (size - sizeof(struct fat_header)) / arch_size)
    {
        return false;
    }
    
    size_t table = sizeof(struct fat_header);
    unsigned arm64_count = 0;
    
    uint64_t selected_offset = 0;
    uint64_t selected_size = 0;
    
    for(uint32_t i = 0; i < count; i++)
    {
        cpu_type_t cputype;
        uint64_t offset;
        uint64_t slice_size;
        
        if(fat64)
        {
            struct fat_arch_64 arch;
            memcpy(&arch, base + table + ((size_t)i * sizeof(arch)), sizeof(arch));
            cputype = OSSwapBigToHostInt32(arch.cputype);
            offset = OSSwapBigToHostInt64(arch.offset);
            slice_size = OSSwapBigToHostInt64(arch.size);
        }
        else
        {
            struct fat_arch arch;
            memcpy(&arch, base + table + ((size_t)i * sizeof(arch)), sizeof(arch));
            cputype = OSSwapBigToHostInt32(arch.cputype);
            offset = OSSwapBigToHostInt32(arch.offset);
            slice_size = OSSwapBigToHostInt32(arch.size);
        }
        
        if(cputype != CPU_TYPE_ARM64)
        {
            continue;
        }
        
        if(++arm64_count > 1)
        {
            return false;
        }
        
        if(offset > SIZE_MAX || slice_size > SIZE_MAX)
        {
            return false;
        }
        
        if(!__range_valid((size_t)offset, (size_t)slice_size, size))
        {
            return false;
        }
        
        selected_offset = offset;
        selected_size = slice_size;
    }
    
    if(arm64_count != 1)
    {
        return false;
    }
    
    return thin_macho_get_cdhash(base + (size_t)selected_offset, (size_t)selected_size, out);
}

bool CDHashOfFD(int fd,
                uint8_t out[USER_FSIGNATURES_CDHASH_LEN])
{
    if(fd < 0 || out == NULL)
    {
        return false;
    }
    
    struct stat st;
    if(fstat(fd, &st) != 0 || st.st_size <= 0)
    {
        return false;
    }
    
    if((uint64_t)st.st_size > SIZE_MAX)
    {
        return false;
    }
    
    size_t size = (size_t)st.st_size;
    const uint8_t *base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(base == MAP_FAILED)
    {
        return false;
    }
    
    bool ok = CDHashOfMachO(base, size, out);
    munmap((void *)base, size);
    return ok;
}
