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

#ifndef NXROMFILEHASH_H
#define NXROMFILEHASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <CommonCrypto/CommonDigest.h>

typedef CC_SHA256_CTX NXROMSHA256Context;
#define NXROMSHA256Init(c) CC_SHA256_Init(c)
#define NXROMSHA256Update(c, d, n) CC_SHA256_Update((c), (d), (CC_LONG)(n))
#define NXROMSHA256Final(o, c) CC_SHA256_Final((o), (c))

#define NXROM_MACHO_DOMAIN "NXROM-MACHO-v1"
#define NXROM_FAT_DOMAIN "NXROM-FAT-v1"
#define NXROM_LC_SEGMENT_64 0x19u
#define NXROM_LC_CODE_SIGNATURE 0x1du
#define NXROM_LC_ID_DYLIB 0x0du
#define NXROM_LC_NX_LOADER 0x114514u
#define NXROM_MH_EXECUTE 2u
#define NXROM_MH_DYLIB 6u
#define NXROM_MH_NO_REEXPORTED_DYLIBS 0x100000u
#define NXROM_MH_PIE 0x200000u
#define NXROM_LIBCPP "/usr/lib/libc++.1.dylib"
#define NXROM_MAX_COMMAND_BYTES (1u << 24)

typedef enum {
    NXROMFileKindPlain = 0,
    NXROMFileKindMachO = 1,
    NXROMFileKindUnsupportedMachO = 2,
} NXROMFileKind;

static inline uint32_t NXROMLE32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline uint64_t NXROMLE64(const uint8_t *p)
{
    return (uint64_t)NXROMLE32(p) | (uint64_t)NXROMLE32(p + 4) << 32;
}

static inline uint32_t NXROMBE32(const uint8_t *p)
{
    return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
}

static inline uint64_t NXROMBE64(const uint8_t *p)
{
    return (uint64_t)NXROMBE32(p) << 32 | (uint64_t)NXROMBE32(p + 4);
}

static inline void NXROMPutLE32(uint8_t *p,
                                uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline int NXROMFileHashFail(char *error,
                                    size_t length,
                                    const char *format, ...)
{
    if(error && length)
    {
        va_list arguments;
        va_start(arguments, format);
        vsnprintf(error, length, format, arguments);
        va_end(arguments);
    }
    return 0;
}

static inline NXROMFileKind NXROMFileKindOf(const uint8_t *data,
                                            size_t size)
{
    if(size < 4)
    {
        return NXROMFileKindPlain;
    }
    uint32_t magic = NXROMLE32(data);
    if(magic == 0xfeedfacfu || magic == 0xbebafecau || magic == 0xbfbafecau)
    {
        return NXROMFileKindMachO;
    }
    if(magic == 0xfeedfaceu || magic == 0xcefaedfeu || magic == 0xcffaedfeu || magic == 0xcafebabeu || magic == 0xcafebabfu)
    {
        return NXROMFileKindUnsupportedMachO;
    }
    return NXROMFileKindPlain;
}

static inline int NXROMIsInsertedIDDylib(const uint8_t *command,
                                         uint32_t size,
                                         const char *name)
{
    size_t length = strlen(name);
    uint32_t expected = (uint32_t)(24 + ((length + 1 + 7) & ~(size_t)7));
    if(size != expected || NXROMLE32(command + 8) != 24 || NXROMLE32(command + 12) != 2
       || NXROMLE32(command + 16) != 0x10000 || NXROMLE32(command + 20) != 0x10000
       || memcmp(command + 24, name, length) != 0)
    {
        return 0;
    }
    for(uint32_t i = (uint32_t)(24 + length); i < size; i++)
    {
        if(command[i] != 0)
        {
            return 0;
        }
    }
    return 1;
}

static inline int NXROMIsLoaderCommand(const uint8_t *command,
                                       uint32_t size)
{
    if(size < 24)
    {
        return 0;
    }
    
    uint32_t offset = NXROMLE32(command + 8);
    size_t length = sizeof(NXROM_LIBCPP);
    return offset >= 24 && offset < size && size - offset >= length && memcmp(command + offset, NXROM_LIBCPP, length) == 0;
}

static inline int NXROMHashThin(const uint8_t *data,
                                size_t size,
                                const char *name,
                                uint8_t out[32],
                                char *error,
                                size_t errorLength)
{
    if(size < 32 || NXROMLE32(data) != 0xfeedfacfu)
    {
        return NXROMFileHashFail(error, errorLength, "not a 64-bit Mach-O");
    }
    
    uint32_t filetype = NXROMLE32(data + 12), ncmds = NXROMLE32(data + 16), sizeofcmds = NXROMLE32(data + 20), flags = NXROMLE32(data + 24);
    if(ncmds == 0 || sizeofcmds > size - 32 || sizeofcmds > NXROM_MAX_COMMAND_BYTES)
    {
        return NXROMFileHashFail(error, errorLength, "malformed load commands");
    }
    
    size_t end = 32 + (size_t)sizeofcmds, offset = 32;
    size_t dataoff = 0, signatures = 0;
    for(uint32_t i = 0; i < ncmds; i++)
    {
        if(end - offset < 8)
        {
            return NXROMFileHashFail(error, errorLength, "malformed load commands");
        }
        uint32_t cmd = NXROMLE32(data + offset), cmdsize = NXROMLE32(data + offset + 4);
        if(cmdsize < 8 || (cmdsize & 7) != 0 || cmdsize > end - offset)
        {
            return NXROMFileHashFail(error, errorLength, "malformed load commands");
        }
        if(cmd == NXROM_LC_CODE_SIGNATURE)
        {
            if(cmdsize != 16)
            {
                return NXROMFileHashFail(error, errorLength, "malformed LC_CODE_SIGNATURE");
            }
            dataoff = NXROMLE32(data + offset + 8);
            signatures++;
        }
        else if(cmd == NXROM_LC_SEGMENT_64)
        {
            if(cmdsize < 72 || NXROMLE32(data + offset + 64) > (cmdsize - 72) / 80)
            {
                return NXROMFileHashFail(error, errorLength, "malformed segment");
            }
        }
        
        offset += cmdsize;
    }
    
    if(offset != end)
    {
        return NXROMFileHashFail(error, errorLength, "malformed load commands");
    }
    
    if(signatures != 1)
    {
        return NXROMFileHashFail(error, errorLength, signatures ? "more than one code signature" : "no code signature (sign it ad hoc: codesign -s -)");
    }
    
    if(dataoff < end || dataoff > size)
    {
        return NXROMFileHashFail(error, errorLength, "the code signature lies outside the file");
    }
    
    size_t content = dataoff;
    offset = 32;
    for(uint32_t i = 0; i < ncmds; i++)
    {
        uint32_t cmd = NXROMLE32(data + offset), cmdsize = NXROMLE32(data + offset + 4);
        if(cmd == NXROM_LC_SEGMENT_64)
        {
            uint64_t fileoff = NXROMLE64(data + offset + 40), filesize = NXROMLE64(data + offset + 48);
            if(fileoff > 0 && filesize > 0 && fileoff < content)
            {
                content = (size_t)fileoff;
            }
            uint32_t nsects = NXROMLE32(data + offset + 64);
            for(uint32_t j = 0; j < nsects; j++)
            {
                const uint8_t *section = data + offset + 72 + 80 * (size_t)j;
                uint64_t sectionSize = NXROMLE64(section + 40);
                uint32_t sectionOffset = NXROMLE32(section + 48), type = NXROMLE32(section + 64) & 0xffu;
                if(sectionOffset > 0 && sectionSize > 0 && type != 0x1 && type != 0xc && type != 0x12 && sectionOffset < content)
                {
                    content = sectionOffset;
                }
            }
        }
        offset += cmdsize;
    }
    if(content < end)
    {
        return NXROMFileHashFail(error, errorLength, "the load commands overlap the code");
    }
    for(size_t i = end; i < content; i++)
    {
        if(data[i] != 0)
        {
            return NXROMFileHashFail(error, errorLength, "bytes between the load commands and the code");
        }
    }
    
    uint8_t *commands = malloc(sizeofcmds ? sizeofcmds : 1);
    if(!commands)
    {
        return NXROMFileHashFail(error, errorLength, "out of memory");
    }
    
    size_t kept = 0;
    uint32_t count = 0;
    offset = 32;
    for(uint32_t i = 0; i < ncmds; i++)
    {
        uint32_t cmd = NXROMLE32(data + offset), cmdsize = NXROMLE32(data + offset + 4);
        const uint8_t *command = data + offset;
        offset += cmdsize;
        if(cmd == NXROM_LC_ID_DYLIB && i == 0 && NXROMIsInsertedIDDylib(command, cmdsize, name))
        {
            continue;
        }
        if(cmd == NXROM_LC_NX_LOADER)
        {
            if(!NXROMIsLoaderCommand(command, cmdsize))
            {
                free(commands);
                return NXROMFileHashFail(error, errorLength, "a LiveContainer loader command that doesn't load libc++");
            }
            continue;
        }
        uint8_t *copy = commands + kept;
        memcpy(copy, command, cmdsize);
        if(cmd == NXROM_LC_SEGMENT_64)
        {
            char segment[17] = {0};
            memcpy(segment, copy + 8, 16);
            if(strcmp(segment, "__PAGEZERO") == 0)
            {
                memset(copy + 24, 0, 16);
            }
            else if(strcmp(segment, "__LINKEDIT") == 0)
            {
                memset(copy + 32, 0, 8);
                memset(copy + 48, 0, 8);
            }
        }
        else if(cmd == NXROM_LC_CODE_SIGNATURE)
        {
            memset(copy + 12, 0, 4);
        }
        kept += cmdsize;
        count++;
    }
    
    uint8_t header[32];
    memcpy(header, data, 32);
    NXROMPutLE32(header + 12, (filetype == NXROM_MH_EXECUTE || filetype == NXROM_MH_DYLIB) ? NXROM_MH_DYLIB : filetype);
    NXROMPutLE32(header + 16, count);
    NXROMPutLE32(header + 20, (uint32_t)kept);
    NXROMPutLE32(header + 24, flags & ~(NXROM_MH_NO_REEXPORTED_DYLIBS | NXROM_MH_PIE));
    
    NXROMSHA256Context context;
    NXROMSHA256Init(&context);
    NXROMSHA256Update(&context, NXROM_MACHO_DOMAIN, sizeof(NXROM_MACHO_DOMAIN));
    NXROMSHA256Update(&context, header, sizeof(header));
    NXROMSHA256Update(&context, commands, kept);
    NXROMSHA256Update(&context, data + content, dataoff - content);
    NXROMSHA256Final(out, &context);
    free(commands);
    return 1;
}

static inline int NXROMFileHash(const uint8_t *data,
                                size_t size,
                                const char *name,
                                uint8_t out[32],
                                char *error,
                                size_t errorLength)
{
    NXROMFileKind kind = NXROMFileKindOf(data, size);
    if(kind == NXROMFileKindUnsupportedMachO)
    {
        return NXROMFileHashFail(error, errorLength, "a 32-bit or big endian Mach-O");
    }
    if(kind == NXROMFileKindPlain)
    {
        NXROMSHA256Context context;
        NXROMSHA256Init(&context);
        NXROMSHA256Update(&context, data, size);
        NXROMSHA256Final(out, &context);
        return 1;
    }
    if(NXROMLE32(data) == 0xfeedfacfu)
    {
        return NXROMHashThin(data, size, name, out, error, errorLength);
    }
    
    int wide = NXROMLE32(data) == 0xbfbafecau;
    if(size < 8)
    {
        return NXROMFileHashFail(error, errorLength, "malformed fat header");
    }
    uint32_t slices = NXROMBE32(data + 4);
    size_t entry = wide ? 32 : 20;
    if(slices == 0 || slices > 16 || 8 + entry * slices > size)
    {
        return NXROMFileHashFail(error, errorLength, "malformed fat header");
    }
    NXROMSHA256Context context;
    NXROMSHA256Init(&context);
    NXROMSHA256Update(&context, NXROM_FAT_DOMAIN, sizeof(NXROM_FAT_DOMAIN));
    NXROMSHA256Update(&context, data + 4, 4);
    for(uint32_t i = 0; i < slices; i++)
    {
        const uint8_t *arch = data + 8 + entry * i;
        uint64_t offset = wide ? NXROMBE64(arch + 8) : NXROMBE32(arch + 8);
        uint64_t length = wide ? NXROMBE64(arch + 16) : NXROMBE32(arch + 12);
        if(offset > size || length > size - offset)
        {
            return NXROMFileHashFail(error, errorLength, "a fat slice lies outside the file");
        }
        uint8_t slice[32];
        if(!NXROMHashThin(data + offset, (size_t)length, name, slice, error, errorLength))
        {
            return 0;
        }
        NXROMSHA256Update(&context, arch, 8);
        NXROMSHA256Update(&context, slice, sizeof(slice));
    }
    NXROMSHA256Final(out, &context);
    return 1;
}

static inline int NXROMFileNXT2Plist(const uint8_t *data,
                                     size_t size,
                                     const uint8_t **plist,
                                     size_t *plistLength)
{
    *plist = NULL;
    *plistLength = 0;
    if(size < 8)
    {
        return 1;
    }
    if(memcmp(data + size - 4, "NXTR", 4) == 0)
    {
        return 0;
    }
    if(memcmp(data + size - 4, "NXT2", 4) != 0)
    {
        return 1;
    }
    uint32_t length = NXROMLE32(data + size - 8);
    const size_t header = 20 + 8 + 8, footer = 8 + 72;
    if(length < header + footer || length > 16384 || (size_t)length + 8 > size)
    {
        return 0;
    }
    const uint8_t *blob = data + size - 8 - length;
    uint64_t contained = NXROMLE64(blob + 28);
    if(contained > length - header - footer)
    {
        return 0;
    }
    *plist = blob + header;
    *plistLength = (size_t)contained;
    return 1;
}

#endif /* NXROMFILEHASH_H */
