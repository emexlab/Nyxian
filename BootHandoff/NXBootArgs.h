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

#ifndef NXBOOTARGS_H
#define NXBOOTARGS_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NX_BOOT_ARGS_MAX 1024

#define NX_BOOT_ARG_VERBOSE         "-v"
#define NX_BOOT_ARG_NO_KEXTS        "-x"
#define NX_BOOT_ARG_KLOG_OBFUSCATE  "klog_obfuscate"
#define NX_BOOT_ARG_FS_SANDBOX      "fs_sandbox"

const char *NXBootGetArguments(void);

static inline const char *NXBootArgsNextToken(const char **cursor, size_t *length)
{
    const char *p = *cursor;
    while(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if(*p == '\0') { *cursor = p; return NULL; }
    const char *start = p;
    while(*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    *length = (size_t)(p - start);
    *cursor = p;
    return start;
}

/* flag given as its own token ("-v") */
static inline bool NXBootArgsHasFlag(const char *args, const char *flag)
{
    if(args == NULL || flag == NULL) return false;
    size_t flagLength = strlen(flag), length = 0;
    const char *cursor = args, *token;
    while((token = NXBootArgsNextToken(&cursor, &length)) != NULL)
    {
        if(length == flagLength && strncmp(token, flag, length) == 0) return true;
    }
    return false;
}

/* the value of the last key=value for key; false when not given */
static inline bool NXBootArgsGetValue(const char *args, const char *key, char *out, size_t size)
{
    if(args == NULL || key == NULL) return false;
    size_t keyLength = strlen(key), length = 0;
    const char *cursor = args, *token, *found = NULL;
    size_t foundLength = 0;
    while((token = NXBootArgsNextToken(&cursor, &length)) != NULL)
    {
        if(length > keyLength && strncmp(token, key, keyLength) == 0 && token[keyLength] == '=')
        {
            found = token + keyLength + 1;
            foundLength = length - keyLength - 1;
        }
    }
    if(found == NULL) return false;
    if(out != NULL && size > 0)
    {
        size_t copy = foundLength < size - 1 ? foundLength : size - 1;
        memcpy(out, found, copy);
        out[copy] = '\0';
    }
    return true;
}

/* key=value as a boolean; fallback when not given or not a boolean */
static inline bool NXBootArgsGetBool(const char *args, const char *key, bool fallback)
{
    char value[16];
    if(!NXBootArgsGetValue(args, key, value, sizeof(value))) return fallback;
    if(!strcasecmp(value, "1") || !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "on")) return true;
    if(!strcasecmp(value, "0") || !strcasecmp(value, "no") || !strcasecmp(value, "false") || !strcasecmp(value, "off")) return false;
    return fallback;
}

/* an old key as the 0.11.6.1 bootloader saw it, including the defaults it registered */
static inline bool NXBootArgsLegacyBool(const char *key, bool fallback)
{
    CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
    if(name == NULL) return fallback;
    Boolean valid = false;
    Boolean value = CFPreferencesGetAppBooleanValue(name, kCFPreferencesCurrentApplication, &valid);
    CFRelease(name);
    return valid ? (bool)value : fallback;
}

/*
 * This boot's arguments into out. true: from the bootloader (0.11.6.2+). false: no boot argument host (0.11.6.1),
 * built from the old keys so it reads the same either way.
 */
static inline bool NXBootArgsCopy(char *out, size_t size)
{
    if(out == NULL || size == 0) return false;
    out[0] = '\0';
    const char *(*host)(void) = (const char *(*)(void))dlsym(RTLD_DEFAULT, "NXBootGetArguments");
    const char *args = host != NULL ? host() : NULL;
    if(args != NULL)
    {
        strlcpy(out, args, size);
        return true;
    }
    if(NXBootArgsLegacyBool("nyxian.boot.verbose", false)) strlcat(out, " -v", size);
    if(!NXBootArgsLegacyBool("nyxian.boot.kextLoading", true)) strlcat(out, " -x", size);
    if(!NXBootArgsLegacyBool("nyxian.boot.log.obfuscated", true)) strlcat(out, " klog_obfuscate=0", size);
    if(!NXBootArgsLegacyBool("nyxian.boot.sandbox.filesystems", true)) strlcat(out, " fs_sandbox=0", size);
    if(out[0] == ' ') memmove(out, out + 1, strlen(out));
    return false;
}

#ifdef __cplusplus
}
#endif

#endif /* NXBOOTARGS_H */
