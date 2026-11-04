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

#include <LindChain/ProcEnvironment/Surface/libkern/kxld/resolve.h>
#include <LindChain/ProcEnvironment/Surface/libkern/kxld/pseudo.h>
#include <LindChain/ProcEnvironment/Surface/libkern/radix/radix.h>
#include <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#include <LindChain/ProcEnvironment/Surface/libkern/version.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <os/lock.h>

static radix_tree_t g_kext_symbol_tree = { 0 };
static radix_tree_t g_kext_identity_tree = { 0 };
static os_unfair_lock g_kext_symbol_lock = OS_UNFAIR_LOCK_INIT;

LIBKERN_DEFINE_PATCHABLE(uint64_t, KXSymbolKey, (const char *name))
{
    uint64_t h = 1469598103934665603ULL;
    for(const uint8_t *p = (const uint8_t *)name; *p; p++)
    {
        h ^= *p;
        h *= 1099511628203ULL;
    }
    return h;
}

LIBKERN_DEFINE_PATCHABLE(void, KXRegisterExportCore, (const char *name, void *addr))
{
    const char *lookup = (name[0] == '_') ? name + 1 : name;
    os_unfair_lock_lock(&g_kext_symbol_lock);
    uint64_t key = KXSymbolKey(lookup);
    kx_export_t *symbol = radix_remove(&g_kext_symbol_tree, key);
    if(symbol != NULL)
    {
        free(symbol->name);
        free(symbol);
    }
    symbol = malloc(sizeof(*symbol));
    symbol->name = strdup(lookup);
    if(symbol->name == NULL)
    {
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return;
    }
    symbol->addr = addr;
    radix_insert(&g_kext_symbol_tree, key, symbol);
    os_unfair_lock_unlock(&g_kext_symbol_lock);
}

LIBKERN_DEFINE_PATCHABLE(void, KXRegisterExport, (const char *name,
                                                  void *addr))
{
    const char *lookup = (name[0] == '_') ? name + 1 : name;
    void *dlAddr = dlsym(RTLD_DEFAULT, lookup);
    if(dlAddr != NULL)
    {
        /* cant export */
        return;
    }
    os_unfair_lock_lock(&g_kext_symbol_lock);
    uint64_t key = KXSymbolKey(lookup);
    kx_export_t *symbol = radix_remove(&g_kext_symbol_tree, key);
    if(symbol != NULL)
    {
        free(symbol->name);
        free(symbol);
    }
    symbol = malloc(sizeof(*symbol));
    symbol->name = strdup(lookup);
    if(symbol->name == NULL)
    {
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return;
    }
    symbol->addr = addr;
    radix_insert(&g_kext_symbol_tree, key, symbol);
    os_unfair_lock_unlock(&g_kext_symbol_lock);
}

LIBKERN_DEFINE_PATCHABLE(void *, KXResolve, (const char *name))
{
    os_unfair_lock_lock(&g_kext_symbol_lock);
    if(!name)
    {
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return NULL;
    }
    const char *lookup = (name[0] == '_') ? name + 1 : name;
    kx_export_t *e = radix_lookup(&g_kext_symbol_tree, KXSymbolKey(lookup));
    if(e && strcmp(e->name, lookup) == 0)
    {
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return e->addr;
    }
    os_unfair_lock_unlock(&g_kext_symbol_lock);
    return dlsym(RTLD_DEFAULT, lookup);
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, KXRegisterKext, (kxld_image_info_t *image_info))
{
    os_unfair_lock_lock(&g_kext_symbol_lock);
    uint64_t key = KXSymbolKey(image_info->mod->identifier);
    kxld_image_info_t *found = radix_lookup(&g_kext_identity_tree, key);
    if(found != NULL)
    {
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return KERN_NAME_EXISTS;
    }
    radix_insert(&g_kext_identity_tree, key, image_info);
    os_unfair_lock_unlock(&g_kext_symbol_lock);
    return KERN_SUCCESS;
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, KXUnregisterKext, (kxld_image_info_t *image_info))
{
    os_unfair_lock_lock(&g_kext_symbol_lock);
    uint64_t key = KXSymbolKey(image_info->mod->identifier);
    kxld_image_info_t *found = radix_remove(&g_kext_identity_tree, key);
    if(found == NULL)
    {
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return KERN_NOT_FOUND;
    }
    os_unfair_lock_unlock(&g_kext_symbol_lock);
    return KERN_SUCCESS;
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, KXGetRegisteredKextForIdentifier, (const char *identifier,
                                                                           kxld_image_info_t **image_info))
{
    os_unfair_lock_lock(&g_kext_symbol_lock);
    uint64_t key = KXSymbolKey(identifier);
    kxld_image_info_t *found = radix_lookup(&g_kext_identity_tree, key);
    if(found)
    {
        *image_info = found;
        os_unfair_lock_unlock(&g_kext_symbol_lock);
        return KERN_SUCCESS;
    }
    os_unfair_lock_unlock(&g_kext_symbol_lock);
    return KERN_NOT_FOUND;
}

static uint32_t platform_query_version(void)
{
    char buf[32];
    size_t len = sizeof(buf);
    unsigned maj = 0, min = 0, pat = 0;
    
    if(sysctlbyname("kern.osproductversion", buf, &len, NULL, 0) != 0)
    {
        return 0;
    }
    if(sscanf(buf, "%u.%u.%u", &maj, &min, &pat) < 1)
    {
        return 0;
    }
    
    return KMOD_VERSION(maj, min, pat);
}

__attribute__((constructor))
static void register_nximage(void)
{
    /* pre-register ios and ksurface */
    kxld_image_info_t *ios_image_info = NULL;
    kern_return_t kr = kxopen_pseudo("com.apple.iphoneos", platform_query_version(), KMOD_FLAG_PERSISTENT | KMOD_FLAG_OVERRIDE_CORE | KMOD_FLAG_ALLOW_UNRESOLVED, &ios_image_info);
    if(kr != KERN_SUCCESS)
    {
        kpanic("failed to create pseudo kext for 'com.apple.ios'.");
    }
    
    size_t length = (size_t)ksurface_version_get_length();
    int version_buffer[length];
    if(ksurface_version_get_buffer(version_buffer, &length) != KERN_SUCCESS)
    {
        kpanic("failed to get the version of ksurface.");
    }
        
    kxld_image_info_t *ksurface_image_info = NULL;
    kr = kxopen_pseudo("ksurface", KMOD_VERSION(version_buffer[0], version_buffer[1], version_buffer[2]), KMOD_FLAG_PERSISTENT | KMOD_FLAG_OVERRIDE_CORE | KMOD_FLAG_ALLOW_UNRESOLVED, &ksurface_image_info);
    if(kr != KERN_SUCCESS)
    {
        kpanic("failed to create pseudo kext for 'ksurface'.");
    }
    
    if(KXRegisterKext(ios_image_info) != KERN_SUCCESS || KXRegisterKext(ksurface_image_info) != KERN_SUCCESS)
    {
        kpanic("failed to register pseudo kext's.");
    }
}
