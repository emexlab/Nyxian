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

#import <Foundation/Foundation.h>
#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#include <LindChain/ProcEnvironment/Surface/libkern/sandbox.h>
#include <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#include <LindChain/ProcEnvironment/Surface/fs/sandbox.h>
#include <os/lock.h>

#define KSURFACE_FS_MAX_MOUNTS      192
#define KSURFACE_FS_MAX_REGIONS     64
#define KSURFACE_FS_MAX_RESOLVE     16

#define FS_PERM_MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef struct {
    /* properties */
    FSMountPermissionFlags permission;
    FSNodeType type;
    CFStringRef entitlementNeededRead;
    CFStringRef entitlementNeededWrite;
    
    /* identitiy */
    char decl[PATH_MAX];
    char bind[PATH_MAX];
    char site[PATH_MAX];
    char phys[PATH_MAX];
} FSMountRecord;

typedef struct {
    char phys[PATH_MAX];
    FSMountPermissionFlags perm;
} FSRegion;

static FSMountRecord g_records[KSURFACE_FS_MAX_MOUNTS];
static size_t g_record_count = 0;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;
static char g_home[PATH_MAX];

static bool fs_contains(const char *parent,
                        const char *child)
{
    size_t n = strlen(parent);
    if(n == 0)
    {
        return false;
    }
    if(n == 1 && parent[0] == '/')
    {
        return child[0] == '/';
    }
    if(strncmp(parent, child, n) != 0)
    {
        return false;
    }
    return child[n] == '\0' || child[n] == '/';
}

static void fs_resolve(const char *in,
                       ssize_t self,
                       char *out,
                       size_t outsz,
                       FSMountPermissionFlags *cap_out)
{
    char cur[PATH_MAX];
    strlcpy(cur, in, sizeof(cur));
    
    FSMountPermissionFlags cap = kFSMountPermissionReadWrite;
    
    for(int round = 0; round < KSURFACE_FS_MAX_RESOLVE; round++)
    {
        ssize_t best    = -1;
        size_t bestlen = 0;
        
        for(size_t i = 0; i < g_record_count; i++)
        {
            if((ssize_t)i == self)
            {
                continue;
            }
            if(g_records[i].type != kFSNodeTypeSymbolicLink)
            {
                continue;
            }
            if(!fs_contains(g_records[i].decl, cur))
            {
                continue;
            }
            size_t l = strlen(g_records[i].decl);
            if(l > bestlen)
            {
                bestlen = l;
                best = (ssize_t)i;
            }
        }
        if(best < 0)
        {
            break;
        }
        
        cap = FS_PERM_MIN(cap, g_records[best].permission);
        
        char next[PATH_MAX];
        snprintf(next, sizeof(next), "%s%s", g_records[best].bind, cur + bestlen);
        if(strcmp(next, cur) == 0)
        {
            break;
        }
        strlcpy(cur, next, sizeof(cur));
    }
    
    strlcpy(out, cur, outsz);
    if(cap_out)
    {
        *cap_out = cap;
    }
}

static bool fs_issuable(const char *phys)
{
    return (g_home[0] && fs_contains(g_home, phys));
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, ksurface_fs_sandbox_registry_add, (FSMountPermissionFlags permission,
                                                                           FSNodeType type,
                                                                           const char *mount_dir,
                                                                           const char *bind_dir,
                                                                           CFStringRef entitlementNeededRead,
                                                                           CFStringRef entitlementNeededWrite))
{
    if(mount_dir == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    if(permission != kFSMountPermissionNone &&
       permission != kFSMountPermissionRead &&
       permission != kFSMountPermissionReadWrite)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    os_unfair_lock_lock(&g_lock);
    
    if(g_record_count >= KSURFACE_FS_MAX_MOUNTS)
    {
        os_unfair_lock_unlock(&g_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    FSMountRecord *r = &g_records[g_record_count];
    memset(r, 0, sizeof(*r));
    r->permission = permission;
    r->type = type;
    if(entitlementNeededRead != NULL)
    {
        r->entitlementNeededRead = CFRetain(entitlementNeededRead);
    }
    if(entitlementNeededWrite != NULL)
    {
        r->entitlementNeededWrite = CFRetain(entitlementNeededWrite);
    }
    strlcpy(r->decl, mount_dir, PATH_MAX);
    if(bind_dir != NULL)
    {
        strlcpy(r->bind, bind_dir, PATH_MAX);
    }
    
    /* sealing mount dynamically */
    fs_resolve(r->decl, (ssize_t)g_record_count, r->site, PATH_MAX, NULL);
    if(r->type == kFSNodeTypeSymbolicLink)
    {
        fs_resolve(r->bind, (ssize_t)g_record_count, r->phys, PATH_MAX, NULL);
    }
    else
    {
        strlcpy(r->phys, r->site, PATH_MAX);
    }
    char canon[PATH_MAX];
    if(realpath(r->phys, canon) != NULL)
    {
        strlcpy(r->phys, canon, PATH_MAX);
    }
    else
    {
        klog_log("ksurface:fs:sandbox", "unmaterialized mount: %s (%s)", r->phys, strerror(errno));
    }
    
    g_record_count++;
    
    os_unfair_lock_unlock(&g_lock);
    return KERN_SUCCESS;
}

static void fs_seal_record(FSMountRecord *r,
                           ssize_t self,
                           bool warn)
{
    fs_resolve(r->decl, self, r->site, PATH_MAX, NULL);
    if(r->type == kFSNodeTypeSymbolicLink)
    {
        fs_resolve(r->bind, self, r->phys, PATH_MAX, NULL);
    }
    else
    {
        strlcpy(r->phys, r->site, PATH_MAX);
    }
    
    char canon[PATH_MAX];
    if(realpath(r->phys, canon) != NULL)
    {
        strlcpy(r->phys, canon, PATH_MAX);
    }
    else if(warn)
    {
        klog_log("ksurface:fs:sandbox", "unmaterialized mount: %s (%s)", r->phys, strerror(errno));
    }
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, ksurface_fs_sandbox_registry_remove, (const char *path))
{
    if(path == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    os_unfair_lock_lock(&g_lock);
    
    if(g_record_count == 0)
    {
        os_unfair_lock_unlock(&g_lock);
        return KERN_INVALID_NAME;
    }
    
    ssize_t victim = -1;
    for(size_t i = g_record_count; i > 0; i--)
    {
        if(strcmp(g_records[i - 1].decl, path) == 0)
        {
            victim = (ssize_t)(i - 1);
            break;
        }
    }
    
    if(victim < 0)
    {
        os_unfair_lock_unlock(&g_lock);
        return KERN_INVALID_NAME;
    }
    
    if(g_records[victim].entitlementNeededRead != NULL)
    {
        CFRelease(g_records[victim].entitlementNeededRead);
    }
    if(g_records[victim].entitlementNeededWrite != NULL)
    {
        CFRelease(g_records[victim].entitlementNeededWrite);
    }
    
    memmove(&g_records[victim], &g_records[victim + 1], (g_record_count - (size_t)victim - 1) * sizeof(FSMountRecord));
    g_record_count--;
    memset(&g_records[g_record_count], 0, sizeof(FSMountRecord));
    for(size_t i = 0; i < g_record_count; i++)
    {
        fs_seal_record(&g_records[i], (ssize_t)i, false);
    }
    
    os_unfair_lock_unlock(&g_lock);
    return KERN_SUCCESS;
}

static void fs_env_init(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *home = getenv("HOME");
        char canon[PATH_MAX];
        if(home == NULL)
        {
            klog_log("ksurface:fs:sandbox", "HOME unset");
        }
        else if(realpath(home, canon) != NULL)
        {
            strlcpy(g_home, canon, PATH_MAX);
        }
        else
        {
            strlcpy(g_home, home, PATH_MAX);
        }
    });
}

kern_return_t ksurface_fs_sandbox_init(void)
{
    fs_env_init();
    if(g_home[0] == '\0')
    {
        klog_log("ksurface:fs:sandbox", "HOME unset, refusing to initialize");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

static void fs_region_push(FSRegion *regs,
                           size_t *n,
                           const char *phys,
                           FSMountPermissionFlags perm)
{
    if(perm == kFSMountPermissionNone)
    {
        return;
    }
    
    for(size_t i = 0; i < *n; i++)
    {
        if(strcmp(regs[i].phys, phys) == 0)
        {
            if(perm > regs[i].perm)
            {
                regs[i].perm = perm;
            }
            return;
        }
    }
    if(*n >= KSURFACE_FS_MAX_REGIONS)
    {
        return;
    }
    
    strlcpy(regs[*n].phys, phys, PATH_MAX);
    regs[*n].perm = perm;
    (*n)++;
}

static FSMountPermissionFlags fs_backing_permission(const char *phys)
{
    FSMountPermissionFlags best = kFSMountPermissionNone;
    size_t bestlen = 0;
    
    for(size_t i = 0; i < g_record_count; i++)
    {
        if(g_records[i].type != kFSNodeTypeDirectory)
        {
            continue;
        }
        if(!fs_contains(g_records[i].phys, phys))
        {
            continue;
        }
        
        size_t l = strlen(g_records[i].phys);
        if(l >= bestlen)
        {
            bestlen = l; best = g_records[i].permission;
        }
    }
    return best;
}

LIBKERN_DEFINE_PATCHABLE(CFArrayRef, ksurface_fs_sandbox_copy_sandbox_extensions_for_entitlements, (const char *path,
                                                                                                    FSMountPermissionFlags wanted,
                                                                                                    CFDictionaryRef entitlements))
{
    if(path == NULL || path[0] != '/')
    {
        return NULL;
    }
    if(wanted == kFSMountPermissionNone)
    {
        return NULL;
    }
    
    os_unfair_lock_lock(&g_lock);
    
    FSRegion *regs = calloc(KSURFACE_FS_MAX_REGIONS, sizeof(FSRegion));
    size_t nregs = 0;
    if(regs == NULL)
    {
        os_unfair_lock_unlock(&g_lock);
        return NULL;
    }
    
    {
        char phys[PATH_MAX];
        FSMountPermissionFlags link_cap = kFSMountPermissionReadWrite;
        
        fs_resolve(path, -1, phys, sizeof(phys), &link_cap);
        
        if(!fs_issuable(phys))
        {
            klog_log("ksurface:fs:sandbox", "path outside container: %s -> %s", path, phys);
            free(regs);
            os_unfair_lock_unlock(&g_lock);
            return NULL;
        }
        
        FSMountPermissionFlags perm = FS_PERM_MIN(wanted, link_cap);
        perm = FS_PERM_MIN(perm, fs_backing_permission(phys));
        if(perm == kFSMountPermissionNone)
        {
            klog_log("ksurface:fs:sandbox", "no mount grants access at %s", path);
            free(regs);
            os_unfair_lock_unlock(&g_lock);
            return NULL;
        }
        
        fs_region_push(regs, &nregs, phys, perm);
    }
    
    for(size_t cursor = 0; cursor < nregs; cursor++)
    {
        FSRegion region = regs[cursor];
        
        for(size_t i = 0; i < g_record_count; i++)
        {
            FSMountRecord *r = &g_records[i];
            if(r->permission == kFSMountPermissionNone)
            {
                continue;
            }
            if(!fs_contains(region.phys, r->site))
            {
                continue;
            }
            if(strcmp(region.phys, r->phys) == 0)
            {
                continue;
            }
            
            FSMountPermissionFlags perm = FS_PERM_MIN(wanted, r->permission);
            
            if(entitlements != NULL)
            {
                if(r->entitlementNeededRead != NULL && CFDictionaryGetValue(entitlements, r->entitlementNeededRead) != kCFBooleanTrue)
                {
                    continue;
                }
                
                /* write only doesnt work yet lol*/
                if(r->entitlementNeededWrite != NULL && CFDictionaryGetValue(entitlements, r->entitlementNeededWrite) != kCFBooleanTrue)
                {
                    perm = FS_PERM_MIN(perm, kFSMountPermissionRead);
                }
            }
            
            if(perm == kFSMountPermissionNone)
            {
                continue;
            }
            
            if(r->type == kFSNodeTypeSymbolicLink)
            {
                perm = FS_PERM_MIN(perm, fs_backing_permission(r->phys));
                if(fs_contains(region.phys, r->phys) && perm <= region.perm)
                {
                    continue;
                }
            }
            else
            {
                if(perm <= region.perm)
                {
                    continue;
                }
            }
            
            fs_region_push(regs, &nregs, r->phys, perm);
        }
    }
    
    CFMutableArrayRef sandboxFileExtensions = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    for(size_t i = 0; i < nregs; i++)
    {
        bool covered = false;
        for(size_t j = 0; j < nregs && !covered; j++)
        {
            if(i == j || regs[j].perm < regs[i].perm)
            {
                continue;
            }
            int c = strcmp(regs[j].phys, regs[i].phys);
            if(c == 0)
            {
                covered = (regs[j].perm > regs[i].perm) || (j < i);
            }
            else
            {
                covered = fs_contains(regs[j].phys, regs[i].phys);
            }
        }
        if(covered)
        {
            continue;
        }
        if(!fs_issuable(regs[i].phys))
        {
            klog_log("ksurface:fs:sandbox", "refusing region outside container: %s", regs[i].phys);
            continue;
        }
        
        const char *cls = (regs[i].perm == kFSMountPermissionReadWrite) ? APP_SANDBOX_READ_WRITE : APP_SANDBOX_READ;
        char *tok = sandbox_extension_issue_file(cls, regs[i].phys, 0);
        if(tok == NULL)
        {
            klog_log("ksurface:fs:sandbox", "issue failed: %s", regs[i].phys);
            continue;
        }
        
        CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tok, strlen(tok) + 1);
        if(data)
        {
            CFArrayAppendValue(sandboxFileExtensions, data); CFRelease(data);
        }
        free(tok);
    }
    
    os_unfair_lock_unlock(&g_lock);
    return sandboxFileExtensions;
}

LIBKERN_DEFINE_PATCHABLE(CFArrayRef, ksurface_fs_sandbox_copy_sandbox_extensions, (const char *path,
                                                                                   FSMountPermissionFlags wanted))
{
    return ksurface_fs_sandbox_copy_sandbox_extensions_for_entitlements(path, wanted, NULL);
}

LIBKERN_DEFINE_PATCHABLE(CFDataRef, ksurface_fs_sandbox_copy_sandbox_extension_for_arbitary_path, (const char *path,
                                                                                                   FSMountPermissionFlags wanted))
{
    if(path == NULL || path[0] != '/')
    {
        return NULL;
    }
    if(wanted == kFSMountPermissionNone)
    {
        return NULL;
    }
    
    const char *cls = (wanted == kFSMountPermissionReadWrite) ? APP_SANDBOX_READ_WRITE : APP_SANDBOX_READ;
    char *tok = sandbox_extension_issue_file(cls, path, 0);
    if(tok == NULL)
    {
        klog_log("ksurface:fs:sandbox", "issue failed: %s", path);
        return NULL;
    }
    
    return CFDataCreate(kCFAllocatorDefault, (const UInt8 *)tok, strlen(tok) + 1);
}
