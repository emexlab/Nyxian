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

#include <LindChain/ProcEnvironment/Surface/fs/mount.h>
#include <LindChain/ProcEnvironment/Surface/trust/entitlement.h>
#include <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <os/lock.h>

const char FS_MOUNT_SANDBOX[PATH_MAX] = "/dev/sandbox";
const char FS_MOUNT_NOUNLINK[PATH_MAX] = "/dev/nounlink";

static os_unfair_lock g_mount_lock = OS_UNFAIR_LOCK_INIT;

static kern_return_t __ksurface_fs_mount_clear_directory(const char *dir_path)
{
    DIR *dir = opendir(dir_path);
    if(!dir)
    {
        return KERN_NOT_FOUND;
    }
    
    struct dirent *entry;
    char path[PATH_MAX];
    
    while((entry = readdir(dir)) != NULL)
    {
        if(strcmp(entry->d_name, ".") == 0 ||
           strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }
        
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        
        struct stat statbuf;
        if(lstat(path, &statbuf) == 0)
        {
            if(S_ISDIR(statbuf.st_mode))
            {
                __ksurface_fs_mount_clear_directory(path);
                rmdir(path);
            }
            else
            {
                unlink(path);
            }
        }
    }
    
    closedir(dir);
    return KERN_SUCCESS;
}

kern_return_t ksurface_fs_mount(FSMountAttr attributes,
                                const char *old_mount_dir,
                                const char *old_bind_dir,
                                ...)
{
    if(old_mount_dir == NULL || old_mount_dir[0] != '/')
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    if(old_bind_dir != NULL && old_bind_dir[0] != '/')
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    /*
     * mount2 is much better since it solves many confusion problems
     * you shall use mount2 instead of mount since mount has a problem.
     *
     * either mount_dir is the path that is user accessible or
     * mount_dir is the path that represents the device, the problem
     * with that is that then bind_dir_becomes the mount_dir.
     */
    
    const char *device_dir = NULL;
    const char *mount_dir = NULL;
    
    if(old_mount_dir && old_bind_dir)
    {
        device_dir = old_bind_dir;
        mount_dir = old_mount_dir;
    }
    else
    {
        device_dir = "/dev/nounlink";
        mount_dir = old_mount_dir;
    }
    
    return ksurface_fs_mount2(attributes, device_dir, mount_dir);
}

kern_return_t ksurface_fs_mount2(FSMountAttr attributes,
                                 const char *device_dir,
                                 const char *mount_dir,
                                 ...)
{
    if(mount_dir == NULL || mount_dir[0] != '/' ||
       device_dir == NULL || device_dir[0] != '/')
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    /* check for yet unsupported flags */
    if((attributes & (kFSMountAttrReadEntitlement | kFSMountAttrWriteEntitlement)) ||
       ((attributes & kFSMountAttrWrite) && !(attributes & kFSMountAttrRead)) /* we need write only path's some day at some point lol */)
    {
        return KERN_NOT_SUPPORTED;
    }
    
    /* figure out sandboxing permissions */
    FSMountPermissionFlags permissions = kFSMountPermissionNone;
    if(attributes & (kFSMountAttrWrite | kFSMountAttrRead))
    {
        permissions = (attributes & kFSMountAttrWrite) ? kFSMountPermissionReadWrite : kFSMountPermissionRead;
    }
    
    /* if bind_dir is givven it becomes a directory */
    FSNodeType type = kFSNodeTypeSymbolicLink;
    if(device_dir == FS_MOUNT_NOUNLINK ||
       strncmp(device_dir, FS_MOUNT_NOUNLINK, PATH_MAX) == 0)
    {
        type = kFSNodeTypeDirectory;
    }
    
    /* shall this be cleared? */
    if(attributes & kFSMountAttrClear)
    {
        /* doesn't really matter much what this returns */
        __ksurface_fs_mount_clear_directory(type == kFSNodeTypeDirectory ? mount_dir : device_dir);
    }
    
    /* preparing node */
    FSPreserverNode node = { .type = type, 0 };
    strlcpy(node.name, mount_dir, PATH_MAX);
    if(device_dir != NULL && type != kFSNodeTypeDirectory)
    {
        strlcpy(node.target, device_dir, PATH_MAX);
    }
    
    os_unfair_lock_lock(&g_mount_lock);
    
    /* and register it */
    kern_return_t kr = ksurface_fs_preserver_add_node(node);
    if(kr != KERN_SUCCESS)
    {
        os_unfair_lock_unlock(&g_mount_lock);
        return kr;
    }
    
    /* adding sandbox filesystem register for mount */
    kr = ksurface_fs_sandbox_registry_add(permissions, type, mount_dir, (type == kFSNodeTypeDirectory) ? NULL : device_dir, attributes & kFSMountAttrReadPlatform ? kNXT2EntitlementPlatform : NULL, attributes & kFSMountAttrWritePlatform ? kNXT2EntitlementPlatform : NULL);
    if(kr != KERN_SUCCESS)
    {
        /* need to recert preserver addition */
        kern_return_t kr_critical = ksurface_fs_preserver_remove_node(node.name);
        if(kr_critical != KERN_SUCCESS)
        {
            kpanic("failed to remove preserver node on failure of adding sandbox registry entry: %s (sbx entry error: %s)", mach_error_string(kr_critical), mach_error_string(kr));
        }
    }
    os_unfair_lock_unlock(&g_mount_lock);
    return kr;
}

kern_return_t ksurface_fs_umount(const char *mount_dir)
{
    if(mount_dir == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    char rpath[PATH_MAX];
    if(realpath(mount_dir, rpath) == NULL)
    {
        /* path doesn't exist so mount does not? */
        strlcpy(rpath, mount_dir, PATH_MAX);
    }
    
    /* perform userspace unmount */
    os_unfair_lock_lock(&g_mount_lock);
    kern_return_t kr = ksurface_fs_sandbox_registry_remove(rpath);
    if(kr != KERN_SUCCESS)
    {
        os_unfair_lock_unlock(&g_mount_lock);
        return kr;
    }
    
    kr = ksurface_fs_preserver_remove_node(rpath);
    if(kr != KERN_SUCCESS)
    {
        os_unfair_lock_unlock(&g_mount_lock);
        return kr;
    }
    os_unfair_lock_unlock(&g_mount_lock);
    
    return KERN_SUCCESS;
}

#define FS_MOUNT_VAR_MAX 32

typedef struct {
    char var[FS_MOUNT_VAR_MAX];
    char path[PATH_MAX];
} ksurface_fs_mount_var_t;

static size_t fs_mount_store_index = 0;
static ksurface_fs_mount_var_t **fs_mount_store = NULL;
static os_unfair_lock g_fs_mount_var_lock = OS_UNFAIR_LOCK_INIT;

static inline kern_return_t ksurface_fs_mount3_lookup_nolock(const char *var,
                                                             ksurface_fs_mount_var_t **var_obj)
{
    assert(var != NULL);

    if(fs_mount_store == NULL)
    {
        return KERN_NOT_FOUND;
    }
    
    for(size_t index = 0; index < fs_mount_store_index; index++)
    {
        ksurface_fs_mount_var_t *var_slot = fs_mount_store[index];
        if(strncmp(var_slot->var, var, FS_MOUNT_VAR_MAX) == 0)
        {
            *var_obj = var_slot;
            return KERN_SUCCESS;
        }
    }

    return KERN_NOT_FOUND;
}

kern_return_t ksurface_fs_mount3_lookup(const char *var,
                                        char *path)
{
    if(var == NULL)
    {
        /* null pointers are obviously not good */
        return KERN_INVALID_ADDRESS;
    }

    if(strnlen(var, FS_MOUNT_VAR_MAX) == FS_MOUNT_VAR_MAX)
    {
        /* invalid length */
        return KERN_INVALID_ARGUMENT;
    }

    /* now lets look this up */
    os_unfair_lock_lock(&g_fs_mount_var_lock);

    ksurface_fs_mount_var_t *var_obj = NULL;
    kern_return_t kr = ksurface_fs_mount3_lookup_nolock(var, &var_obj);
    if(kr != KERN_SUCCESS)
    {
        os_unfair_lock_unlock(&g_fs_mount_var_lock);
        return kr;
    }
    
    /* writing path lol */
    strlcpy(path, var_obj->path, PATH_MAX);

    os_unfair_lock_unlock(&g_fs_mount_var_lock);

    return KERN_SUCCESS;
}

static inline bool ksurface_fs_repair_path(char *path)
{
    /* absolute paths shall just fall through */
    if(path[0] != '/')
    {
        return false;
    }
    
    char repaired_path[PATH_MAX];
    int offset = 0;
    
    /* check if path begins with /etc or /var */
    if(strncmp(path, "/etc", 4) == 0 ||
       strncmp(path, "/var", 4) == 0)
    {
        offset += snprintf(repaired_path, sizeof(repaired_path), "/private");
    }
    
    bool is_slashed = false;
    for(int index = 0; (index + offset) < PATH_MAX; index++)
    {
        /* TODO: I feel there is a better more efficient sexy trick */
        if(is_slashed)
        {
            if(path[index] == '/')
            {
                continue;
            }
            
            is_slashed = false;
        }
        else if(path[index] == '/')
        {
            is_slashed = true;
        }
        
        repaired_path[offset++] = path[index];
    }
    
    strlcpy(path, repaired_path, PATH_MAX);
    
    return true;
}

static inline bool ksurface_fs_expand_path(const char *path,
                                           char *expanded_path)
{
    /* absolute paths shall just fall through */
    if(path[0] == '/')
    {
        strlcpy(expanded_path, path, PATH_MAX);
        return true;
    }
    else if(path[0] != '$')
    {
        /*
         * relative paths are not supported in the
         * kernel, cuz relative to what?
         */
        return false;
    }
    
    /* it seems to be a variable */
    char variable[FS_MOUNT_VAR_MAX];
    size_t var_end_char_index = 1;
    for(; var_end_char_index < (FS_MOUNT_VAR_MAX + 1); var_end_char_index++)
    {
        if(path[var_end_char_index] == '/' ||
           path[var_end_char_index] == '\0')
        {
            variable[var_end_char_index - 1] = '\0';
            break;
        }
        variable[var_end_char_index - 1] = path[var_end_char_index];
    }
    
    char var_path[PATH_MAX];
    if(ksurface_fs_mount3_lookup(variable, var_path) != KERN_SUCCESS)
    {
        return false;
    }
    
    if(path[var_end_char_index] == '\0')
    {
        snprintf(expanded_path, PATH_MAX, "%s", var_path);
    }
    else
    {
        snprintf(expanded_path, PATH_MAX, "%s/%s", var_path, &path[var_end_char_index]);
    }
    
    if(!ksurface_fs_repair_path(expanded_path))
    {
        return false;
    }
    
    return true;
}

kern_return_t ksurface_fs_mount3_var_add(const char *var,
                                         const char *path)
{
    if(var == NULL || path == NULL)
    {
        /* null pointers are obviously not good */
        return KERN_INVALID_ADDRESS;
    }

    if(strnlen(var, FS_MOUNT_VAR_MAX) == FS_MOUNT_VAR_MAX || strnlen(path, PATH_MAX) == PATH_MAX)
    {
        /* invalid length */
        return KERN_INVALID_ARGUMENT;
    }
    
    char expanded_var_path[PATH_MAX];
    if(!ksurface_fs_expand_path(path, expanded_var_path))
    {
        /* expansion failed */
        return KERN_NO_SPACE;
    }

    os_unfair_lock_lock(&g_fs_mount_var_lock);

    /* handling slot allocation */
    ksurface_fs_mount_var_t *slot = calloc(1, sizeof(ksurface_fs_mount_var_t));
    if(slot == NULL)
    {
        os_unfair_lock_unlock(&g_fs_mount_var_lock);
        return KERN_NO_SPACE;
    }

    /* handling pointer slot allocation */
    size_t var_insert_index = fs_mount_store_index++;
    if(fs_mount_store == NULL)
    {
        fs_mount_store = calloc(1, sizeof(ksurface_fs_mount_var_t*));
        if(fs_mount_store == NULL)
        {
            fs_mount_store_index--;
            os_unfair_lock_unlock(&g_fs_mount_var_lock);
            return KERN_NO_SPACE;
        }
    }
    else
    {
        ksurface_fs_mount_var_t **new_store = realloc(fs_mount_store, sizeof(ksurface_fs_mount_var_t*) * fs_mount_store_index);
        if(new_store == NULL)
        {
            fs_mount_store_index--;
            os_unfair_lock_unlock(&g_fs_mount_var_lock);
            return KERN_NO_SPACE;
        }
        fs_mount_store = new_store;
    }

    /* basically slot setup */
    strlcpy(slot->var, var, FS_MOUNT_VAR_MAX);
    strlcpy(slot->path, expanded_var_path, PATH_MAX);

    /* storing the slot */
    fs_mount_store[var_insert_index] = slot;

    os_unfair_lock_unlock(&g_fs_mount_var_lock);

    return KERN_SUCCESS;
}

kern_return_t ksurface_fs_mount3_var_del(const char *var)
{
    /* TODO: implement that feature */
    return KERN_NOT_SUPPORTED;
}

kern_return_t ksurface_fs_mount3(FSMountAttr attributes,
                                 const char *device_dir,
                                 const char *mount_dir,
                                 ...)
{
    if(device_dir == NULL || mount_dir == NULL)
    {
        /* null pointers are obviously not good */
        return KERN_INVALID_ADDRESS;
    }

    if(strnlen(device_dir, FS_MOUNT_VAR_MAX) == PATH_MAX || strnlen(mount_dir, PATH_MAX) == PATH_MAX)
    {
        /* invalid length */
        return KERN_INVALID_ARGUMENT;
    }
    
    /* accessed only within the log */
    char expanded_device_dir[PATH_MAX];
    char expanded_mount_dir[PATH_MAX];
    
    if(!ksurface_fs_expand_path(device_dir, expanded_device_dir) ||
       !ksurface_fs_expand_path(mount_dir, expanded_mount_dir))
    {
        /* expansion failed */
        return KERN_INVALID_ARGUMENT;
    }
    
    return ksurface_fs_mount2(attributes, expanded_device_dir, expanded_mount_dir);
}
