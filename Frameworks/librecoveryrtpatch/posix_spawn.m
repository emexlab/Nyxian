/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2026 emexlab
 Copyright (C) 2026 roothider

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
#include <spawn.h>
#include <limits.h>
#include <Broadpatch/Broadpatch.h>
#include <errno.h>
#include "ksurface_abi.h"
#include <malloc/malloc.h>
#include <LiveProcessLegacy/LPLSyscall.h>
#include <LiveProcessLegacy/LPLFileport.h>
#include "spawn_bootstrap.h"

#ifndef POSIX_SPAWN_SETSID
#define POSIX_SPAWN_SETSID 0x0400
#endif

/* https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/spawn_internal.h#L352-L360 */
typedef enum {
    PSFA_OPEN = 0,
    PSFA_CLOSE = 1,
    PSFA_DUP2 = 2,
    PSFA_INHERIT = 3,
    PSFA_FILEPORT_DUP2 = 4,
    PSFA_CHDIR = 5,
    PSFA_FCHDIR = 6
} psfa_t;

/* https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/spawn_internal.h#L375-L394 */
typedef struct _psfa_action {
    psfa_t  psfaa_type;                     /* file action type */
    union {
        int psfaa_filedes;                  /* fd to operate on */
        mach_port_name_t psfaa_fileport;    /* fileport to operate on */
    };
    union {
        struct {
            int     psfao_oflag;            /* open flags to use */
            mode_t  psfao_mode;             /* mode for open */
            char    psfao_path[PATH_MAX];   /* path to open */
        } psfaa_openargs;
        struct {
            int psfad_newfiledes;           /* new file descriptor to use */
        } psfaa_dup2args;
        struct {
            char    psfac_path[PATH_MAX];   /* path to chdir */
        } psfaa_chdirargs;
    };
} _psfa_action_t;

/* https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/spawn_internal.h#L414 */
typedef struct _posix_spawn_file_actions {
    int             psfa_act_alloc;         /* available actions space */
    int             psfa_act_count;         /* count of defined actions */
    _psfa_action_t  psfa_act_acts[];        /* actions array (uses c99) */
} *_posix_spawn_file_actions_t;

typedef __darwin_mach_port_t fileport_t;

int64_t liveshim_syscall(uint32_t syscall_num, ...);

@interface PEFileHandle : NSObject <NSSecureCoding,NSCopying>

@property (nonatomic,strong) NSObject<OS_xpc_object> *fd;

+ (instancetype)handleForFileDescriptor:(int)fd;
+ (instancetype)handleForFilePort:(fileport_t)fp;
+ (instancetype)handleForFileAtPath:(NSString*)path withFlags:(int)flags withPermissions:(int)perm;
+ (instancetype)handleForFileAtPath:(NSString*)path withFlags:(int)flags;
+ (instancetype)handleForFileAtPath:(NSString*)path;
- (void)setFileDescriptor:(int)fd;
- (int)extractFileDescriptor;
- (BOOL)extractFileDescriptorToLoc:(int)loc;
- (BOOL)writeOut:(NSString*)path;
- (BOOL)writeIn:(NSString*)path;

@end

@interface PEFileTable : NSObject <NSSecureCoding>

@property (nonatomic) NSMutableDictionary<NSNumber*,PEFileHandle*> *fd_map;

+ (instancetype)currentTable;
+ (instancetype)emptyTable;

- (void)apply;
- (int)appendFileDescriptor:(int)fd withMappingToLoc:(int)loc;
- (int)appendFilePort:(fileport_t)fp withMappingToLoc:(int)loc;
- (int)appendFileDescriptor:(int)fd;
- (int)closeWithFileDescriptor:(int)fd;
- (int)openWithFileDescriptor:(int)fd withPath:(const char*)path withFlags:(int)flags withMode:(mode_t)mode;
- (int)dup2WithOldFileDescriptor:(int)oldFd withNewFileDescriptor:(int)newFd;

@end

int64_t environment_proxy_spawn_process_at_path(NSString *path, NSArray *arguments, NSDictionary *environment, PEFileTable *fileTable, NSString *workingDirectory, short spawnFlags, pid_t spawnPgroup);

#pragma mark - posix_spawn helper

NSArray<NSString*> *NSArrayFromCArray(char *const argv[])
{
    /* sanity check */
    if(argv == NULL)
    {
        return @[];
    }
    
    int argc = 0;
    while(argv[argc] != NULL)
    {
        argc++;
    }
    
    /* creating mutable array with predefined argv lenght  */
    NSMutableArray<NSObject<NSSecureCoding,NSCopying> *> *array = [NSMutableArray arrayWithCapacity:argc];
    
    /*
     * itterating through each argument and stuff the mutable
     * array with each argument.
     */
    for(int i = 0; i < argc; i++)
    {
        NSObject<NSSecureCoding,NSCopying> *arg = nil;
        
        /* converting C into NSString */
        arg = [NSString stringWithCString:argv[i] encoding:NSUTF8StringEncoding];
        
        /* sanity checking arg object */
        if(arg != NULL)
        {
            /* and obviously appending it */
            [array addObject:arg];
        }
    }
    
    /* return immutable array */
    return [array copy];
}

NSDictionary<NSString*,NSString*> *NSDictionaryFromCDictionary(char *const envp[])
{
    /* sanity check */
    if(envp == NULL)
    {
        return @{};
    }
    
    /* creating mutable dictionary */
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    
    /*
     * itterating through each environment variable
     * to convert it into ObjC.
     */
    for(char *const *p = envp; *p != NULL; p++)
    {
        /*
         * converting entire environment variable into
         * ObjC object.
         */
        NSString *entry = [NSString stringWithCString:*p encoding:NSUTF8StringEncoding];
        
        /* sanity check */
        if(entry == NULL)
        {
            continue;
        }
        
        /* getting range till equation */
        NSRange equalRange = [entry rangeOfString:@"="];
        
        if(equalRange.location == NSNotFound)
        {
            continue;
        }
        
        /* crafting other properties  */
        NSString *key = [entry substringToIndex:equalRange.location];
        NSString *value = [entry substringFromIndex:equalRange.location + 1];
            
        /* sanity check */
        if(key &&
           value)
        {
            dict[key] = value;
        }
    }
    
    return [dict copy];
}

#pragma mark - posix_spawn persona

int posix_spawnattr_set_persona_np(const posix_spawnattr_t *attr, uid_t persona, uint32_t flags);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *attr, uid_t uid);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *attr, gid_t gid);

#define PE_PERSONA_FLAGS_OVERRIDE   0x00000001
#define PE_PERSONA_UID              0x00010000
#define PE_PERSONA_GID              0x00020000

typedef struct {
    uid_t pspi_id;
    uint32_t pspi_flags;
    uid_t pspi_uid;
    gid_t pspi_gid;
} pe_persona_info_t;

static ssize_t pe_persona_offset(void)
{
    static ssize_t offset = -2;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        offset = -1;
        posix_spawnattr_t attr;
        if(posix_spawnattr_init(&attr) != 0)
        {
            return;
        }
        void *base = *(void **)&attr;
        size_t size = base ? malloc_size(base) : 0;
        void **before = size >= sizeof(void *) ? malloc(size) : NULL;
        if(before != NULL)
        {
            memcpy(before, base, size);
            if(posix_spawnattr_set_persona_np(&attr, 0x7A11, PE_PERSONA_FLAGS_OVERRIDE) == 0 &&
               posix_spawnattr_set_persona_uid_np(&attr, 0x1A2B3C) == 0 &&
               posix_spawnattr_set_persona_gid_np(&attr, 0x2B3C4D) == 0)
            {
                for(size_t at = 0; at + sizeof(void *) <= size; at += sizeof(void *))
                {
                    pe_persona_info_t *info = *(pe_persona_info_t **)((char *)base + at);
                    if(before[at / sizeof(void *)] != NULL || info == NULL)
                    {
                        continue;
                    }
                    if(info->pspi_id == 0x7A11 && info->pspi_uid == 0x1A2B3C && info->pspi_gid == 0x2B3C4D &&
                       (info->pspi_flags & (PE_PERSONA_UID | PE_PERSONA_GID)) == (PE_PERSONA_UID | PE_PERSONA_GID))
                    {
                        offset = (ssize_t)at;
                        break;
                    }
                }
            }
            free(before);
        }
        posix_spawnattr_destroy(&attr);
    });
    return offset;
}

static NSString *pe_persona_string(const posix_spawnattr_t *spawn_attr)
{
    if(spawn_attr == NULL)
    {
        return nil;
    }
    ssize_t offset = pe_persona_offset();
    void *base = spawn_attr ? *(void **)spawn_attr : NULL;
    if(offset < 0 || base == NULL || (size_t)offset + sizeof(void *) > malloc_size(base))
    {
        return nil;
    }
    pe_persona_info_t *info = *(pe_persona_info_t **)((char *)base + offset);
    if(info == NULL || !(info->pspi_flags & (PE_PERSONA_UID | PE_PERSONA_GID)))
    {
        return nil;
    }
    NSString *uid = (info->pspi_flags & PE_PERSONA_UID) ? [NSString stringWithFormat:@"%u", info->pspi_uid] : @"-";
    NSString *gid = (info->pspi_flags & PE_PERSONA_GID) ? [NSString stringWithFormat:@"%u", info->pspi_gid] : @"-";
    return [NSString stringWithFormat:@"%@:%@", uid, gid];
}

#pragma mark - posix_spawn implementation

static void pe_release_bootstrap(mach_port_t *port)
{
    if(MACH_PORT_VALID(*port))
    {
        mach_port_deallocate(mach_task_self(), *port);
    }
}

LIBKERN_PATCH(int, posix_spawn, (pid_t *process_identifier,
                                 const char *path,
                                 const posix_spawn_file_actions_t *fa,
                                 const posix_spawnattr_t *spawn_attr,
                                 char *const argv[],
                                 char *const envp[]),
{
    short spawnFlags = 0;
    pid_t spawnPgroup = 0;
    bool bootstrapPresent = false;
    mach_port_t bootstrap __attribute__((cleanup(pe_release_bootstrap))) = MACH_PORT_NULL;
    int bootstrapError = pe_spawn_bootstrap_copy(spawn_attr, &bootstrapPresent, &bootstrap);
    if(bootstrapError != 0)
    {
        return bootstrapError;
    }
    
    if(spawn_attr != NULL)
    {
        int attrRet = posix_spawnattr_getflags(spawn_attr, &spawnFlags);
        if(attrRet != 0)
        {
            return attrRet;
        }
        
        if((spawnFlags & POSIX_SPAWN_SETSID) &&
           (spawnFlags & POSIX_SPAWN_SETPGROUP))
        {
            return EINVAL;
        }
        
        if(spawnFlags & POSIX_SPAWN_SETPGROUP)
        {
            attrRet = posix_spawnattr_getpgroup(spawn_attr, &spawnPgroup);
            if(attrRet != 0)
            {
                return attrRet;
            }
        }
    }
    
    char *resolved = realpath(path, NULL);
    if(resolved == NULL)
    {
        /* errno comes from realpath */
        return errno;
    }
    
    PEFileTable *fileTable = [PEFileTable currentTable];
    NSMutableIndexSet *closeOnExec = [NSMutableIndexSet indexSet];
    bool cloexecDefault = false;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    cloexecDefault = (spawnFlags & POSIX_SPAWN_CLOEXEC_DEFAULT) != 0;
#endif
    for(NSNumber *key in fileTable.fd_map.allKeys)
    {
        int fd = key.intValue;
        if(fd < 0)
        {
            continue;
        }
        
        int fdFlags = fcntl(fd, F_GETFD);
        if(cloexecDefault ||
           (fdFlags >= 0 && (fdFlags & FD_CLOEXEC)))
        {
            [closeOnExec addIndex:(NSUInteger)fd];
        }
    }
    
    /*
     * nullified cwd buffer, because of the case where a posix
     * file actions sets the buffer via PSFA_CHDIR, if not we
     * retrieve the cwd and use it instead
     * as the cwd of the child process, which is expected posix
     * behaviour.
     */
    char cwd[PATH_MAX] = {};
    
    if(fa == NULL)
    {
        /* preventing a NULL ptr deref. */
        goto skip_fileactions;
    }
    
    /* interpretting file actions :3c */
    _posix_spawn_file_actions_t *faPtr = (_posix_spawn_file_actions_t*)fa;
    
    for(uint64_t i = 0; i < (*faPtr)->psfa_act_count; i++)
    {
        _psfa_action_t *action = &((*faPtr)->psfa_act_acts[i]);
        
        /* TODO: handle failure */
        switch((*faPtr)->psfa_act_acts[i].psfaa_type)
        {
            case PSFA_OPEN:
                [fileTable openWithFileDescriptor:action->psfaa_filedes withPath:action->psfaa_openargs.psfao_path withFlags:action->psfaa_openargs.psfao_oflag withMode:action->psfaa_openargs.psfao_mode];
                if(action->psfaa_filedes >= 0)
                {
                    if(action->psfaa_openargs.psfao_oflag & O_CLOEXEC)
                    {
                        [closeOnExec addIndex:(NSUInteger)action->psfaa_filedes];
                    }
                    else
                    {
                        [closeOnExec removeIndex:(NSUInteger)action->psfaa_filedes];
                    }
                }
                break;
            case PSFA_CLOSE:
                [fileTable closeWithFileDescriptor:action->psfaa_filedes];
                if(action->psfaa_filedes >= 0)
                {
                    [closeOnExec removeIndex:(NSUInteger)action->psfaa_filedes];
                }
                break;
            case PSFA_DUP2:
                [fileTable dup2WithOldFileDescriptor:action->psfaa_filedes withNewFileDescriptor:action->psfaa_dup2args.psfad_newfiledes];
                /* dup2 (also onto itself) clears close-on-exec of the target */
                if(action->psfaa_dup2args.psfad_newfiledes >= 0)
                {
                    [closeOnExec removeIndex:(NSUInteger)action->psfaa_dup2args.psfad_newfiledes];
                }
                break;
            case PSFA_INHERIT:
                [fileTable appendFileDescriptor:action->psfaa_filedes];
                if(action->psfaa_filedes >= 0)
                {
                    [closeOnExec removeIndex:(NSUInteger)action->psfaa_filedes];
                }
                break;
            case PSFA_FILEPORT_DUP2:
                [fileTable appendFilePort:action->psfaa_fileport withMappingToLoc:action->psfaa_dup2args.psfad_newfiledes];
                if(action->psfaa_dup2args.psfad_newfiledes >= 0)
                {
                    [closeOnExec removeIndex:(NSUInteger)action->psfaa_dup2args.psfad_newfiledes];
                }
                break;
            case PSFA_CHDIR:
                /* not available on iOS but shrug, add it anyways */
                strlcpy(cwd, action->psfaa_chdirargs.psfac_path, PATH_MAX);
                break;
            case PSFA_FCHDIR:
            {
                /* not available on iOS but shrug, add it anyways */
                char path[PATH_MAX];
                if(fcntl(action->psfaa_filedes, F_GETPATH, path) != -1)
                {
                    strlcpy(cwd, path, PATH_MAX);
                }
                break;
            }
            default:
                break;
        }
    }
    
skip_fileactions:
    
    /* FIX: the exec step, drop what is still marked close-on-exec */
    [closeOnExec enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
        [fileTable closeWithFileDescriptor:(int)idx];
    }];
    
    if(cwd[0] == '\0')
    {
        getcwd(cwd, PATH_MAX);
    }
    
    /* the old ServerSession api requires paths as NSString */
    NSString *nsCwd = [NSString stringWithCString:cwd encoding:NSUTF8StringEncoding];
    if(nsCwd == nil)
    {
        free(resolved);
        return EAGAIN;
    }
    
    /* persona ids for the child, the host checks whether this process may hand them out */
    NSMutableDictionary *environment = [NSDictionaryFromCDictionary(envp) mutableCopy];
    [environment removeObjectForKey:@"__PE_SPAWN_PERSONA"];
    NSString *persona = pe_persona_string(spawn_attr);
    if(persona != nil)
    {
        environment[@"__PE_SPAWN_PERSONA"] = persona;
    }
    
    int64_t pid = environment_proxy_spawn_process_at_path([NSString stringWithCString:resolved encoding:NSUTF8StringEncoding], NSArrayFromCArray(argv), environment, fileTable, nsCwd, spawnFlags, spawnPgroup);
    if(pid < 0)
    {
        /* lacking entitlements? */
        free(resolved);
        return EPERM;
    }
    
    /* overwriting passed process identifier pointer if applicable */
    if(process_identifier != NULL)
    {
        *process_identifier = (pid_t)pid;
    }
    
    liveshim_syscall(SYS_waittask, pid);
    
    free(resolved);
    return 0;
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(posix_spawn);
}
