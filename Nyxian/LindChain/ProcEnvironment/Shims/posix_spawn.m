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
#import <LindChain/ProcEnvironment/PEFileTable.h>
#import <LindChain/ProcEnvironment/Shims/environment.h>
#import <LindChain/ProcEnvironment/Shims/proxy.h>
#import <LindChain/ProcEnvironment/Shims/posix_spawn.h>
#import <LindChain/ProcEnvironment/litehook/litehook.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/ZSign/zsigner.h>
#import <LiveProcessLegacy/LPLSyscall.h>
#import <Broadpatch/Broadpatch.h>
#import <fcntl.h>
#import <ksurface_config.h>
#include <ksurface_abi.h>
#include <sys/stat.h>

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

#pragma mark - posix_spawn implementation

LIBKERN_PATCH(int, posix_spawn, (pid_t *process_identifier,
                                 const char *path,
                                 const posix_spawn_file_actions_t *fa,
                                 const posix_spawnattr_t *spawn_attr,
                                 char *const argv[],
                                 char *const envp[]),
{
    short spawnFlags = 0;
    pid_t spawnPgroup = 0;
    
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
    
    /*
     * resolving realpath of the executable, to prevent
     * weird file bugs to happen, this is standard
     * apple validity. I got no idea tbh.
     */
    char *resolved = realpath(path, NULL);
    if(resolved == NULL)
    {
        /* errno comes from realpath */
        return errno;
    }
    
    /*
     * checking code signature of resolved binary,
     * otherwise it wont be able to run.
     */
    LCMachO *machO = LCMapMachO(resolved, true);
    bool cs_valid = false;
    if(machO != nil)
    {
        cs_valid = LCCheckCodeSignature(machO);
        LCUnmapMachO(machO);
    }
    if(!cs_valid)
    {
        /* attempt signing */
        int fd = open(path, O_RDWR);
        if(fd >= 0)
        {
            int ret = (int)liveshim_syscall(SYS_sign, fd);
            close(fd);
            if(ret != 0)
            {
                /* errno comes from the syscall in this case */
                goto out_free_resolved;
            }
        }
        else
        {
            goto out_free_resolved;
        }
        
        /*
         * checking if kernel virt actually signed
         * executable.
         */
        LCMachO *machO = LCMapMachO(resolved, true);
        if(machO != nil)
        {
            cs_valid = LCCheckCodeSignature(machO);
            LCUnmapMachO(machO);
        }
        if(!cs_valid)
        {
            errno = ENOEXEC;
        out_free_resolved:
            free(resolved);
            return errno;
        }
    }
    
    /*
     * create new file table of all current file descriptors,
     * because they are by default inherited by the new child
     * process which is expected behaviour. the file actions
     * can alter that stabily.
     */
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
    
    /*
     * trying to spawn process via old ass ServerSession API, which
     * then triggers the subsystem LDEProcess on the host side.
     */
    int64_t pid = environment_proxy_spawn_process_at_path([NSString stringWithCString:resolved encoding:NSUTF8StringEncoding], NSArrayFromCArray(argv), NSDictionaryFromCDictionary(envp), fileTable, nsCwd, spawnFlags, spawnPgroup);
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

/*
 * https://github.com/Apple-FOSS-Mirror/Libc/blob/2ca2ae74647714acfc18674c3114b1a5d3325d7d/sys/posix_spawn.c#L1358
 *
 * skidded from apple them selves..
 */
LIBKERN_PATCH(int, posix_spawnp, (pid_t * __restrict pid,
                                  const char * __restrict file,
                                  const posix_spawn_file_actions_t *file_actions,
                                  const posix_spawnattr_t * __restrict attrp,
                                  char *const argv[ __restrict],
                                  char *const envp[ __restrict]),
{
    const char *env_path;
    char *bp;
    char *cur;
    char *p;
    int lp;
    int ln;
    int err = 0;
    int eacces = 0;
    struct stat sb;
    char path_buf[PATH_MAX];
    
    if((env_path = getenv("PATH")) == NULL)
    {
        env_path = "/";
    }
    
    /* If it's an absolute or relative path name, it's easy. */
    if(index(file, '/'))
    {
        bp = (char *)file;
        cur = NULL;
        goto retry;
    }
    
    bp = path_buf;
    
    /* If it's an empty path name, fail in the usual POSIX way. */
    if(*file == '\0')
    {
        return ENOENT;
    }
    
    if((cur = alloca(strlen(env_path) + 1)) == NULL)
    {
        return ENOMEM;
    }
    
    strcpy(cur, env_path);
    
    while((p = strsep(&cur, ":")) != NULL)
    {
        /*
         * It's a SHELL path -- double, leading and trailing colons
         * mean the current directory.
         */
        if(*p == '\0')
        {
            p = ".";
            lp = 1;
        }
        else
        {
            lp = (int)strlen(p);
        }
        ln = (int)strlen(file);
        
        /*
         * If the path is too long complain.  This is a possible
         * security issue; given a way to make the path too long
         * the user may spawn the wrong program.
         */
        if(lp + ln + 2 > sizeof(path_buf))
        {
            err = ENAMETOOLONG;
            goto done;
        }
        
        bcopy(p, path_buf, lp);
        path_buf[lp] = '/';
        bcopy(file, path_buf + lp + 1, ln);
        path_buf[lp + ln + 1] = '\0';
        
    retry:
        err = posix_spawn(pid, bp, file_actions, attrp, argv, envp);
        switch(err)
        {
            case E2BIG:
            case ENOMEM:
            case ETXTBSY:
                goto done;
            case ELOOP:
            case ENAMETOOLONG:
            case ENOENT:
            case ENOTDIR:
                break;
            case ENOEXEC:
                goto done;
            default:
                /*
                 * EACCES may be for an inaccessible directory or
                 * a non-executable file.  Call stat() to decide
                 * which.  This also handles ambiguities for EFAULT
                 * and EIO, and undocumented errors like ESTALE.
                 * We hope that the race for a stat() is unimportant.
                 */
                if(stat(bp, &sb) != 0)
                {
                    break;
                }
                
                if(err == EACCES)
                {
                    eacces = 1;
                    continue;
                }
                
                goto done;
        }
    }
    
    err = eacces ? EACCES : ENOENT;
    
done:
    return err;
});

#pragma mark - Initilizer

void environment_posix_spawn_init(void)
{
    LIBKERN_INSTALL_PATCH(posix_spawn);
    LIBKERN_INSTALL_PATCH(posix_spawnp);
}
