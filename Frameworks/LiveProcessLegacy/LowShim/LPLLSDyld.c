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

#include <LiveProcessLegacy/LPLShim.h>
#include <LiveProcessLegacy/LPLLSDyld.h>
#include <LiveProcessLegacy/LPLDyldNodeRemap.h>
#include <LiveProcessLegacy/LPLCdhash.h>
#include <Frameworks/HWHook/HWHookThreadContext.h>
#include <mach-o/dyld_images.h>
#include <sys/mman.h>
#include <copyfile.h>
#include <sys/clonefile.h>
#include <copyfile.h>
#include <time.h>
#include <os/lock.h>
#include <pthread.h>
#include <LiveProcessLegacy/LPLLSPatchcache.h>
#include <Broadpatch/Broadpatch.h>
#include <Frameworks/libpatchfind/libpatchfind.h>

#if __has_include(<ksurface_config.h>)
#include <ksurface_config.h>
#else
#define KSURFACE_DYLD_HOOK_LOGGING_ENABLED 0
#define KSURFACE_DYLD_HARDENED_CDHASH_VERIFIER 1
#endif /* __has_include(<ksurface_config.h>) */

#if KSURFACE_DYLD_HOOK_LOGGING_ENABLED

static inline void _dyld_hook_log_timestamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    printf("[%6ld.%03ldms] ", ts.tv_sec % 1000, ts.tv_nsec / 1000000);
}

#define dyld_hook_log(fmt, ...) \
    do { \
        _dyld_hook_log_timestamp(); \
        printf(fmt, ##__VA_ARGS__); \
    } while (0)

#else
#define dyld_hook_log(fmt, ...) ((void)0)
#endif /* KSURFACE_DYLD_HOOK_LOGGING_ENABLED */

static int (*orig_dyld_open)(const char *path, int flags, mode_t mode);
static int (*orig_dyld_fcntl)(int fildes, int cmd, void *param);
static int (*orig_dyld_fstat64)(int fildes, struct stat *buf);
static int (*orig_dyld_stat64)(const char *path, struct stat *buf);
static int (*orig_dyld_openat)(int fd, const char *path, int flags, mode_t mode);

static int hook_fcntl(int fildes,
                      int cmd,
                      void *param)
{
    dyld_hook_log("[hook_fcntl:args] (fildes = %d, cmd: %d, param: %p)\n", fildes, cmd, param);
    int ret = orig_dyld_fcntl(fildes, cmd, param);
    if(cmd == F_GETPATH)
    {
        dyld_hook_log("[hook_fcntl:orig_return] (ret = %d, path: %s)\n", ret, (char*)param);
        inode_bank_get_path(inode_for_fd(fildes), param, MAXPATHLEN);
    }
#if KSURFACE_DYLD_HOOK_LOGGING_ENABLED
    else
    {
        dyld_hook_log("[hook_fcntl:orig_return] (ret = %d)\n", ret);
    }
#endif /* KSURFACE_DYLD_HOOK_LOGGING_ENABLED */
    
#if KSURFACE_DYLD_HOOK_LOGGING_ENABLED
    if(cmd == F_GETPATH)
    {
        dyld_hook_log("[hook_fcntl:return] (ret = %d, path: %s)\n", ret, (char*)param);
    }
    else
    {
        dyld_hook_log("[hook_fcntl:return] (ret = %d)\n", ret);
    }
#endif /* KSURFACE_DYLD_HOOK_LOGGING_ENABLED */
    
    return ret;
}

static const char *mmap_sandbox_map_exec_allowed_path = NULL;

static _Thread_local bool cdhash_verified = false;
static _Thread_local bool cdhash_must_valid;
static _Thread_local bool open_hardlock;
static _Thread_local const char *cdhash_data_container_match;
static _Thread_local dlopen_cdhash_verifier_failed_callback_t cdhash_verifier_failed_callback;
static int path_open(int fd,
                     int flags)
{
    char actualPath[PATH_MAX];
    if(fcntl(fd, F_GETPATH, actualPath) != -1)
    {
        dyld_hook_log("[path_open:path] %s\n", actualPath);
        
        const char prefix[] = "/private/var/mobile/Containers/Data";
        if(strncmp(actualPath, prefix, sizeof(prefix) - 1) == 0)
        {
            /* need a new path */
            char newTmpPath[PATH_MAX];
            snprintf(newTmpPath, sizeof(newTmpPath),  "%s/tmp/%d/0x%llx.dylib", mmap_sandbox_map_exec_allowed_path, getpid(), inode_for_fd(fd));    /* use tmp so iOS clears it automatically in LP home */
            
            dyld_hook_log("[path_open] new path: %s\n", newTmpPath);
            dyld_hook_log("[path_open] dyld needs to think that %s is located at %s\n", newTmpPath, actualPath);
            
            int copyfd = open(newTmpPath, flags);
            if(copyfd >= 0)
            {
                close(fd);
                dup2(copyfd, fd);
                close(copyfd);
                dyld_hook_log("[path_open] path already has APFS CoW copy\n");
                goto lv_bypass_setup_done;
            }
            
            dyld_hook_log("[path_open] APFS CoW copy needed\n");
            if(fclonefileat(fd, AT_FDCWD, newTmpPath, 0) == 0)
            {
                dyld_hook_log("[path_open] APFS CoW copy succeeded\n");
                copyfd = open(newTmpPath, flags);
                if(copyfd < 0)
                {
                    dyld_hook_log("[path_open] couldn't open file descriptor\n");
                    goto lv_bypass_setup_done;
                }
            }
            else
            {
             
                dyld_hook_log("[path_open] APFS CoW copy failed(errno: %s), falling back to copyfile\n", strerror(errno));
                copyfd = open(newTmpPath, O_RDWR | O_CREAT | O_TRUNC, 0777);
                if(copyfd < 0)
                {
                    dyld_hook_log("[path_open] couldn't open file descriptor\n");
                    goto lv_bypass_setup_done;
                }
            
                int ret = fcopyfile(fd, copyfd, NULL, COPYFILE_DATA);
                close(copyfd);
                if(ret != 0)
                {
                    dyld_hook_log("[path_open] fcopyfile failed: %s\n", strerror(errno));
                    goto lv_bypass_setup_done;
                }
                dyld_hook_log("[path_open] fcopyfile succeeded\n");
                
                copyfd = open(newTmpPath, flags);
                if(copyfd < 0)
                {
                    dyld_hook_log("[path_open] couldn't open file descriptor\n");
                    goto lv_bypass_setup_done;
                }
            }
            
            /* this to orient or selfs */
            ino_t inode = inode_for_fd(copyfd);
            dyld_hook_log("[path_open] setting up inode redirection for inode: 0x%llx\n", inode);
            inode_bank_put(inode, newTmpPath);
            inode_bank_set_redirect(inode, actualPath);
            
            close(fd);
            dup2(copyfd, fd);
            close(copyfd);
            
        lv_bypass_setup_done:
            
            if(cdhash_must_valid && !cdhash_verified)
            {
                /* no matter what this is not reentrant */
                cdhash_must_valid = false;
                cdhash_verified = false;
                
                lseek(fd, 0, SEEK_SET);
                /* need to get cdhash and then reset it's position */
                
                
                uint8_t cdhash[USER_FSIGNATURES_CDHASH_LEN];
                bool success = CDHashOfFD(fd, (uint8_t*)&cdhash);
                dyld_hook_log("[path_open] [nyxian cdhash verifier] (foundCdhash = %p, cdhash = %p)\n", cdhash, cdhash_data_container_match);
                
                /* match */
                if(!success ||
                   cdhash_data_container_match == NULL ||
                   memcmp(cdhash_data_container_match, cdhash, USER_FSIGNATURES_CDHASH_LEN) != 0)
                {
                    cdhash_verified = false;
                    dyld_hook_log("[path_open] [nyxian cdhash verifier] cdhash does not match, calling callback if givven\n");
                    
#if KSURFACE_DYLD_HARDENED_CDHASH_VERIFIER
                    open_hardlock = true;
#else
                    if(cdhash_verifier_failed_callback != NULL)
                    {
                        cdhash_verifier_failed_callback(fd, &open_hardlock);
                    }
#endif /* !KSURFACE_DYLD_HARDENED_CDHASH_VERIFIER */
                    
                    /* callback can set open hardlock */
                    if(open_hardlock)
                    {
                        dyld_hook_log("[path_open] [error: hard locked]\n");
                        errno = EACCES;
                        close(fd);
                        fd = -1;
                    }
                }
                else
                {
                    dyld_hook_log("[path_open] [nyxian cdhash verifier] cdhash valid!\n");
                    cdhash_verified = true;
                    lseek(fd, 0, SEEK_SET);
                }
            }
        }
    }
    return fd;
}

static int hook_open(const char *path,
                     int flags,
                     mode_t mode)
{
    dyld_hook_log("[hook_open:args] (path = %s, flags = %d, mode = %d)\n", path, flags, mode);
    if(open_hardlock)
    {
        dyld_hook_log("[hook_open:args] [error: hard locked]\n");
        errno = EACCES;
        return -1;
    }
    
    int fd = orig_dyld_open(path, flags, mode);
    if(fd < 0 || flags & O_DIRECTORY)
    {
        goto just_return;
    }
    
    fd = path_open(fd, flags);
    
just_return:
    dyld_hook_log("[hook_open:return] (fd = %d)\n", fd);
    return fd;
}

static int hook_openat(int dirfd,
                       const char *path,
                       int flags,
                       mode_t mode)
{
    dyld_hook_log("[hook_openat:args] (dirfd = %d, path = %s, flags = %d, mode = %d)\n", dirfd, path, flags, mode);
    if(open_hardlock)
    {
        dyld_hook_log("[hook_openat:args] [error: hard locked]\n");
        errno = EACCES;
        return -1;
    }
    
    int fd = orig_dyld_openat(dirfd, path, flags, mode);
    if(fd < 0 || flags & O_DIRECTORY)
    {
        goto just_return;
    }
    
    fd = path_open(fd, flags);
    
just_return:
    dyld_hook_log("[hook_openat:return] (fd = %d)\n", fd);
    return fd;
}

static const time_t fake_time = 1700000000;

static int hook_fstat64(int fd,
                        struct stat *buf)
{
    dyld_hook_log("[hook_fstat64:args] (fd = %d, buf = %p)\n", fd, buf);
    int ret = orig_dyld_fstat64(fd, buf);
    if(ret == 0)
    {
        char canon[PATH_MAX];
        if(inode_bank_get_path(buf->st_ino, canon, sizeof(canon)) || orig_dyld_fcntl(fd, F_GETPATH, canon) != -1)
        {
            ino_t fake_ino = fake_inode_for_path(canon);
            dyld_hook_log("[hook_fstat64] changing inode:\n");
            dyld_hook_log("    st_ino: %llu -> %llu\n", buf->st_ino, fake_ino);
            buf->st_ino = fake_ino;
        }
        
        dyld_hook_log("[hook_fstat64] changing times:\n");
        dyld_hook_log("    st_mtimespec: %lu -> %lu\n", buf->st_mtimespec.tv_sec, fake_time);
        buf->st_mtimespec.tv_sec = fake_time;
        buf->st_mtimespec.tv_nsec = 0;
        dyld_hook_log("    st_ctimespec: %lu -> %lu\n", buf->st_ctimespec.tv_sec, fake_time);
        buf->st_ctimespec.tv_sec = fake_time;
        buf->st_ctimespec.tv_nsec = 0;
        dyld_hook_log("    st_birthtimespec: %lu -> %lu\n", buf->st_birthtimespec.tv_sec, fake_time);
        buf->st_birthtimespec.tv_sec = fake_time;
        buf->st_birthtimespec.tv_nsec = 0;
        
        dyld_hook_log("[hook_fstat64] zeroing out dev device:\n");
        dyld_hook_log("    st_dev: %d -> %d\n", buf->st_dev, 0);
    }
    dyld_hook_log("[hook_fstat64:return] (ret = %d)\n", ret);
    return ret;
}

static int hook_stat64(const char *path,
                       struct stat *buf)
{
    dyld_hook_log("[hook_stat64:args] (path = %s, buf = %p)\n", path, buf);
    int ret = orig_dyld_stat64(path, buf);
    if(ret == 0)
    {
        char canon[PATH_MAX];
        if(!realpath(path, canon))
        {
            strlcpy(canon, path, sizeof(canon));
        }
        
        ino_t fake_ino = fake_inode_for_path(canon);
        dyld_hook_log("[hook_stat64] changing inode:\n");
        dyld_hook_log("    st_ino: %llu -> %llu\n", buf->st_ino, fake_ino);
        buf->st_ino = fake_ino;   /* canonicalizes internally */
        
        dyld_hook_log("[hook_stat64] changing times:\n");
        dyld_hook_log("    st_mtimespec: %lu -> %lu\n", buf->st_mtimespec.tv_sec, fake_time);
        buf->st_mtimespec.tv_sec = fake_time;
        buf->st_mtimespec.tv_nsec = 0;
        dyld_hook_log("    st_ctimespec: %lu -> %lu\n", buf->st_ctimespec.tv_sec, fake_time);
        buf->st_ctimespec.tv_sec = fake_time;
        buf->st_ctimespec.tv_nsec = 0;
        dyld_hook_log("    st_birthtimespec: %lu -> %lu\n", buf->st_birthtimespec.tv_sec, fake_time);
        buf->st_birthtimespec.tv_sec = fake_time;
        buf->st_birthtimespec.tv_nsec = 0;
        
        dyld_hook_log("[hook_stat64] zeroing out dev device:\n");
        dyld_hook_log("    st_dev: %d -> %d\n", buf->st_dev, 0);
    }
    dyld_hook_log("[hook_stat64:return] (ret = %d)\n", ret);
    return ret;
}

HWHookThreadContextRef HWHookDlopenThreadContext(void)
{
    if(!ksurface_user_patchcache_load())
    {
        return NULL;
    }
    
    static HWHookThreadContextRef context = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        orig_dyld_fcntl = (void*)patchcache[kDyldPtrFcntl];
        orig_dyld_open = (void*)patchcache[kDyldPtrOpen];
        orig_dyld_fstat64 = (void*)patchcache[kDyldPtrFstat64];
        orig_dyld_stat64 = (void*)patchcache[kDyldPtrStat64];
        orig_dyld_openat = (void*)patchcache[kDyldPtrOpenat];
        if(orig_dyld_fcntl == NULL || orig_dyld_open == NULL || orig_dyld_fstat64 == NULL || orig_dyld_stat64 == NULL || orig_dyld_openat == NULL)
        {
            return;
        }
        
        HWHookRef fcntlHook = HWHookCreateWithPointerToSymbol(kCFAllocatorDefault, orig_dyld_fcntl, hook_fcntl);
        if(fcntlHook == NULL)
        {
            return;
        }
        
        HWHookRef openHook = HWHookCreateWithPointerToSymbol(kCFAllocatorDefault, orig_dyld_open, hook_open);
        if(openHook == NULL)
        {
            CFRelease(fcntlHook);
            return;
        }
        
        HWHookRef fstat64Hook = HWHookCreateWithPointerToSymbol(kCFAllocatorDefault, orig_dyld_fstat64, hook_fstat64);
        if(fstat64Hook == NULL)
        {
            CFRelease(fcntlHook);
            CFRelease(openHook);
            return;
        }
        
        HWHookRef stat64Hook = HWHookCreateWithPointerToSymbol(kCFAllocatorDefault, orig_dyld_stat64, hook_stat64);
        if(fstat64Hook == NULL)
        {
            CFRelease(fcntlHook);
            CFRelease(openHook);
            CFRelease(fstat64Hook);
            return;
        }
        
        HWHookRef openatHook = HWHookCreateWithPointerToSymbol(kCFAllocatorDefault, orig_dyld_openat, hook_openat);
        if(openatHook == NULL)
        {
            CFRelease(fcntlHook);
            CFRelease(openHook);
            CFRelease(fstat64Hook);
            CFRelease(stat64Hook);
            return;
        }
        
        HWHookSetDisableContextHooksInFrame(fcntlHook, true);
        HWHookSetDisableContextHooksInFrame(openHook, true);
        HWHookSetDisableContextHooksInFrame(fstat64Hook, true);
        HWHookSetDisableContextHooksInFrame(stat64Hook, true);
        HWHookSetDisableContextHooksInFrame(openatHook, true);
        
        context = HWHookThreadContextCreate(kCFAllocatorDefault);
        if(context == NULL)
        {
            goto release_hooks;
        }
        
        if(!HWHookThreadContextAppendHook(context, fcntlHook) ||
           !HWHookThreadContextAppendHook(context, openHook) ||
           !HWHookThreadContextAppendHook(context, fstat64Hook) ||
           !HWHookThreadContextAppendHook(context, stat64Hook) ||
           !HWHookThreadContextAppendHook(context, openatHook))
        {
            CFRelease(context);
        release_hooks:
            CFRelease(fcntlHook);
            CFRelease(openHook);
            CFRelease(fstat64Hook);
            CFRelease(stat64Hook);
            CFRelease(openatHook);
            return;
        }
    });
    return context;
}

extern bool performHookDyldApi(const char* functionName, uint32_t adrpOffset, void** origFunction, void* hookFunction);

static pthread_mutex_t g_dlopen_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_active_dlopens = 0;
static char g_dlopen_tmp_root[PATH_MAX];

static bool dlopen_session_enter(void)
{
    pthread_mutex_lock(&g_dlopen_lock);
    
    if(g_active_dlopens == 0)
    {
        int n = snprintf(g_dlopen_tmp_root, sizeof(g_dlopen_tmp_root), "%s/tmp/%d", mmap_sandbox_map_exec_allowed_path, getpid());
        if(n < 0 || n >= sizeof(g_dlopen_tmp_root))
        {
            pthread_mutex_unlock(&g_dlopen_lock);
            return false;
        }
        
        inode_bank_init();
        
        int err = mkpath_np(g_dlopen_tmp_root, 0777);
        if(err != 0 && err != EEXIST)
        {
            pthread_mutex_unlock(&g_dlopen_lock);
            return false;
        }
    }
    
    g_active_dlopens++;
    
    pthread_mutex_unlock(&g_dlopen_lock);
    return true;
}

static void dlopen_session_leave(void)
{
    pthread_mutex_lock(&g_dlopen_lock);
    if(g_active_dlopens > 0 && --g_active_dlopens == 0)
    {
        inode_bank_unlink_all(g_dlopen_tmp_root);
        rmdir(g_dlopen_tmp_root);
    }
    pthread_mutex_unlock(&g_dlopen_lock);
}

void *(*dlopen_orig)(void* dyldApiInstancePtr, const char *path, int mode) = NULL;
LIBKERN_DEFINE_PATCHABLE(void*, dlopen_hook, (void* dyldApiInstancePtr, const char *path, int mode))
{
    if(!dlopen_session_enter())
    {
        return NULL;
    }
    
    dyld_hook_log("[hook_dlopen] %s\n", path);
    
    /* backing up the current hardware breakpoint context */
    HWHookThreadContextRef context = HWHookDlopenThreadContext();
    HWHookThreadContextRef currentContext = HWHookThreadContextGetCurrent();
    if(currentContext != NULL)
    {
        currentContext = (HWHookThreadContextRef)CFRetain(currentContext);
        HWHookThreadContextExit(currentContext);
    }
    
    open_hardlock = false;
    HWHookThreadContextEnter(context);
    void *ret = dlopen_orig(dyldApiInstancePtr, path, mode);
    HWHookThreadContextExit(context);
    
    /* restoring the last context if applicable */
    if(currentContext != NULL)
    {
        HWHookThreadContextEnter(currentContext);
        CFRelease(currentContext);
    }
    
    dlopen_session_leave();
    return ret;
}

void *dlopen_cdhash_verified(const char *path,
                             int flags,
                             const char *cdhash,
                             dlopen_cdhash_verifier_failed_callback_t callback)
{
    cdhash_verified = false;
    cdhash_must_valid = true;
    cdhash_data_container_match = cdhash;
    cdhash_verifier_failed_callback = callback;
    void *ret = dlopen(path, flags);    /* enters the dlopen api hook */
    cdhash_verifier_failed_callback = NULL;
    cdhash_data_container_match = NULL;
    cdhash_must_valid = false;
    return ret;
}

__attribute__((constructor))
void LiveShimDlopenHookInit(void)
{
    performHookDyldApi("dlopen", 2, (void**)&dlopen_orig, (void*)dlopen_hook);
    
    const char *home = getenv("HOME");
    if(home == NULL)
    {
        return;
    }
    
    char *home_copy = strndup(home, MAXPATHLEN);
    if(home_copy == NULL)
    {
        return;
    }
    
    mmap_sandbox_map_exec_allowed_path = home_copy;
}

const char *dyld_get_mmap_sandbox_map_exec_allowed_path(void)
{
    return mmap_sandbox_map_exec_allowed_path;
}
