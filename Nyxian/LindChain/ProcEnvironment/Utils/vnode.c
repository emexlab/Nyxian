/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#include <LindChain/ProcEnvironment/Utils/vnode.h>
#include <LindChain/ProcEnvironment/Surface/libkern/radix/radix.h>
#include <sys/clonefile.h>
#include <copyfile.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <os/lock.h>
#include <time.h>
#include <sys/stat.h>
#include <CoreFoundation/CoreFoundation.h>

bool vnode_refresh_with_path(const char* path)
{
    int fd = open(path, O_RDWR);
    if(fd < 0)
    {
        return false;
    }
    
    /* destroys existing VFS node */
    if(unlink(path) != 0)
    {
        close(fd);
        return false;
    }
    
    bool success = vnode_recover_with_fd_to_path(fd, path);
    close(fd);
    return success;
}

bool vnode_recover_with_fd_to_path(int fd,
                                   const char *path)
{
    /* creates new node at zero cost */
    unlink(path);   /* unlink first, there shall be no vnode before hand */
    if(fclonefileat(fd, AT_FDCWD, path, 0) == 0)
    {
        /* yayyy =3 */
        return true;
    }
    
    /* fallback is using copy file */
    int copyfd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0777);
    if(copyfd < 0)
    {
        /* something went terribly wrong */
        return false;
    }
    
    /* more expensive, but more efficient than nothing */
    off_t offset = lseek(fd, 0, SEEK_CUR);
    lseek(fd, 0, SEEK_SET);
    bool copyfile_succeeded = fcopyfile(fd, copyfd, NULL, COPYFILE_DATA) == 0;
    lseek(fd, offset, SEEK_SET);
    close(copyfd);
    return copyfile_succeeded;
}

#if !CLIENT_ENV

static radix_tree_t g_vnode_inaccessible_inode_tree = { 0 };
static os_unfair_lock g_vnode_inaccessible_inode_lock = OS_UNFAIR_LOCK_INIT;

static void random_string(char *out,
                          size_t len)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        srand((unsigned)time(NULL));
    });
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(size_t i = 0; i < len; i++)
    {
        out[i] = chars[rand() % (sizeof(chars) - 1)];
    }
    out[len] = '\0';
}

int vnode_inaccessible_open(const char *path,
                            int flg)
{
    char *copyPath = strndup(path, PATH_MAX);
    if(copyPath == NULL)
    {
        errno = ENOMEM;
        return -1;
    }
    
    os_unfair_lock_lock(&g_vnode_inaccessible_inode_lock);
    
    /* open the accessible file */
    int fd = open(copyPath, O_RDONLY);
    if(fd < 0)
    {
        close(fd);
        free(copyPath);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    /* create a clone of that same file */
    char name[9];
    random_string(name, 8);
    char inaccessible_path[PATH_MAX];
    snprintf(inaccessible_path, PATH_MAX, "%s/Library/%s", getenv("HOME"), name);
    
    /* efficiently clone to the inaccessible path */
    if(!vnode_recover_with_fd_to_path(fd, inaccessible_path))
    {
        close(fd);
        free(copyPath);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    chmod(inaccessible_path, 0777);
    
    /* now open the inaccessible fd */
    int inaccessible_fd = open(inaccessible_path, flg);
    close(fd);
    if(inaccessible_fd < 0)
    {
        unlink(inaccessible_path);
        free(copyPath);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    /* now we can capture its inode and link it to the path from before */
    struct stat vnstat;
    if(fstat(inaccessible_fd, &vnstat) != 0)
    {
        close(inaccessible_fd);
        unlink(inaccessible_path);
        free(copyPath);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    /* store the thing into the radix tree */
    if(radix_insert(&g_vnode_inaccessible_inode_tree, vnstat.st_ino, copyPath) != 0)
    {
        close(inaccessible_fd);
        unlink(inaccessible_path);
        free(copyPath);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
    return inaccessible_fd;
}

int vnode_inaccessible_close(int fd,
                             bool refresh)
{
    os_unfair_lock_lock(&g_vnode_inaccessible_inode_lock);
    
    /* recapture inode */
    struct stat vnstat;
    if(fstat(fd, &vnstat) != 0)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        close(fd);
        return -1;
    }
    
    char *accessiblePath = radix_remove(&g_vnode_inaccessible_inode_tree, vnstat.st_ino);
    if(accessiblePath == NULL)
    {
        errno = ENOENT;
        close(fd);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    if(refresh && !vnode_recover_with_fd_to_path(fd, accessiblePath))
    {
        close(fd);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    free(accessiblePath);
    
    char path[PATH_MAX];
    if(fcntl(fd, F_GETPATH, path) != 0)
    {
        close(fd);
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    unlink(path);
    close(fd);
    
    os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
    return 0;
}

int vnode_inaccessible_reopen(int *fd)
{
    os_unfair_lock_lock(&g_vnode_inaccessible_inode_lock);
    
    /* need path for vn refresh */
    char path[PATH_MAX];
    if(fcntl(*fd, F_GETPATH, path) != 0)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    int flags = fcntl(*fd, F_GETFL);
    if(flags == -1)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    int acc = (flags & O_ACCMODE);
    
    /* recapture inode */
    struct stat vnstat;
    if(fstat(*fd, &vnstat) != 0)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    close(*fd);
    *fd = open(path, acc);
    if(*fd < 0)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    /* removing entry */
    char *accessiblePath = radix_remove(&g_vnode_inaccessible_inode_tree, vnstat.st_ino);
    if(accessiblePath == NULL)
    {
        errno = ENOENT;
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    if(fstat(*fd, &vnstat) != 0)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    /* store the thing into the radix tree */
    if(radix_insert(&g_vnode_inaccessible_inode_tree, vnstat.st_ino, accessiblePath) != 0)
    {
        os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
        return -1;
    }
    
    os_unfair_lock_unlock(&g_vnode_inaccessible_inode_lock);
    return 0;
}

#endif /* !CLIENT_ENV */
