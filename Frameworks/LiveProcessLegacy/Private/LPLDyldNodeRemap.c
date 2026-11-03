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

#include <LiveProcessLegacy/LPLDyldNodeRemap.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static DyldInodeEntry g_bank[INODE_BANK_CAPACITY];
static pthread_rwlock_t g_bank_lock = PTHREAD_RWLOCK_INITIALIZER;
static bool g_initialized = false;

static inline uint32_t hash_ino(ino_t ino)
{
    uint64_t x = (uint64_t)ino;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)(x % INODE_BANK_CAPACITY);
}

ino_t inode_for_fd(int fd)
{
    struct stat buf;
    if(fstat(fd, &buf) != 0)
    {
        return 0x0;
    }
    return buf.st_ino;
}

void inode_bank_init(void)
{
    pthread_rwlock_wrlock(&g_bank_lock);
    if(!g_initialized)
    {
        memset(g_bank, 0, sizeof(g_bank));
        g_initialized = true;
    }
    pthread_rwlock_unlock(&g_bank_lock);
}

void inode_bank_put(ino_t ino,
                    const char *real_path)
{
    if(!ino || !real_path)
    {
        return;
    }
    
    pthread_rwlock_wrlock(&g_bank_lock);
    
    uint32_t idx = hash_ino(ino);
    uint32_t start_idx = idx;
    
    while(g_bank[idx].in_use)
    {
        if(g_bank[idx].ino == ino)
        {
            strncpy(g_bank[idx].real_path, real_path, PATH_MAX - 1);
            pthread_rwlock_unlock(&g_bank_lock);
            return;
        }
        idx = (idx + 1) % INODE_BANK_CAPACITY;
        if(idx == start_idx)
        {
            pthread_rwlock_unlock(&g_bank_lock);
            return;
        }
    }
    
    g_bank[idx].ino = ino;
    g_bank[idx].in_use = true;
    strncpy(g_bank[idx].real_path, real_path, PATH_MAX - 1);
    g_bank[idx].redirect_path[0] = '\0';
    
    pthread_rwlock_unlock(&g_bank_lock);
}

void inode_bank_set_redirect(ino_t ino,
                             const char *redirect_path)
{
    if(!ino || !redirect_path)
    {
        return;
    }
    
    pthread_rwlock_wrlock(&g_bank_lock);
    
    uint32_t idx = hash_ino(ino);
    uint32_t start_idx = idx;
    
    while(g_bank[idx].in_use)
    {
        if(g_bank[idx].ino == ino)
        {
            strncpy(g_bank[idx].redirect_path, redirect_path, PATH_MAX - 1);
            pthread_rwlock_unlock(&g_bank_lock);
            return;
        }
        idx = (idx + 1) % INODE_BANK_CAPACITY;
        if(idx == start_idx)
        {
            break;
        }
    }
    
    pthread_rwlock_unlock(&g_bank_lock);
}

bool inode_bank_get_path(ino_t ino,
                         char *out_path,
                         size_t max_len)
{
    if(!ino || !out_path)
    {
        return false;
    }
    
    pthread_rwlock_rdlock(&g_bank_lock);
    
    uint32_t idx = hash_ino(ino);
    uint32_t start_idx = idx;
    
    while(g_bank[idx].in_use)
    {
        if(g_bank[idx].ino == ino)
        {
            const char *target = (g_bank[idx].redirect_path[0] != '\0') ? g_bank[idx].redirect_path : g_bank[idx].real_path;
            strncpy(out_path, target, max_len - 1);
            out_path[max_len - 1] = '\0';
            pthread_rwlock_unlock(&g_bank_lock);
            return true;
        }
        idx = (idx + 1) % INODE_BANK_CAPACITY;
        if(idx == start_idx)
        {
            break;
        }
    }
    
    pthread_rwlock_unlock(&g_bank_lock);
    return false;
}

bool inode_bank_get_ino_by_path(const char *path,
                                ino_t *out_ino)
{
    if(!path || !out_ino)
    {
        return false;
    }
    
    pthread_rwlock_rdlock(&g_bank_lock);
    
    for(int i = 0; i < INODE_BANK_CAPACITY; i++)
    {
        if(g_bank[i].in_use)
        {
            if(strcmp(g_bank[i].real_path, path) == 0 ||
               strcmp(g_bank[i].redirect_path, path) == 0)
            {
                *out_ino = g_bank[i].ino;
                pthread_rwlock_unlock(&g_bank_lock);
                return true;
            }
        }
    }
    
    pthread_rwlock_unlock(&g_bank_lock);
    return false;
}

void inode_bank_unlink_all(const char *tmp_root)
{
    if(!tmp_root)
    {
        return;
    }
    size_t rl = strlen(tmp_root);
    pthread_rwlock_wrlock(&g_bank_lock);
    for(int i = 0; i < INODE_BANK_CAPACITY; i++)
    {
        if(g_bank[i].in_use && strncmp(g_bank[i].real_path, tmp_root, rl) == 0)
        {
            unlink(g_bank[i].real_path);
        }
    }
    pthread_rwlock_unlock(&g_bank_lock);
}

static void np_lexical_resolve(const char *in, char *out, size_t outsz)
{
    size_t seg_start[PATH_MAX / 2];
    int    top = 0;
    size_t w = 0;
    
    if(outsz < 2)
    {
        if(outsz)
        {
            out[0] = '\0';
        }
        return;
    }
    
    const char *p = in;
    while(*p == '/')
    {
        p++;
    }
    
    while(*p)
    {
        const char *q = p;
        while(*q && *q != '/') q++;
        size_t len = (size_t)(q - p);
        if(len == 1 && p[0] == '.')
        {
            
        }
        else if(len == 2 && p[0] == '.' && p[1] == '.')
        {
            if(top > 0)
            {
                top--;
                w = seg_start[top];
            }
        }
        else if(len > 0)
        {
            if(top < (int)(PATH_MAX / 2))
            {
                seg_start[top++] = w;
            }
            if(w + 1 < outsz)
            {
                out[w++] = '/';
            }
            for(size_t i = 0; i < len && w + 1 < outsz; i++)
            {
                out[w++] = p[i];
            }
        }
        
        p = q;
        while(*p == '/') p++;
    }
    
    if(w == 0) out[w++] = '/';
    out[w] = '\0';
}

static void np_canonicalize(const char *in, char *out, size_t outsz)
{
    char tmp[PATH_MAX];
    
    static const char cryptex[] = "/private/preboot/Cryptexes/OS";
    if(strncmp(in, cryptex, sizeof(cryptex) - 1) == 0)
    {
        in += sizeof(cryptex) - 1;
        if(*in != '/')
        {
            in = "/";
        }
    }
    
    static const struct { const char *from; const char *to; } firmlinks[] = {
        { "/var", "/private/var" },
        { "/tmp", "/private/tmp" },
        { "/etc", "/private/etc" },
    };
    for(size_t i = 0; i < sizeof(firmlinks) / sizeof(firmlinks[0]); i++)
    {
        size_t flen = strlen(firmlinks[i].from);
        if(strncmp(in, firmlinks[i].from, flen) == 0 && (in[flen] == '/' || in[flen] == '\0'))
        {
            size_t tlen = strlen(firmlinks[i].to);
            size_t rest = strlen(in + flen);
            if(tlen + rest + 1 <= sizeof(tmp))
            {
                memcpy(tmp, firmlinks[i].to, tlen);
                memcpy(tmp + tlen, in + flen, rest + 1);
                in = tmp;
            }
            break;
        }
    }
    
    np_lexical_resolve(in, out, outsz);
}

ino_t fake_inode_for_path(const char *path)
{
    if(!path || !*path)
    {
        return 0x0;
    }
    char canon[PATH_MAX];
    np_canonicalize(path, canon, sizeof(canon));
    uint64_t h = 1469598103934665603ULL;
    for(const unsigned char *p = (const unsigned char *)canon; *p; p++)
    {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    if(h == 0)
    {
        h = 0x30a43;
    }
    return (ino_t)h;
}
