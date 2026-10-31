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

#ifndef PROCENVIRONMENT_MAPPING_H
#define PROCENVIRONMENT_MAPPING_H

#include <LindChain/ProcEnvironment/Surface/libkern/sys/core.h>
#include <LindChain/ProcEnvironment/Surface/libkern/radix/radix.h>
#include <LindChain/ProcEnvironment/Surface/proc/def.h>
#include <LindChain/ProcEnvironment/Surface/tty/def.h>
#include <LindChain/ProcEnvironment/Surface/lock.h>
#include <LindChain/ProcEnvironment/Surface/key.h>
#include <stdint.h>
#include <limits.h>
#include <pthread.h>

typedef struct {
    /*
     * syscall server which handles certain
     * syscalls made by userspace processes.
     */
    syscall_server_t *sys_server;
    
    /*
     * public static key used to validate
     * nyxian trust entitlement blobs.
     */
    uint8_t *pub_key;
    size_t pub_key_len;
    
    /*
     * structure that holds host information.
     * Such as hostname.
     */
    struct {
        
        /*
         * lock making sure rw happens not at
         * the same time
         */
        pthread_rwlock_t struct_lock;
        
        /*
         * hostname buffer, holding current hostname.
         * which can be changed by userspace with
         * enough entitlements.
         */
        char hostname[MAXHOSTNAMELEN];
    } host_info;
    
    /*
     * process information structure.
     * It holds all processes that run
     * inside of nyxian and manages them.
     */
    struct {
        
        /* rwlock securing structures */
        pthread_rwlock_t struct_lock;
        
        /*
         * count of processes currently running
         * inside of nyxian.
         */
        uint32_t proc_count;
        
        /*
         * radix tree where all processes are
         * listed inside.
         */
        radix_tree_t tree;
        
        /*
         * launch process(aka Nyxian it self
         * running as host for the glient
         * processes).
         */
        ksurface_proc_t *kern_proc;
    } proc_info;
    
    struct {
        /* rwlock securing structures */
        pthread_rwlock_t struct_lock;
        
        /*
         * radix tree where all tty's are
         * listed inside.
         */
        radix_tree_t tty;
    } tty_info;
    
    struct {
        /* rwlock securing structures */
        pthread_rwlock_t struct_lock;
        
        /*
         * radix tree where all kext objects
         * are listed inside.
         */
        radix_tree_t kexts;
    } kext_info;
} ksurface_mapping_t;

#endif /* PROCENVIRONMENT_MAPPING_H */
