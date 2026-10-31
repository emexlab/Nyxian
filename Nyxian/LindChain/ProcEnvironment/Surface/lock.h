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

#ifndef PROCENVIRONMENT_LOCK_H
#define PROCENVIRONMENT_LOCK_H

#import <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#include <string.h>
#include <errno.h>

#if DEBUG
#define PTHREAD_RWLOCK_DEBUG_IMP_RDLOCK(ptr) do { \
    int _e; \
    do { \
        _e = pthread_rwlock_rdlock(ptr); \
        if(_e == EAGAIN) \
        { \
            sched_yield(); \
        } \
        else if(_e) \
        { \
            kpanic("lock @ %p failed to rdlock with: %s", ptr, strerror(_e)); \
        } \
    } while (_e == EAGAIN); \
} while(0)
#define PTHREAD_RWLOCK_DEBUG_IMP_WRLOCK(ptr) ({ int _e = pthread_rwlock_wrlock(ptr); if (_e) kpanic("lock @ %p failed to wrlock with: %s", ptr, strerror(_e)); })
#define PTHREAD_RWLOCK_DEBUG_IMP_UNLOCK(ptr) ({ int _e = pthread_rwlock_unlock(ptr); if (_e) kpanic("lock @ %p failed to unlock with: %s", ptr, strerror(_e)); })
#else
#define PTHREAD_RWLOCK_DEBUG_IMP_RDLOCK(ptr) do { \
    int _e; \
    do { \
        _e = pthread_rwlock_rdlock(ptr); \
        if(_e == EAGAIN) \
        { \
            sched_yield(); \
        } \
    } while (_e == EAGAIN); \
} while(0)
#define PTHREAD_RWLOCK_DEBUG_IMP_WRLOCK(ptr) pthread_rwlock_wrlock(ptr);
#define PTHREAD_RWLOCK_DEBUG_IMP_UNLOCK(ptr) pthread_rwlock_unlock(ptr);
#endif /* DEBUG */

#define proc_table_rdlock() PTHREAD_RWLOCK_DEBUG_IMP_RDLOCK(&(ksurface->proc_info.struct_lock))
#define proc_table_wrlock() PTHREAD_RWLOCK_DEBUG_IMP_WRLOCK(&(ksurface->proc_info.struct_lock))
#define proc_table_unlock() PTHREAD_RWLOCK_DEBUG_IMP_UNLOCK(&(ksurface->proc_info.struct_lock))

#define tty_table_rdlock() PTHREAD_RWLOCK_DEBUG_IMP_RDLOCK(&(ksurface->tty_info.struct_lock))
#define tty_table_wrlock() PTHREAD_RWLOCK_DEBUG_IMP_WRLOCK(&(ksurface->tty_info.struct_lock))
#define tty_table_unlock() PTHREAD_RWLOCK_DEBUG_IMP_UNLOCK(&(ksurface->tty_info.struct_lock))

#define host_rdlock() PTHREAD_RWLOCK_DEBUG_IMP_RDLOCK(&(ksurface->host_info.struct_lock))
#define host_wrlock() PTHREAD_RWLOCK_DEBUG_IMP_WRLOCK(&(ksurface->host_info.struct_lock))
#define host_unlock() PTHREAD_RWLOCK_DEBUG_IMP_UNLOCK(&(ksurface->host_info.struct_lock))

#define kext_table_rdlock() PTHREAD_RWLOCK_DEBUG_IMP_RDLOCK(&(ksurface->kext_info.struct_lock))
#define kext_table_wrlock() PTHREAD_RWLOCK_DEBUG_IMP_WRLOCK(&(ksurface->kext_info.struct_lock))
#define kext_table_unlock() PTHREAD_RWLOCK_DEBUG_IMP_UNLOCK(&(ksurface->kext_info.struct_lock))

#endif /* PROCENVIRONMENT_LOCK_H */
