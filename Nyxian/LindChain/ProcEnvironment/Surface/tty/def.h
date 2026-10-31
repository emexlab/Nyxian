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

#ifndef TTY_DEF_H
#define TTY_DEF_H

#include <LindChain/ProcEnvironment/Surface/libkern/obj/kvobject.h>
#include <LindChain/ProcEnvironment/Surface/proc/def.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>

#define TTY_MAX_RD 4096

#define MASTERFD 0
#define SLAVEFD 1

typedef struct ksurface_tty ksurface_tty_t;

struct ksurface_tty {
    /* object header */
    kvobject_t header;
    
    /* file descriptors */
    int userspacefd[2];     /* ownable by userspace processes */
    int kernelfds[2];       /* owned by the kernel tty driver */
    
    /* userspace file descriptors kernel identifiers */
    uint32_t userspacekcid[2];
    
    /* the thread */
    pthread_t pump_thread;
    int alive;
    
    /* the properties */
    struct termios t;
    struct winsize ws;
    
    /* buffers used by the tty driver */
    char rbuf[TTY_MAX_RD];
    char obuf[TTY_MAX_RD * 2];
    
    /* controlling session and foreground process group */
    pid_t sid;
    pid_t pgrp;
};

#endif /* TTY_DEF_H */
