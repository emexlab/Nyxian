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

#import <LiveProcessLegacy/LPLFileport.h>
#include <unistd.h>
#include <errno.h>

int fileport_dup2(fileport_t port,
                  int fd)
{
    // Get new file descriptor
    int newFd = fileport_makefd(port);
    
    // Check if newFd is valid
    if(newFd == 0)
    {
        errno = EFAULT;
        return -1;
    }
    
    // Now its duped but now overbind the target
    if(newFd == fd) return newFd;
    if(dup2(fd, newFd) != 0) return -1;
    if(close(newFd) != 0) return -1;
    return 0;
}
