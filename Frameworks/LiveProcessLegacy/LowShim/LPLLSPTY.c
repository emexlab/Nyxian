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
#include <LiveProcessLegacy/LPLFileport.h>
#include <Broadpatch/Broadpatch.h>
#include <util.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

LIBKERN_PATCH(int, openpty, (int *amaster,
                             int *aslave,
                             char *name,
                             struct termios *termp,
                             struct winsize *winp),
{
    if(amaster == NULL || aslave == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    
    mach_port_t master_port = MACH_PORT_NULL;
    mach_port_t slave_port  = MACH_PORT_NULL;
    
    int ret = (int)liveshim_syscall(SYS_openpty, &master_port, &slave_port);
    if(ret != 0)
    {
        return -1;
    }
    
    int master = fileport_makefd(master_port);
    int slave = fileport_makefd(slave_port);
    
    mach_port_deallocate(mach_task_self(), master_port);
    mach_port_deallocate(mach_task_self(), slave_port);
    
    if(master < 0 || slave < 0)
    {
        if(master >= 0)
        {
            close(master);
        }
        if(slave >= 0)
        {
            close(slave);
        }
        errno = EBADF;
        return -1;
    }
    
    if(termp != NULL)
    {
        if(tcsetattr(slave, TCSANOW, termp) != 0)
        {
            close(master);
            close(slave);
            return -1;
        }
    }
    
    if(winp != NULL)
    {
        if(ioctl(slave, TIOCSWINSZ, winp) != 0)
        {
            close(master);
            close(slave);
            return -1;
        }
    }
    
    if(name != NULL)
    {
        if(ttyname_r(slave, name, 128) != 0)
        {
            name[0] = '\0';
        }
    }
    
    *amaster = master;
    *aslave = slave;
    
    return 0;
});

__attribute__((constructor))
static void InstallPTYPatches(void)
{
    LIBKERN_INSTALL_PATCH(openpty);
}
