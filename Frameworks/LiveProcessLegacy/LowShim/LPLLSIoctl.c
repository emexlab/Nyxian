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
#include <Broadpatch/Broadpatch.h>
#include <sys/ioccom.h>

LIBKERN_PATCH(int, ioctl, (int fd,
                           unsigned long flag,
                           ...),
{
    uintptr_t arg = 0;
    
    if(IOCPARM_LEN(flag) != 0)
    {
        va_list ap;
        va_start(ap, flag);
        arg = va_arg(ap, uintptr_t);
        va_end(ap);
    }
    
    int ret = (int)liveshim_syscall(SYS_ioctl, fd, flag, arg, 0, 0, 0);
    if(ret != 0 && errno == ENOSYS)
    {
        return LIBKERN_ORIG(ioctl)(fd, flag, arg);
    }
    
    return ret;
});

LIBKERN_PATCH(int, isatty, (int fd),
{
    struct termios termios;
    return liveshim_syscall(SYS_ioctl, fd, TIOCGETA, &termios) == 0;
});

LIBKERN_PATCH(int, tcgetattr, (int fd,
                               struct termios *t),
{
    return (int)liveshim_syscall(SYS_ioctl, fd, TIOCGETA, t);
});

LIBKERN_PATCH(int, tcsetattr, (int fd,
                               int options,
                               struct termios *t),{
    unsigned long req;

    switch(options)
    {
        case TCSANOW:
            req = TIOCSETA;
            break;
        case TCSADRAIN:
            req = TIOCSETAW;
            break;
        case TCSAFLUSH:
            req = TIOCSETAF;
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    
    return (int)liveshim_syscall(SYS_ioctl, fd, req, t);
});

LIBKERN_PATCH(int, tcgetpgrp, (int fd),{
    pid_t pgrp = 0;
    int ret = (int)liveshim_syscall(SYS_ioctl, fd, TIOCGPGRP, &pgrp);
    return (ret == 0) ? pgrp : -1;
});

LIBKERN_PATCH(int, tcsetpgrp, (int fd,
                               pid_t pgrp),
{
    return (int)liveshim_syscall(SYS_ioctl, fd, TIOCSPGRP, &pgrp);
});

__attribute__((constructor))
static void InstallPatches(void)
{
    LIBKERN_INSTALL_PATCH(ioctl);
    LIBKERN_INSTALL_PATCH(isatty);
    LIBKERN_INSTALL_PATCH(tcgetattr);
    LIBKERN_INSTALL_PATCH(tcsetattr);
    LIBKERN_INSTALL_PATCH(tcgetpgrp);
    LIBKERN_INSTALL_PATCH(tcsetpgrp);
}
